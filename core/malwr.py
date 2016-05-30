
"""
Python API for malwr.com Website.

Followings are the available search terms;
______________________________________________________________________
|   PREFIX	    |       DESCRIPTION                                  |
----------------------------------------------------------------------
|   name:	    |   File name pattern
|   type:	    |   File type/format
|   string:	    |   String contained in the binary
|   ssdeep:	    |   Fuzzy hash
|   crc32:	    |   CRC32 hash
|   imphash:	|   Search for PE Imphash
|   file:	    |   Opened files matching the pattern
|   key:	    |   Opened registry keys matching the pattern
|   mutex:	    |   Opened mutexes matching the pattern
|   domain:	    |   Contacted the specified domain
|   ip:	        |   Contacted the specified IP address
|   url:	    |   Performed HTTP requests matching the URL pattern
|   signature:	|   Search for Cuckoo Sandbox signatures
|   tag:	    |   Search on your personal tags
----------------------------------------------------------------------


"""

import requests, logging
from lxml import html

class MalwrApi(object):

    def __init__(self, username=None, password=None):
        self.logger = logging.getLogger(__name__)
        self.logged = False
        self.url = "https://malwr.com"
        self.headers = {
            'User-Agent':
                "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:41.0) " +
                "Gecko/20100101 Firefox/41.0"
        }
        self.session = requests.session()

        if not (username or password):
            self.logger.warn ("MalwrApi::You must login using your username and password")
        else:
            csrf_token = self.get_session_token(self.url + '/account/login')
            payload = {
                'csrfmiddlewaretoken': csrf_token,
                'username': username,
                'password': password
            }
            login_request = self.session.post("https://malwr.com/account/login/",
                                              data=payload,
                                              headers=self.headers)

            login_status = self.check_login_status(login_request)
            self.logged = login_status['loggedIn']
            if self.logged is False:
                self.logger.warn (login_status['msg'])


    def check_login_status(self, result):
        rTree = html.fromstring(result.content)
        error = rTree.xpath("//div[@class='alert alert-error']")
        err_elm = [elem.text_content().replace("\n", "").strip() for elem in error]
        status = {}
        if len(err_elm) > 0:
            status['loggedIn'] = False
            status['msg'] = 'MalwrApi::' + err_elm[0]
        else:
            status['loggedIn'] = True

        return status

    def get_session_token(self, url=None):
        result = self.session.get(url, headers=self.headers)
        tree = html.fromstring(result.content)
        token = list(set(tree.xpath("//input[@name='csrfmiddlewaretoken']/@value")))[0]
        return token


    def get_search_results(self, raw_result, search_word):
        try:
            result_list = []
            tree = html.fromstring(raw_result.content)
            bucket_elems = tree.findall(".//div[@class='box-content']/")[0]
            sub = bucket_elems.findall('tbody')[0]
            for idx, submission in enumerate(sub.findall('tr'), start=0):
                html_objs = submission.findall('td')
                link_url = html_objs[0].xpath('//td/a')[idx].attrib['href']
                elements = [elem.text_content().replace("\n", "").strip() for elem in html_objs]
                objs_to_add = {
                    'submission_time': elements[0],
                    'hash': elements[1],
                    'submission_url': link_url,
                    'file_name': elements[2]
                }
                result_list.append(objs_to_add)

            return result_list
        except IndexError as e:
            self.logger.info ("An unexpected HTML format was returned from Malwr.com by query:" + search_word)
            return []

    def search (self, search_word=None):
        if not self.logged:
            self.logger.warn ("MalwrApi::You must login using your username and password")
            return
        search_url = self.url + '/analysis/search/'
        csrf_token = self.get_session_token(search_url)
        payload = {
            'csrfmiddlewaretoken': csrf_token,
            'search': search_word
        }
        raw_result = self.session.post(search_url,
                                       data=payload,
                                       headers=self.headers)
        return self.get_search_results(raw_result, search_word)


