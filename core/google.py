#!/usr/bin/env python
"""
RAPID Google Module
-------------------

Functions and utility classes for performing searches via Google.

Search results are encapsulated in the SearchResult class which has the following members:
    url: The search result URL
    title: A title for the search result
    content: A brief description or summary of the content of the result

Instances of SearchResult may be quickly and easily converted to dictionaries via their 'to_dict' method.  This
dictionary has the same keys as the object itself.

The primary function for obtaining search results is 'search.'  This function is a generator, returning a new
SearchResult each time it is called up to a specified limit.  If no limit is specified, it will continue searching for
results until no more are available from Google.

A convenience function, 'accumulate,' is also provided which will accumulate all results from 'search' into a list.
Obviously a limit MUST be specified when using this function.

Both 'search' and 'accumulate' allow users to specify a Sifter for filtering results.  (The name 'Sifter' was chosen to
avoid conflict or confusion with Python's built-in 'filter.')   Sifters examine a SearchResult instance and return a
boolean indicating whether the result should be kept (True) or discarded (False).  Users may write their own Sifter by
extending the Sifter class.  Two Sifter implementations are also provided:
    KeepSifter: This Sifter (which is used as a default) will always keep all results
    DomainSifter: This Sifter will discard any results from a given domain (specified in its constructor)

As a convenience, this module also provides the MemoryLWPCookieJar class.  This is an extension of LWPCookieJar that
stores its cookies in an internal string rather than on the filesystem.

This module is designed to work either in Python 2.x or Python 3.x.  The module may also be run directly as a script,
in which case the '-h' argument should be specified for more information.
"""

import abc
import json
import logging
import sys
import time

if sys.version_info[0] > 2:
    # Python 3.x Import Statements
    from http.cookiejar import LWPCookieJar
    from http.cookiejar import LoadError
    from io import StringIO
    from urllib.request import Request
    from urllib.request import urlopen
    from urllib.parse import parse_qs
    from urllib.parse import urlencode
    from urllib.parse import urlparse
else:
    # Python 2.x Import Statements
    from cookielib import LWPCookieJar
    from cookielib import LoadError
    from StringIO import StringIO
    from urllib2 import Request
    from urllib2 import urlopen
    from urllib import urlencode
    from urlparse import urlparse
    from urlparse import parse_qs

try:
    from bs4 import BeautifulSoup
    is_bs4 = True
except ImportError:
    from BeautifulSoup import BeautifulSoup
    is_bs4 = False


CUSTOM_SEARCH_URL_BASE="http://www.google.com/custom?"
GOOGLE_HOME_PAGE = "https://www.google.com/"
SEARCH_URL_BASE = GOOGLE_HOME_PAGE + "search?"
AJAX_URL_BASE = "https://ajax.googleapis.com/ajax/services/search/web?"

LOGGER = logging.getLogger(__name__)


class MemoryLWPCookieJar(LWPCookieJar):
    """
    A subclass of LWPCookieJar that stores cookie contents in an in-memory "file" rather than on the filesystem.

    Cookie "file" contents are stored in a string in memory and accessed as a file via a StringIO object.  The contents
    of this string may be obtained by calling the getvalue() method.
    """

    def __init__(self):
        """
        Create a new LWPCookieJar that uses an in-memory "file."

        The contents of this file can be retrieved by calling the 'getvalue' method.
        """
        LWPCookieJar.__init__(self)
        self._string = ""

    def save(self, filename=None, ignore_discard=False, ignore_expires=False):
        # Note: StringIO doesn't support 'with' statements in Python 2.x
        f = None
        try:
            # There really isn't an LWP Cookies 2.0 format, but this indicates
            # that there is extra information in here (domain_dot and
            # port_spec) while still being compatible with libwww-perl, I hope.
            f = StringIO(self._string)
            f.write("#LWP-Cookies-2.0\n")
            f.write(self.as_lwp_str(ignore_discard, ignore_expires))
            self._string = f.getvalue()
        finally:
            if f is not None:
                f.close()

    def load(self, filename=None, ignore_discard=False, ignore_expires=False):
        # Note: StringIO doesn't support 'with' statements in Python 2.x
        f = None
        try:
            f = StringIO(self._string)
            self._really_load(f, filename, ignore_discard, ignore_expires)
            self._string = f.getvalue()
        finally:
            if f is not None:
                f.close()

    def getvalue(self):
        """
        Get the contents of the cookie "file."

        :return: The string contents of the in-memory cookie "file"
        """
        return self._string


# Prepare Cookie Jar
cookie_jar = MemoryLWPCookieJar()
try:
    cookie_jar.load()
except LoadError:
    # Note: This will ALWAYS throw an exception because its empty, but it still must be called
    pass


class SearchResult:
    """
    An abstraction/summary of a Google search results.

    This class includes the following members:
        url: The search result URL
        title: A title for the result
        content: A brief description of the result

    There is also a convenience method, 'to_dict,' which will return a dictionary containing these values.  Class
    members are provided as 'constants' for the keys in these dictionaries:
        URL: The search result URL
        TITLE: The title of the search result
        CONTENT: A brief description of the result

    The string representation of this class is the string representation of the dictionary as returned by 'to_dict.'
    """

    URL = "url"
    TITLE = "title"
    CONTENT = "content"

    def __init__(self, url, title, content):
        """
        Create a new search result.

        :param url: The search result URL
        :param title:  The title for the result
        :param content: A brief description of the result
        """
        self.url = url
        self.title = title
        self.content = content

    def to_dict(self):
        """
        Get a dictionary representation of this result summary.

        This dictionary uses the following SearchResult class 'constants' as keys:
            URL: The search result URL
            TITLE: The title of the search result
            CONTENT: A brief description of the result

        :return: The dictionary representation
        """
        return {SearchResult.URL: self.url,
                SearchResult.TITLE: self.title,
                SearchResult.CONTENT: self.content}

    def __str__(self):
        return str(self.to_dict())

    @staticmethod
    def from_dict(dictionary):
        """
        Create a SearchResult from a dictionary.

        This factory method is the inverse of the SearchResult.to_dict

        :param dictionary: The dictionary (such as one obtained from SearchResult.to_dict)
        :return: The SearchResult instance
        :raises: KeyError if the dictionary does not contain a required key
        """
        url = dictionary[SearchResult.URL]
        title = dictionary[SearchResult.TITLE]
        content = dictionary[SearchResult.CONTENT]
        return SearchResult(url, title, content)


class Sifter:
    """
    An abstract base class for filters.  (The name 'Sifter' and the method 'sift' are used to avoid confusion or overlap
    with the 'filter' built-in.   Sifters have one method, 'sift,' which returns a boolean.  A result of True means that
    the result should be kept, while a result of False means that it should be discarded.
    """
    __metaclass__ = abc.ABCMeta

    def __init__(self):
        """Create a new Sifter."""
        self._logger = LOGGER.getChild(type(self).__name__)

    @abc.abstractmethod
    def sift(self, result):
        """
        Filter a value.

        :param result: The SearchResult instance to be filtered
        :return: True if the value should be kept, or False if it should be discarded
        """
        pass

    def __str__(self):
        return type(self).__name__


class KeepSifter(Sifter):
    """A Sifter (filter) implementation that always keeps all results"""

    def sift(self, result):
        return True


class DomainSifter(Sifter):
    """A Sifter (filter) implementation for domains that discards any result whose URL is a given domain or a sub-domain
    thereof"""

    def __init__(self, domain):
        """
        Create a new Sifter for discarding any result with a URL that is or is a subdomain of a given domain.

        :param domain: The domain to be excluded
        """
        super(DomainSifter, self).__init__()
        self._domain = domain

    def sift(self, result):
        # Example: If our domain is "foo.com" then we must discard anything with a netloc of 'foo.com' OR anything that
        # ends with '.foo.com'
        keep = True
        netloc = urlparse(result.url).netloc
        if netloc == self._domain:
            self._logger.info("Discarding URL (filtered domain '%s'): %s", self._domain, result.url)
            keep = False
        elif netloc.endswith("." + self._domain):
            self._logger.info("Discarding URL (subdomain of filtered domain '%s'): %s", self._domain, result.url)
            keep = False
        return keep

    def __str__(self):
        return "%s(%s)" % (type(self).__name__, self._domain)


def _get_page(url):
    """
    Retrieve a page.

    This method will ensure that cookies are managed via the 'cookie_jar' module member.

    :param url: The URL of the page to be retrieved
    :return: The page contents, decoded in UTF-8
    """
    request = Request(url)
    request.add_header('User-Agent',
                       'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0)')
    # Note: This Google API REQUIRES a Referer or it will eventually flag you for a ToS violation
    request.add_header('Referer',
                       'http://localhost:8000/pivoteer')
    cookie_jar.add_cookie_header(request)
    response = urlopen(request)
    cookie_jar.extract_cookies(response, request)
    if 200 != response.code:
        msg = "Error retrieving page (%d)" % response.code
        LOGGER.error(msg)
        raise IOError(msg)
    return response.read().decode("utf-8")


def _call_google_rest(value, start=0, limit=10, **kwargs):
    """
    A generator for search results obtained via Google's REST API.

    Note that this API is technically deprecated, and in experiential testing is significantly slower (because there
    doesn't seem to be a good way to get more than a very small number of results per call).  In general, you should
    prefer to use _call_google_html rather than this method.

    :param value: The value for which to search
    :param start: The result at which to start.  The default value, 0, will start at the beginning (which is a very
    good place to start)
    :param limit: The maximum number of search results.  Note that this is just a guide.   (This parameter is currently
    NOT used, but maintained to provide a similar signature to _call_google_html.)
    :param kwargs: Additional query parameters to be included in the URL
    :return: The next SearchResult
    """
    params = {'v': '1.0',
              'start': start,
              'q': value}
    params.update(kwargs)
    encoded = urlencode(params)
    search_url = AJAX_URL_BASE + encoded
    LOGGER.debug("Using Google REST search URL: %s", search_url)
    decoded = _get_page(search_url)
    LOGGER.debug("Raw response content: %s", decoded)
    obj = json.loads(decoded)
    if LOGGER.isEnabledFor(logging.DEBUG):
        encoder = json.JSONEncoder(indent=2)
        LOGGER.debug("Google JSON response:\n%s", encoder.encode(obj))

    # Double-check the response code within the body JSON.  (I've found, for example, that if it suspects a TOS
    # violation, the response code in 'get_page' is 200, but the response in the JSON body is actually 403.)
    if 200 != obj['responseStatus']:
        msg = "Error querying Google: " + obj['responseDetails']
        LOGGER.error(msg)
        raise IOError(msg)

    response_data = obj['responseData']
    results = response_data['results']
    for result in results:
        url = result['unescapedUrl']
        title = result['titleNoFormatting']
        content = result['content']
        info = SearchResult(url, title, content)
        yield info


def create_html_search_url(value, start=0, limit=10, **kwargs):
    """
    Create the HTML search URL for a value.

    :param value: The value for which to search
    :param start: The first result number to be returned.  A value of 0 (the default) will start at the very beginning
    (which is a very good place to start)
    :param limit: The maximum number of results to return
    :param kwargs: Additional query parameters
    :return: The search URL
    """
    params = {'q': value,
              'start': start,
              'num': limit}
    params.update(kwargs)
    encoded = urlencode(params)
    search_url = SEARCH_URL_BASE + encoded
    LOGGER.debug("Created search URL for '%s': %s", value, search_url)
    return search_url


def filter_result(link):
    """
    Filter links found in the Google result pages HTML code.

    Note: This method is taken from the 'google' module available via pip.  This module contains the following license
    information:

    # Python bindings to the Google search engine
    # Copyright (c) 2009-2016, Mario Vilas
    # All rights reserved.
    #
    # Redistribution and use in source and binary forms, with or without
    # modification, are permitted provided that the following conditions are met:
    #
    #     * Redistributions of source code must retain the above copyright notice,
    #       this list of conditions and the following disclaimer.
    #     * Redistributions in binary form must reproduce the above copyright
    #       notice,this list of conditions and the following disclaimer in the
    #       documentation and/or other materials provided with the distribution.
    #     * Neither the name of the copyright holder nor the names of its
    #       contributors may be used to endorse or promote products derived from
    #       this software without specific prior written permission.
    #
    # THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    # AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    # IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    # ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
    # LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
    # CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    # SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    # INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    # CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    # ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    # POSSIBILITY OF SUCH DAMAGE.

    :param link: The link to be filtered
    :return: The filtered link, or None if the link doesn't yield a valid result
    """
    try:

        # Valid results are absolute URLs not pointing to a Google domain
        # like images.google.com or googleusercontent.com
        o = urlparse(link, 'http')
        if o.netloc and 'google' not in o.netloc:
            return link

        # Decode hidden URLs.
        if link.startswith('/url?'):
            link = parse_qs(o.query)['q'][0]

            # Valid results are absolute URLs not pointing to a Google domain
            # like images.google.com or googleusercontent.com
            o = urlparse(link, 'http')
            if o.netloc and 'google' not in o.netloc:
                return link

        # Include interstitial ad sites (which may be malicious).  (Note: This is a change from the original
        # implementation of 'filter_link.')
        if link.startswith("/interstitial?"):
            link = parse_qs(o.query)["url"][0]
            o = urlparse(link, "http")
            if o.netloc and 'google' not in o.netloc:
                return link

    # Otherwise, or on error, return None.
    except Exception:
        pass
    return None


def _call_google_html(value, start=0, limit=10, **kwargs):
    """
    A generator for search results obtained via parsing Google HTML results.

    :param value: The value for which to search
    :param start: The result at which to start.  The default value, 0, will start at the beginning (which is a very
    good place to start)
    :param limit: The maximum number of results
    :param kwargs: Additional query parameters to be included in the URL
    :return: The next SearchResult
    """
    search_url = create_html_search_url(value, start, limit, **kwargs)
    LOGGER.debug("Using Google HTML search URL: %s", search_url)
    decoded = _get_page(search_url)
    if is_bs4:
        soup = BeautifulSoup(decoded, 'html.parser')
    else:
        soup = BeautifulSoup(decoded)
    LOGGER.debug("Processing HTML:\n%s", soup.prettify())
    g_list = soup.find(id="search").find_all("div", {"class": "g"})
    for g in g_list:
        LOGGER.debug("Processing 'g'-class div: %s", g)
        r = g.find("h3", {"class": "r"})
        if r is None:
            continue
        a = r.find("a")
        raw_url = a.attrs["href"]
        url = filter_result(raw_url)
        if url is None:
            LOGGER.info("Discarding filtered URL: %s", raw_url)
            continue
        title = a.get_text()
        s = g.find("div", {"class": "s"})
        st = s.find("span", {"class": "st"})
        content = st.get_text()
        info = SearchResult(url, title, content)
        yield info


def search(value, start=0, limit=10, pause=2.0, sifter=None):
    """
    A generator to get the next SearchResult from Google for a value.

    :param value: The value for which to search
    :param start: The starting index at which to search.   A value of 0 (the default) will start at the very beginning
    (which is a very good place to start)
    :param limit: The maximum number of results to return
    :param pause: The length of time to wait between calls to the Google API
    :param sifter: A Sifter for filtering results.  Only those results pass the sifter will be returned
    :return: The next SearchResult
    """
    if sifter is None:
        sifter = KeepSifter()
    LOGGER.info("Performing Google search:\n\tValue: %s\n\tStart: %d\n\tLimit: %d\n\tSifter Type: %s",
                value,
                start,
                limit,
                sifter)

    # Retrieve the Google Home Page to load cookies.  We don't care about the results; we just want the cookies to be
    # loaded.
    _get_page(GOOGLE_HOME_PAGE)

    # Get search results
    hashes = set()
    count = 0
    queries = 0
    keep_going = True
    while keep_going:
        queries += 1
        current = 0
        info = None
        # Note: This could be changed to use the REST-based API, if desired, by calling _call_google_rest instead
        for info in _call_google_html(value, start=start, limit=limit):
            current += 1
            # Ignore duplicate results
            h = hash(info.url)
            if h in hashes:
                continue
            hashes.add(h)
            LOGGER.debug("Got info: %s", info)
            # Only count search results that pass our sifter
            if sifter.sift(info):
                count += 1
                yield info
            # If a limit was specified and we've met it, we can stop
            if limit is not None and count >= limit:
                keep_going = False
                break
        # If no results were returned, don't try again expecting different results.  That's the definition of insanity.
        if info is None:
            LOGGER.warn("No more results available for value: %s", value)
            break
        start += current
        # Only sleep if we're planning on making another loop
        if keep_going:
            time.sleep(pause)
    LOGGER.debug("Google search complete after %d total queries", queries)


def accumulate(value, start=0, limit=10, pause=2.0, sifter=None):
    """
    A convenience method that combines the results from 'search' into a list.

    It is an error to call this method without a defined limit.

    :param value: The value for which to search.  This value is used directly, so if you desire it to be quoted, you
     should do so prior to calling this function
    :param start: The result at which to start.  The default value, 0, will start at the beginning (which is a very
    good place to start)
    :param limit: The maximum number of results to return.  Unlike 'search,' the value of 'limit' may NOT be None when
    calling this function
    :param pause: The length of time to pause between making calls to Google.  (If you make calls to frequently, they
    might block you.)
    :param sifter: A filter for result values.  If no sifter (filter) is specified, all results will be returned (that
    is, no results will be filtered out)
    :return: A list of all SearchResults
    """
    return list(search(value, start, limit, pause, sifter))


# ------------------------------
# Module Execution (as a script)
# ------------------------------
if __name__ == "__main__":
    # Parse Arguments
    import argparse
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-g",
                        "--loglevel",
                        dest="loglevel",
                        default=logging.getLevelName(logging.INFO),
                        help="Specify the log level (DEBUG, INFO, WARNING, ERROR, CRITICAL) (default: INFO)")
    parser.add_argument("-l",
                        "--limit",
                        dest="limit",
                        type=int,
                        default=10,
                        help="Maximum number of results (default: 10)")
    parser.add_argument("value",
                        help="The value for which to search")
    args = parser.parse_args()

    # Configure Logging
    format_string = "[%(levelname)s] %(name)s: %(message)s (%(filename)s:%(lineno)d)"
    formatter = logging.Formatter(format_string)
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.getLevelName(args.loglevel.upper()))
    LOGGER.debug("Using Python version %s", sys.version)

    # Quote Value
    raw = args.value
    LOGGER.debug("Raw value: %s", raw)
    quoted = "\"" + raw + "\""
    LOGGER.debug("Quoted value: %s", quoted)

    # Perform Search
    LOGGER.info("Starting search for value: %s", quoted)
    things = accumulate(quoted, sifter=DomainSifter(raw), limit=args.limit)
    LOGGER.info("Found %d total thing(s)", len(things))
    for thing in things:
        LOGGER.info("%s\n\tURL: %s\n\tDescription: %s\n\n",
                    thing.title,
                    thing.url,
                    thing.content)
