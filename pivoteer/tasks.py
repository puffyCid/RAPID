from __future__ import absolute_import
import sys
from netaddr import *

import datetime, logging, json
from dateutil.parser import parse
import dpath.util
from collections import OrderedDict
from django.conf import settings
from RAPID.celery import app
from core.utilities import scrape_attribute
from core.threatcrowd import ThreatCrowd
from core.totalhash import TotalHashApi
from core.malwr import MalwrApi
from core.lookups import lookup_ip_whois, lookup_domain_whois, resolve_domain, geolocate_ip, lookup_ip_censys_https, \
    lookup_google_safe_browsing, lookup_certs_censys, google_for_indicator, LookupException
from pivoteer.collectors.scrape import RobtexScraper, InternetIdentityScraper
from pivoteer.collectors.scrape import VirusTotalScraper, ThreatExpertScraper
from pivoteer.collectors.api import PassiveTotal
from pivoteer.records import RecordSource, RecordType
from .models import IndicatorRecord

logger = logging.getLogger(None)

def create_record(record_type,
                  record_source,
                  info,
                  date=None):
    """
    Create an indicator record.

    :param record_type: The record type, which should be a value from the RecordType enumeration
    :param record_source: The source for the record, which should be a value from the RecordSource enumeration
    :param info: The actual data to be stored in the record
    :param date: The date to use with this record, or None to use the current date
    :return: The new IndicatorRecord instance
    """
    current_time = date or datetime.datetime.utcnow()
    record = IndicatorRecord(record_type=record_type.name,
                             info_source=record_source.name,
                             info_date=current_time,
                             info=info)
    logger.info("Created %s (%s) record from %s: %s",
                record_type.name,
                record_type.title,
                record_source.title,
                record)
    return record


def save_record(record_type,
                record_source,
                info,
                date=None):
    """
    A convenience function that calls 'create_record' and also saves the resulting record.

    :param record_type: The record type, which should be a value from the RecordType enumeration
    :param record_source: The source for the record, which should be a value from the RecordSource enumeration
    :param info: The actual data to be stored in the record
    :param date: The date to use with this record, or None to use the current date
    :return: The new IndicatorRecord instance
    """
    record = create_record(record_type, record_source, info, date)
    record.save()
    logger.info("%s (%s) record from %s saved successfully",
                record_type.name,
                record_type.title,
                record_source.title)
    return record


@app.task
def empty_task(indicator):
    """Task that does nothing, because a tab with no task won't load.
    """
    pass


@app.task
def certificate_cen(indicator):
    record_type = RecordType.CE
    record_source = RecordSource.CEN
    record = lookup_certs_censys(indicator, 25)
    record['indicator'] = indicator
    logger.info("Retrieved Censys.io search results for indicator %s" % indicator)
    if record:
        try:
            save_record(record_type, record_source, record)
        except Exception:
            logger.exception("Error saving %s (%s) record from %s",
                             record_type.name,
                             record_type.title,
                             record_source.title)


# Task to look up threatcrowd domain
@app.task
def domain_thc(domain):
    record_type = RecordType.TR
    record_source = RecordSource.THR
    record = ThreatCrowd.queryDomain(domain)
    record['domain'] = domain
    logger.info("Retrieved ThreatCrowd data for domain %s. Data: %s" % (domain, json.dumps(record)))
    if record:
        try:
            save_record(record_type, record_source, record)
        except Exception:
            logger.exception("Error saving %s (%s) record from %s",
                             record_type.name,
                             record_type.title,
                             record_source.title)


# Task to look up threatcrowd ip
@app.task
def ip_thc(ip):
    record_type = RecordType.TR
    record_source = RecordSource.THR
    record = ThreatCrowd.queryIp(ip)
    record['ip'] = ip
    if record:
        try:
            save_record(record_type, record_source, record)
        except Exception:
            logger.exception("Error saving %s (%s) record from %s",
                             record_type.name,
                             record_type.title,
                             record_source.title)


@app.task
def domain_whois(domain):
    record_type = RecordType.WR
    record_source = RecordSource.WIS
    record = lookup_domain_whois(domain)

    if record:
        try:
            info = OrderedDict({'domain_name': record['domain_name'],
                                'status': record['status'],
                                'registrar': record['registrar'],
                                'updated_date': record['updated_date'],
                                'expiration_date': record['expiration_date'],
                                'nameservers': record['nameservers'],
                                'contacts': record['contacts']})
            save_record(record_type, record_source, info)
        except Exception:
            logger.exception("Error saving %s (%s) record from %s",
                             record_type.name,
                             record_type.title,
                             record_source.title)


@app.task
def ip_whois(ip_address):
    record_type = RecordType.WR
    record_source = RecordSource.WIS
    record = lookup_ip_whois(ip_address)

    if record:
        try:
            info = OrderedDict({'query': record['query'],
                                'asn_cidr': record['asn_cidr'],
                                'asn': record['asn'],
                                'asn_registry': record['asn_registry'],
                                'asn_country_code': record['asn_country_code'],
                                'asn_date': record['asn_date'],
                                'referral': record['referral'],
                                'nets': record['nets']})
            save_record(record_type, record_source, info)
        except Exception:
            logger.exception("Error saving %s (%s) record from %s",
                             record_type.name,
                             record_type.title,
                             record_source.title)


@app.task
def domain_hosts(domain):
    try:
        hosts = resolve_domain(domain)
    except LookupException as e:
        logger.error("Error performing domain resolution for domain '%s': %s", domain, e.message)
        return
    if type(hosts) == list:
        record_type = RecordType.HR
        record_source = RecordSource.DNS
        for host in hosts:
            ip_location = geolocate_ip(host)
            https_cert = lookup_ip_censys_https(host)
            info = OrderedDict({"geo_location": ip_location,
                                "https_cert": https_cert,
                                "ip": host, "domain": domain})
            try:
                save_record(record_type,
                            record_source,
                            info)
            except Exception:
                logger.exception("Error saving %s (%s) record from %s",
                                 record_type.name,
                                 record_type.title,
                                 record_source.title)


@app.task
def ip_hosts(ip_address):
    scraper = RobtexScraper()
    hosts = scraper.run(ip_address)
    ip_location = geolocate_ip(ip_address)
    https_cert = lookup_ip_censys_https(ip_address)

    if type(hosts) == list:
        record_type = RecordType.HR
        record_source = RecordSource.REX
        for host in hosts:
            try:
                info = OrderedDict({"geo_location": ip_location,
                                    "https_cert": https_cert,
                                    "ip": ip_address, "domain": host})
                save_record(record_type,
                            record_source,
                            info)
            except Exception:
                logger.exception("Error saving %s (%s) record from %s",
                                 record_type.name,
                                 record_type.title,
                                 record_source.title)


@app.task
def passive_hosts(indicator, record_source):
    record_type = RecordType.HR
    if record_source is RecordSource.IID:
        scraper = InternetIdentityScraper()
        passive = scraper.run(indicator)  # returns table of data rows {ip, domain, date, ip_location}

    elif record_source is RecordSource.PTO:
        api_key = settings.PASSIVE_TOTAL_API
        collector = PassiveTotal(api_key, api_version="v1")
        passive = collector.retrieve_data(indicator, "passive")

    elif record_source is RecordSource.VTO:
        scraper = VirusTotalScraper()
        passive = scraper.get_passive(indicator)  # returns table of data rows {ip, domain, date, ip_location}

    else:
        passive = {}

    for entry in passive:
        try:
            date = entry['date']
            info = OrderedDict({"geo_location": entry['ip_location'],
                                "ip": entry['ip'],
                                "domain": entry['domain']})
            save_record(record_type, record_source, info, date=date)
        except Exception:
            logger.exception("Error saving %s (%s) record from %s",
                             record_type.name,
                             record_type.title,
                             record_source.title)


@app.task
def malware_samples(indicator, record_source):
    record_type = RecordType.MR
    if record_source is RecordSource.VTO:
        scraper = VirusTotalScraper()
        malware = scraper.get_malware(indicator)

    elif record_source is RecordSource.TEX:
        scraper = ThreatExpertScraper()
        malware = scraper.run(indicator)

    else:
        malware = []

    for entry in malware:
        try:
            date = entry['date']
            info = OrderedDict({"md5": entry['md5'],
                                "sha1": entry['sha1'],
                                "sha256": entry['sha256'],
                                "indicator": entry['C2'],
                                "link": entry['link']})
            save_record(record_type, record_source, info, date=date)
        except Exception:
            logger.exception("Error saving %s (%s) record from %s",
                             record_type.name,
                             record_type.title,
                             record_source.title)

@app.task
def google_safebrowsing(indicator):
    record_type = RecordType.SB
    record_source = RecordSource.GSB
    safebrowsing_response = lookup_google_safe_browsing(indicator)
    safebrowsing_status = safebrowsing_response[0]
    safebrowsing_body = safebrowsing_response[1]
    # We store the status code that the Google SafeSearch API returns.
    info = OrderedDict({"indicator": indicator,
                        "statusCode": safebrowsing_status,
                        "body": safebrowsing_body})
    try:
        save_record(record_type, record_source, info)
    except Exception:
        logger.exception("Error saving %s (%s) record from %s",
                         record_type.name,
                         record_type.title,
                         record_source.title)


# Task to look up malwr ip or domain search terms
@app.task
def malwr_ip_domain_search(indicator):
    record_type = RecordType.MR
    record_source = RecordSource.MWS
    mw_logger = logging.getLogger(None)
    api_id = settings.MALWR_LOGIN_ID
    api_secret = settings.MALWR_LOGIN_SECRET
    mw = MalwrApi(username=api_id, password=api_secret)
    if valid_ipv6(indicator) or valid_ipv4(indicator):
        query = "ip:" + indicator
    else:
        query = "domain:" + indicator

    raw_record = mw.search(search_word=query);

    if len(raw_record) > 0:
        try:
            mw_logger.info("Retrieved Malwr data for query %s Data: %s" % (query, raw_record))

            for entry in raw_record:
                m_hash_link = "https://malwr.com" + entry['submission_url']
                submission_time = parse(entry['submission_time'])
                info = OrderedDict({"sha1": entry['hash'],
                                    "indicator": indicator,
                                    "link": m_hash_link,
                                    "md5": "",
                                    "sha256": ""})
                save_record(record_type,
                            record_source,
                            info,
                            date=submission_time)

            logger.info("%s %s for %s saved successfully",
                        len(raw_record),
                        record_type.title,
                        record_source.title)


        except Exception:
            logger.exception("Error saving %s (%s) record from %s",
                             record_type.name,
                             record_type.title,
                             record_source.title)
    else:
        mw_logger.info("No Malwr data, save aborted")



# Task to look up totalhash ip or domain search terms
@app.task
def totalhash_ip_domain_search(indicator):
    record_type = RecordType.MR
    record_source = RecordSource.THS
    th_logger = logging.getLogger(None)
    api_id = settings.TOTAL_HASH_API_ID
    api_secret = settings.TOTAL_HASH_SECRET
    current_time = datetime.datetime.utcnow()
    th = TotalHashApi(user=api_id, key=api_secret)
    if valid_ipv6(indicator) or valid_ipv4(indicator):
        query = "ip:" + indicator
    else:
        query = "dnsrr:" + indicator
    th_logger.info("Querying Totalhash for %s" % query)
    res = th.do_search(query)
    record = th.json_response(res)  # from totalhash xml response
    try:
        record_count = dpath.util.get(json.loads(record), "response/result/numFound")
    except KeyError:
        logger.info("No Totalhash data, save aborted")
        return None

    if int(record_count) > 0:
        try:
            raw_record = json.loads(record)

            th_logger.info("Retrieved Totalhash data for query %s Data: %s" % (query, raw_record))

            # Adding to malware records, # key 'text' contains actual hash
            # We must include md5 and sha256 even though this task doesn't gather values for them.
            # Otherwise, some record retrieval methods may fail.
            for entry in scrape_attribute(raw_record, 'text'):
                hash_link = "https://totalhash.cymru.com/analysis/?" + entry
                info = OrderedDict({"sha1": entry,
                                    "indicator": indicator,
                                    "link": hash_link,
                                    "md5": "",
                                    "sha256": ""})
                save_record(record_type,
                            record_source,
                            info,
                            date=current_time)

            logger.info("%s TH record_entries saved successfully" % record_count)
        except Exception:
            logger.exception("Error saving %s (%s) record from %s",
                             record_type.name,
                             record_type.title,
                             record_source.title)
    else:
        logger.info("No Totalhash data, save aborted")


@app.task
def make_indicator_search_records(indicator, indicator_type):
    """
    A Celery task for searching Google for an indicator.

    If the indicator is a domain, results from the domain itself will be xcluded.

    This task creates an indicator record of type 'SR' (Search Result) and a source of 'GSE' (Google Search Engine).
    The record will have the current time associated with it.  Ther ecord data is an ordered mapping containing three
    keys:
        indicator: The indicator value
        indicator_type: The indicator type
        results: A list of SearchResult dictionary objects.  The order of this list should be the order in which results
                 were returned by Google.   Please refer to the documentation for core.google.SearchResult for a
                 description of these objects.

    :param indicator: The indicator being processed
    :param indicator_type: The type of the indicator
    :return: This method does not return any values
    """
    record_type = RecordType.SR
    record_source = RecordSource.GSE
    try:
        domain = indicator if indicator_type == 'domain' else None
        results = google_for_indicator(indicator, domain=domain)
        info = OrderedDict({"indicator": indicator,
                            "results": results})
        save_record(record_type, record_source, info)
    except Exception:
        logger.exception("Error saving %s (%s) record from %s",
                         record_type.name,
                         record_type.title,
                         record_source.title)
