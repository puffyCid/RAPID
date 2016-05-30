import datetime, logging
from celery import Celery
from collections import OrderedDict
from django.test import TestCase
from pivoteer.records import RecordSource, RecordType
from pivoteer.models import IndicatorRecord, IndicatorManager
from pivoteer.tasks import certificate_cen, domain_thc, ip_thc, domain_whois, ip_whois, domain_hosts, ip_hosts, passive_hosts, malware_samples, google_safebrowsing, totalhash_ip_domain_search, make_indicator_search_records, save_record

app = Celery('RAPID')

logger = logging.getLogger(None)


class IndicatorRecordValues(TestCase):

    indicator = "twitter.com"
    ip_indicator = "199.59.150.7"
    current_time = datetime.datetime.utcnow()

    def setUp(self):
        # These settings ensure that Celery does not attempt to run tasks asynchronously.
        app.conf.update(CELERY_ALWAYS_EAGER=True)
        app.conf.update(TEST_RUNNER = 'djcelery.contrib.test_runner.CeleryTestSuiteRunner')

    def test_safebrowsing_record_contents(self):
        # Execute Celery task synchronously . This will store the record in the test DB.
        google_safebrowsing(self.indicator)

        # Retrieve records (return value is a QuerySet).
        safebrowsing_records = IndicatorRecord.objects.safebrowsing_record(self.indicator)

        # Validate that each field is included in the record.
        # We must loop even though there is only one record because Django gives us a QuerySet.
        for record in safebrowsing_records:
            self.assertTrue("SB" in record.record_type)
            self.assertTrue("GSB" in record.info_source)
            # self.assertTrue("info_date" in record)
            self.assertTrue("statusCode" in record.info)
            self.assertTrue("indicator" in record.info)
            self.assertTrue("body" in record.info)

    def test_malware_record_contents(self):
        # Execute Celery task synchronously. This will store the record in the test DB.
        malware_samples(self.indicator, "VTO")

        # Retrieve records (return value is a QuerySet).
        malware_vto_records = IndicatorRecord.objects.malware_records(self.indicator)

        # Validate that each field is included in the record.
        # We must loop even though there is only one record because Django gives us a QuerySet.
        for record in malware_vto_records:
            self.assertTrue("MR" in record.record_type)
            self.assertTrue("VTO" in record.info_source)
            self.assertTrue("md5" in record.info)
            self.assertTrue("sha1" in record.info)
            self.assertTrue("indicator" in record.info)
            self.assertTrue("link" in record.info)

    def test_certificate_cen_contents(self):
        # Execute Celery task synchronously. This will store the record in the test DB.
        certificate_cen(self.indicator)

        # Retrieve records (return value is a dict.).
        certificate_cen_records = IndicatorRecord.objects.recent_cert(self.indicator)

        # Validate that each field is included in the record.
        self.assertTrue("info_date" in certificate_cen_records)
        self.assertTrue("info" in certificate_cen_records)

    def test_domain_thc(self):
        # Execute Celery task synchronously. This will store the record in the test DB.
        domain_thc(self.indicator)

        # Retrieve records (return value is a dict).
        domain_thc_records = IndicatorRecord.objects.recent_tc(self.indicator)

        # Validate that each field is included in the record.
        self.assertTrue("info_date" in domain_thc_records)
        self.assertTrue("info" in domain_thc_records)

    def test_ip_thc(self):
        # Execute Celery task synchronously. This will store the record in the test DB.
        ip_thc(self.indicator)

        # Retrieve records (return value is a dict).
        ip_thc_records = IndicatorRecord.objects.recent_tc(self.indicator)

        # Validate that each field is included in the record.
        self.assertTrue("info_date" in ip_thc_records)
        self.assertTrue("info" in ip_thc_records)

    def test_domain_whois(self):
        # Execute Celery task synchronously. This will store the record in the test DB.
        domain_whois(self.indicator)

        # Retrieve records (return value is a ValuesQuerySet).
        domain_whois_records = IndicatorRecord.objects.whois_records(self.indicator)

        # Validate that each field is included in the record.
        # We must loop even though there is only one record because Django gives us a QuerySet.
        for record in domain_whois_records:
            self.assertTrue("domain_name" in record['info'])
            self.assertTrue("status" in record['info'])
            self.assertTrue("registrar" in record['info'])
            self.assertTrue("updated_date" in record['info'])
            self.assertTrue("expiration_date" in record['info'])
            self.assertTrue("nameservers" in record['info'])
            self.assertTrue("contacts" in record['info'])
            self.assertTrue("info_date" in record)

    def test_ip_whois(self):
        # Execute Celery task synchronously. This will store the record in the test DB.
        ip_whois(self.ip_indicator)

        # Retrieve records (return value is a QuerySet).
        ip_whois_records = IndicatorRecord.objects.whois_records(self.ip_indicator)

        # Validate that each field is included in the record.
        # We must loop even though there is only one record because Django gives us a QuerySet.
        for record in ip_whois_records:
            self.assertTrue("query" in record['info'])
            self.assertTrue("asn" in record['info'])
            self.assertTrue("asn_registry" in record['info'])
            self.assertTrue("asn_country_code" in record['info'])
            self.assertTrue("asn_date" in record['info'])
            self.assertTrue("referral" in record['info'])
            self.assertTrue("info_date" in record)


    def test_domain_hosts(self):
        # Execute Celery task synchronously. This will store the record in the test DB.
        domain_hosts(self.indicator)

        # Retrieve records (return value is a QuerySet).
        domain_hosts_records = IndicatorRecord.objects.recent_hosts(self.indicator)

        # Validate that each field is included in the record.
        # We must loop even though there is only one record because Django gives us a QuerySet.
        for record in domain_hosts_records:
            self.assertTrue("HR" in record.record_type)
            self.assertTrue("DNS" in record.info_source)
            # self.assertTrue("info_date" in record)
            # self.assertTrue("info" in record)
            self.assertTrue("geo_location" in record.info)
            self.assertTrue("https_cert" in record.info)
            self.assertTrue("ip" in record.info)

    def test_ip_hosts(self):
        # Execute Celery task synchronously. This will store the record in the test DB.
        ip_hosts(self.ip_indicator)

        # Retrieve records (return value is a QuerySet).
        ip_hosts_records = IndicatorRecord.objects.recent_hosts(self.ip_indicator)

        # Validate that each field is included in the record.
        # We must loop even though there is only one record because Django gives us a QuerySet.
        for record in ip_hosts_records:
            self.assertTrue("HR" in record.record_type)
            self.assertTrue("REX" in record.info_source)
            # self.assertEqual(self.current_time, record.info_date)
            # self.assertTrue("info" in record)
            self.assertTrue("geo_location" in record.info)
            self.assertTrue("https_cert" in record.info)
            self.assertTrue("ip" in record.info)

    def test_passive_hosts(self):
        # Execute Celery task synchronously. This will store the record in the test DB.
        ip_hosts(self.ip_indicator)

        # Retrieve records (return value is a QuerySet).
        ip_hosts_records = IndicatorRecord.objects.host_records(self.ip_indicator)

        # Validate that each field is included in the record.
        # We must loop even though there is only one record because Django gives us a QuerySet.
        for record in ip_hosts_records:
            self.assertTrue("HR" in record.record_type)
            self.assertTrue("REX" in record.info_source)
            self.assertTrue("geo_location" in record.info)
            self.assertTrue("domain" in record.info)
            self.assertTrue("ip" in record.info)

    def test_make_indicator_search_records(self):
        # Execute Celery task synchronously. This will store the record in the test DB.
        # make_indicator_search_records(self.indicator, "domain")

        # Retrieve records (return value is QuerySet).
        google_records = IndicatorRecord.objects.get_search_records(self.indicator)

        for record in google_records:
            self.assertTrue("info" in record)
            self.assertTrue("info_date" in record)
            self.assertTrue("results" in record['info'])
            self.assertTrue("indicator" in record['info'])

    #  Excluded due to API limit restrictions.
    #   def test_totalhash_ip_domain_search(self):

    def test_save_record(self):
        record_type = RecordType.SB
        record_source = RecordSource.GSB
        info = "foo"
        record = save_record(record_type, record_source, info)

        self.assertEqual(record.record_type, record_type.name)
        self.assertEqual(record.info_source, record_source.name)
        self.assertEqual(info, record.info)
        self.assertTrue(hasattr(record, 'info_date'))

