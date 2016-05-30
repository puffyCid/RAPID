import datetime, logging
from collections import OrderedDict
from django.test import TestCase
from pivoteer.records import RecordSource, RecordType
from pivoteer.models import IndicatorRecord
from pivoteer.tasks import save_record

logger = logging.getLogger(None)
class IndicatorManagerValues(TestCase):

    indicator = "twitter.com"
    ip_indicator = "199.59.150.7"

    def test_safebrowsing_retreival(self):
        record_type = RecordType.SB
        record_source = RecordSource.GSB
        info = {"indicator": self.indicator,
                "statusCode": 204,
                "body": "OK"}
        save_record(record_type, record_source, info)

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
        record_type = RecordType.MR
        record_source = RecordSource.VTO
        info = {"indicator": self.indicator,
                "link": "val",
                "md5": "val",
                "sha1": "val"}
        save_record(record_type, record_source, info)

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
        record_type = RecordType.CE
        record_source = RecordSource.CEN
        info = {"info": "test",
                "indicator": self.indicator}
        save_record(record_type, record_source, info)

        # Retrieve records (return value is a dict.).
        certificate_cen_records = IndicatorRecord.objects.recent_cert(self.indicator)

        # Validate that each field is included in the record.
        self.assertTrue("info_date" in certificate_cen_records)
        self.assertTrue("info" in certificate_cen_records)

    def test_domain_thc(self):
        record_type = RecordType.TR
        record_source = RecordSource.THR
        info = {"info": "test",
                "domain": self.indicator}
        save_record(record_type, record_source, info)

        # Retrieve records (return value is a dict).
        domain_thc_records = IndicatorRecord.objects.recent_tc(self.indicator)

        # Validate that each field is included in the record.
        self.assertTrue("info_date" in domain_thc_records)
        self.assertTrue("info" in domain_thc_records)

    def test_ip_thc(self):
        record_type = RecordType.TR
        record_source = RecordSource.THR
        info = {"info": "test",
                "ip": self.ip_indicator}
        save_record(record_type, record_source, info)

        # Retrieve records (return value is a dict).
        ip_thc_records = IndicatorRecord.objects.recent_tc(self.ip_indicator)

        # Validate that each field is included in the record.
        self.assertTrue("info_date" in ip_thc_records)
        self.assertTrue("info" in ip_thc_records)

    def test_domain_whois(self):
        record_type = RecordType.WR
        record_source = RecordSource.WIS
        record = {}
        record['info_date'] = datetime.datetime.utcnow()
        record['info'] = OrderedDict({'domain_name': self.indicator,
                            'status': 200,
                            'registrar': "test",
                            'updated_date': record['info_date'],
                            'expiration_date': datetime.datetime.utcnow() + datetime.timedelta(hours=-24),
                            'nameservers': "test",
                            'contacts': "test"})
        save_record(record_type, record_source, record)

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

        record_type = RecordType.WR
        record_source = RecordSource.WIS
        info = OrderedDict({'query': self.ip_indicator,
                            'asn_cidr': 'test',
                            'asn': 'test',
                            'asn_registry': 'test',
                            'asn_country_code': 'test',
                            'asn_date': 'test',
                            'referral': 'test',
                            'nets': 'test'})
        json = save_record(record_type, record_source, info)
        # Retrieve records (return value is a QuerySet).]
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


    def test_domain_hosts(self):
        record_type = RecordType.HR
        record_source = RecordSource.DNS
        info = OrderedDict({"geo_location": "test",
                            "https_cert": "test",
                            "ip": self.ip_indicator,
                            "domain": "test"})

        save_record(record_type, record_source, info)

        # Retrieve records (return value is a QuerySet).
        domain_hosts_records = IndicatorRecord.objects.recent_hosts(self.ip_indicator)

        # Validate that each field is included in the record.
        # We must loop even though there is only one record because Django gives us a QuerySet.
        for record in domain_hosts_records:
            self.assertTrue("HR" in record.record_type)
            self.assertTrue("DNS" in record.info_source)
            self.assertTrue("geo_location" in record.info)
            self.assertTrue("https_cert" in record.info)
            self.assertTrue("ip" in record.info)

    def test_ip_hosts(self):
        record_type = RecordType.HR
        record_source = RecordSource.REX
        info = OrderedDict({"geo_location": "test",
                            "https_cert": "test",
                            "ip": self.ip_indicator,
                            "domain": "test"})
        save_record(record_type, record_source, info)

        # Retrieve records (return value is a QuerySet).
        ip_hosts_records = IndicatorRecord.objects.recent_hosts(self.ip_indicator)

        # Validate that each field is included in the record.
        # We must loop even though there is only one record because Django gives us a QuerySet.
        for record in ip_hosts_records:
            self.assertTrue("HR" in record.record_type)
            self.assertTrue("REX" in record.info_source)
            self.assertTrue("geo_location" in record.info)
            self.assertTrue("https_cert" in record.info)
            self.assertTrue("ip" in record.info)

    def test_passive_hosts(self):
        record_type = RecordType.HR
        record_source = RecordSource.REX
        info = OrderedDict({"geo_location": "test",
                            "https_cert": "test",
                            "ip": self.ip_indicator,
                            "domain": "test"})
        save_record(record_type, record_source, info)

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
        record_type = RecordType.SR
        record_source = RecordSource.GSE
        info = OrderedDict({"indicator": self.indicator,
                            "results": "test"})
        save_record(record_type, record_source, info)

        # Retrieve records (return value is QuerySet).
        google_records = IndicatorRecord.objects.get_search_records(self.indicator)

        for record in google_records:
            self.assertTrue("info" in record)
            self.assertTrue("info_date" in record)
            self.assertTrue("results" in record['info'])
            self.assertTrue("indicator" in record['info'])
