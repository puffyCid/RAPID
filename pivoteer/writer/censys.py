"""
Classes and functions for writing IndicatorRecord objects with a record type of "CE" (Censys Record)
"""

from pivoteer.writer.core import CsvWriter


class CensysCsvWriter(CsvWriter):
    """
    A CsvWriter implementation for IndicatorRecords with a record type of "CE" (Censys Record)
    """

    def __init__(self, writer):
        """
        Create a new CsvWriter for Censys Records using the given writer.

        :param writer: The writer
        """
        super(CensysCsvWriter, self).__init__(writer)

    def create_title_rows(self, indicator, records):
        yield ["Certificate Search Results"]

    def create_header(self):
        return ["Subject", "Issuer", "SHA256", "Validity Start", "Validity End"]

    def create_rows(self, record):
        info = record["info"]
        records = info["records"]
        for record in records:
            parsed = record["parsed"]
            subject = parsed["subject_dn"]
            issuer = parsed["issuer_dn"]
            sha256 = parsed["fingerprint_sha256"]
            validity = parsed["validity"]
            start = validity["start"]
            end = validity["end"]
            yield [subject, issuer, sha256, start, end]
