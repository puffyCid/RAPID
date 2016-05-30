"""
Classes and functions for writing SafeBrowsing Records, which are IndicatorRecords with a record type of "SB."
"""
from django.conf import settings
from pivoteer.writer.core import CsvWriter


class SafeBrowsingCsvWriter(CsvWriter):
    """
    A CsvWriter implementation for SafeBrowsing Records
    """

    def __init__(self, writer):
        """
        Create a new CsvWriter for Search Records using the given writer
        :param writer:
        """
        super(SafeBrowsingCsvWriter, self).__init__(writer)
        self.__link = None

    def write(self, indicator, records):
        # Note: Currently, the SafeBrowsing CSV format includes the permalink in every row.  This link is based upon the
        # indicator being processed, which is passed in during this method.  We therefore create and store the permalink
        # as an instance member for the duration of the 'write' call--thus making this class very not thread safe!
        self.__link = settings.GOOGLE_SAFEBROWSING_URL + indicator
        super(SafeBrowsingCsvWriter, self).write(indicator, records)
        self.__link = None

    def create_header(self):
        return ["Date", "Response", "SafeBrowsing Link"]

    def create_rows(self, record):
        date = record.info_date
        body = record.info["body"]
        yield [date, body, self.__link]
