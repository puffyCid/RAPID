"""
Classes and functions for writing IndicatorRecords with a record_type of "WR" (WhoIs Record)
"""

from pivoteer.writer.core import CsvWriter


class WhoIsCsvWriter(CsvWriter):
    """
    A CsvWriter implementation for writing IndicatorRecords with a record type of "WR" (WhoIs Record) in CSV format
    """

    def __init__(self, writer):
        """
        Create a new CsvWriter for Search Records using the given writer
        :param writer:
        """
        super(WhoIsCsvWriter, self).__init__(writer)

    def create_header(self):
        return ["Lookup Date", "WHOIS Information"]

    def create_rows(self, record):
        if record is not None:
            date = record.get("info_date", None)
            info = record.get("info", None)
            if date and info:
                yield [date, info]
