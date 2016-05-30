"""
Classes and functions for writing Host Records.

Host Records are IndicatorRecords with a record type of "HR."
"""

from pivoteer.writer.core import CsvWriter


class HostCsvWriter(CsvWriter):
    """
    A CsvWriter implementation for IndicatorRecord objects with a record type of "HR" (Host Record)
    """

    def __init__(self, writer):
        """
        Create a new CsvWriter for Host Records using the given writer.

        :param writer: The writer
        """
        super(HostCsvWriter, self).__init__(writer)

    def create_header(self):
        return ["Date", "Source", "IP", "Domain", "IP Location"]

    def create_rows(self, record):
        if record is not None:
            yield [record.info_date,
                   record.info_source,
                   record.info["ip"],
                   record.info["domain"],
                   record.info["geo_location"]]

