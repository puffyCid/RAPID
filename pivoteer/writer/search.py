"""
Classes and functions for writing Search Records.

A Search Record is an IndicatorRecord with a record type of "SR."
"""
from core.google import SearchResult
from pivoteer.writer.core import CsvWriter


class SearchCsvWriter(CsvWriter):
    """
    A CsvWriter for IndicatorRecord objects with a record type of "SR" (Search Record)
    """

    def __init__(self, writer):
        """
        Create a new CsvWriter for Search Records using the given writer
        :param writer:
        """
        super(SearchCsvWriter, self).__init__(writer)

    def create_title_rows(self, indicator, records):
        title = "Top Google Search Results for Indicator '%s'" % indicator
        return [[title]]

    def create_header(self):
        return ["Title", "URL", "Content"]

    def create_rows(self, record):
        info = record["info"]
        results = info["results"]
        for result in results:
            search_result = SearchResult.from_dict(result)
            row = [search_result.title,
                   search_result.url,
                   search_result.content]
            yield row
