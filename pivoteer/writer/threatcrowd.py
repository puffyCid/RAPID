"""
Classes and functions for writing Threat Crowd records.

Threat Crowd Records are IndicatorRecords with a record type of "TR."
"""

from pivoteer.writer.core import CsvWriter


class ThreatCrowdCsvWriter(CsvWriter):
    """
    A CsvWriter implementation for writing Threat Crowd Records (i.e. IndicatorRecords with a record type of "TR").
    """

    def __init__(self, writer):
        """
        Create a new CsvWriter for Host Records using the given writer.

        :param writer: The writer
        """
        super(ThreatCrowdCsvWriter, self).__init__(writer)

    def create_title_rows(self, indicator, records):
        return [["ThreatCrowd Records"]]

    def create_header(self):
        return ["Type", "Data", "Date"]

    def create_rows(self, record):
        if record is None:
            return
        info = record["info"]
        if info is None:
            return
        response_code = info["response_code"]
        if response_code != "1":
            return

        yield ["Lookup Date", record["info_date"], None]
        info = record.get("info", None)
        if not info:
            return
        yield ["Permalink", info.get("permalink", None), None]
        yield ["Emails", ", ".join(info.get("emails", list())), None]
        resolutions = info.get("resolutions", None)
        if resolutions:
            for resolution in resolutions:
                value = resolution.get("ip_address", None) or resolution.get("domain", None)
                resolved = resolution.get("last_resolved", None)
                yield ["Resolution", value, resolved]
        subdomains = info.get("subdomains", None)
        if subdomains:
            for subdomain in subdomains:
                yield ["Subdomain", subdomain, None]
        hashes = info.get("hashes")
        if hashes:
            for h in hashes:
                yield ["Hash", h, None]
