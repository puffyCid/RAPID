"""
Classes for writing Pivoteer indicator records to various formats.
"""

import abc


class Writer(object):
    """
    A base class for IndicatorRecord writers.

    Writers should NOT be considered thread-safe unless specifically documented as such.
    """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def write(self, indicator, record):
        """
        Write an IndicatorRecord.

        :param indicator: The indicator value of the record being written
        :param record: The record to be written
        :return:
        """
        raise NotImplementedError("Writer subclasses must implement 'write'")


class CsvWriter(Writer):
    """
    An abstract Writer implementation for saving IndicatorRecords in CSV format.

    Subclasses must implement the following methods:
        create_header: Create a single row (list) that is used as the header for the CSV columns
        create_rows: Create a list of rows for a record.   You may either return a list or implement this as a generator
        (though the latter is recommended)

    Subclasses MAY also elect to implement the following method(s):
        create_title_rows: Create a list of rows to be written at the top of the CSV output providing titular and/or
        summary information

    Finally, subclasses must remember to properly call the constructor in order to pass a csv.writer object.  Here is an
    example constructor for the class 'MyClass' which extends CsvWriter:
        class MyClass(CsvWriter):
            def __init__(self, writer):
                super(CsvWriter, self).__init__(writer)
    """

    __metaclass__ = abc.ABCMeta

    def __init__(self, writer):
        """
        Create a new CSV writer.

        :param writer: The CSV writer object
        """
        self.writer = writer

    def create_title_rows(self, indicator, records):
        """
        Create any title rows to be included with the CSV output.

        Title rows are placed before the actual header row.  Title rows may contain summary information and are
        particularly important when combining multiple record types in the same output.

        The default implementation returns an empty list (i.e. no title rows).  Should you choose to override this
        behavior, you should return a list of lists.   Each inner list is a title row, and each item in that inner list
        is a column in the row.

        :param indicator: The indicator value
        :param records: The records being written
        :return: A list of lists where each inner list is a title row whose items represent columns in that row
        """
        return list()

    @abc.abstractmethod
    def create_header(self):
        """
        Create the single header row for CSV output of this record type.

        :return: A list where each item therein is a column header
        """
        raise NotImplementedError("CsvWriter subclasses must implement 'create_headers'")

    @abc.abstractmethod
    def create_rows(self, record):
        """
        Convert an IndicatorRecord into row data.

        Some IndicatorRecords actually contain multiple results.  That's why this method expects a iterable of lists.
        Subclasses may elect to use a generator rather than returning a list, in which case each call should yield a
        list corresponding to a single row.  If returning a list, each item in the list must in turn be a list
        representing a single row.

        In other words, you could choose either of these approaches:
            def create_rows(self, record):
                # Generator Approach (Recommended)
                iterable = get_something_from_record(record)
                for thing in iterable:
                    row = make_row_from_thing(thing)
                    yield row
            def create_rows(self, record):
                # List Approach
                iterable = get_something_from_record(record)
                rows = list()
                for thing in iterable:
                    row = make_row_from_thing(thing)
                    rows.append(row)
                return rows

        Note that, even if a record corresponds to only one row, it is still necessary to return an iterable.

        :param record: The IndicatorRecord being processed
        :return: An iterable of row data
        """
        raise NotImplementedError("CsvWriter subclasses must implement 'create_row'")

    def write(self, indicator, records):
        if not records:
            return
        titles = self.create_title_rows(indicator, records)
        for row in titles:
            self.writer.writerow(row)
        header_row = self.create_header()
        if header_row:
            self.writer.writerow(header_row)
        for record in records:
            rows = self.create_rows(record)
            for row in rows:
                if row is not None:
                    self.writer.writerow(row)
