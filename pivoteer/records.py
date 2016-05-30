"""
Functions, classes, and enumerations particular to our indicator record types and sources

The RecordType enumeration defines the IndicatorRecord types supported in Pivoteer.  To add a new record, you will need
to give it a two-character name (enumeration constant) as well as a more descriptive title.  You should ALWAYS use
RecordType enumerations rather than using a "magic string" for the type.

The RecordSource enumeration is very similar to the RecordType enumeration.  Whereas RecordType specifies the type of a
record, RecordSource tells where that record came from.  Multiple record sources may possible create the records of the
same type, and a record source might also theoretically produce records of multiple types.  As with RecordType, new
record sources require a three-character name as well as a human-readable title.
"""

try:
    # Python 3
    import enum
except ImportError:
    # Python 2
    import enum34 as enum


class __TitledEnum(enum.Enum):
    """
    A base class for enumerations which are defined by a string value also accessible via the 'title' property
    """

    def __init__(self, title):
        """
        Create a new enumerated value with the given title
        :param title: The title
        """
        self.__title = title

    @property
    def title(self):
        """
        Get the title of this enumerated value.

        This method will also provide "title" as a read-only property of instance of instances of this class.

        :return: The title
        """
        return self.__title


@enum.unique
class RecordType(__TitledEnum):
    """
    A titled enumeration of record types
    """
    CE = "Censys Record"
    HR = "Host Record"
    MR = "Malware Record"
    SB = "SafeBrowsing Record"
    SR = "Search Record"
    TR = "ThreatCrowd Record"
    WR = "Whois Record"


@enum.unique
class RecordSource(__TitledEnum):
    """
    A titled enumeration of sources for indicator records
    """
    CEN = "Censys.io"
    DNS = "DNS Query"
    GSB = "Google Safe Browsing"
    GSE = "Google Search Engine"
    IID = "Internet Identity"
    PTO = "Passive Total"
    REX = "Robotex"
    TEX = "Threat Expert"
    THR = "ThreatCrowd"
    THS = "Total Hash"
    MWS = "Malwr"
    VTO = "Virus Total"
    WIS = "WHOIS"
