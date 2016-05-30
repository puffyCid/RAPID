import datetime
from IPy import IP
import tldextract
import re


def time_jump(days=0, hours=0, minutes=0):
    """
    Return the time X number of hours from current time (utc)
    """
    start_timestamp = datetime.datetime.utcnow()
    minute_timestamp = start_timestamp.strftime('%Y-%m-%d %H:%M')

    current_time = datetime.datetime.strptime(minute_timestamp, '%Y-%m-%d %H:%M')
    differential = current_time + datetime.timedelta(days=days,
                                                     hours=hours,
                                                     minutes=minutes)

    return differential


def check_ip_valid(submission):
    """
    Check if submission is a valid IP address
    """
    try:
        if str(IP(submission)) == str(submission):
            return True
        else:
            return False

    except ValueError:
        return False


def check_email_valid(submission):
    """
    Check if submission is a valid email address
    """
    if re.match(r"[^@]+@[^@]+\.[^@]+", submission):
        return True
    else:
        return False


def check_domain_valid(submission):
    """
    Check if a submission is a valid domain.

    :param submission: The submission to be checked
    :return: True if 'submission' is a valid domain, otherwise False
    """
    return re.match("^([A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*(?:\\.[A-Za-z]{2,}))$", submission) is not None


def discover_type(submission):
    """Figure out type of indicator a submission is
    
    Valid types are:
        ip: If the string matches an ipv4 string (i.e. '1.2.3.4')
        domain: If the string matches a valid domain name (i.e. 'www.domain.com')
        other: Any string that does not match one of the others.
    
    Args:
        submission (str): The indicator to check the type against
    
    Returns (str): The indicator type: 'ip', 'domain', or 'other'
    
    """
    if check_ip_valid(submission):
        return "ip"

    #elif check_email_valid(submission):
    #    return "email"

    elif check_domain_valid(submission):
        return "domain"

    else:
        return "other"


def get_base_domain(submission):
    # Extract base domain name for lookup
    ext = tldextract.extract(submission)

    if ext.domain and ext.tld:
        delimiter = "."
        sequence = (ext.domain, ext.tld)
        domain_name = delimiter.join(sequence)
        return domain_name

    return None

def scrape_attribute(search_dict, field):
    fields_found = []
    if isinstance(search_dict, dict):
        for k, v in search_dict.items():
            if k == field:
                fields_found.append(v)
            elif isinstance(v, dict):
                results = scrape_attribute(v, field)
                for result in results:
                    fields_found.append(result)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        more_results = scrape_attribute(item, field)
                        for another_result in more_results:
                            fields_found.append(another_result)
    return fields_found


