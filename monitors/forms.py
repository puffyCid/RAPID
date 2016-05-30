import logging
import re
from django import forms
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from core.utilities import time_jump
from core.utilities import discover_type
from .models import CertificateMonitor, DomainMonitor, IpMonitor
from .tasks import GEOLOCATION_KEY, DOMAIN_KEY, IP_KEY


LOGGER = logging.getLogger(__name__)
"""The logger for this module"""

User = get_user_model()

PENDING = "(Pending)"
"""A string used to indicate that a monitor has been submitted but not yet run"""


class MonitorSubmission(forms.Form):
    indicators = forms.CharField(label='Indicator Submission', widget=forms.TextInput())

    def __init__(self, *args, **kwargs):
        super(MonitorSubmission, self).__init__(*args, **kwargs)
        self.valid_domains = []
        self.valid_ips = []

    def clean_indicators(self):
        submission = self.cleaned_data.get('indicators')
        indicator_list = re.split(r'[,;|\n\r ]+', submission)

        for indicator in indicator_list:

            indicator = indicator.rstrip().lower()
            indicator_type = discover_type(indicator)

            if indicator_type == "domain":
                self.valid_domains.append(indicator)

            if indicator_type == "ip":
                self.valid_ips.append(indicator)

            if indicator_type == "other":
                LOGGER.warn("Discarding attempt to add '%s' as an IP or Domain to be monitored", indicator)
                raise ValidationError("%s is not a valid IP or Domain" % indicator)

    def save_submission(self, request):

        current_user = User.objects.get(email__exact=request.user)
        lookup_time = time_jump(minutes=2)
        set_interval = 24

        for domain in self.valid_domains:

            try:
                new_monitor = DomainMonitor(owner=current_user,
                                            domain_name=domain,
                                            lookup_interval=set_interval,
                                            next_lookup=lookup_time)
                new_monitor = self.update_monitor(new_monitor)
                new_monitor.save()
            except:
                LOGGER.exception("Error saving domain monitor from %s for %s", current_user, domain)

        for ip_address in self.valid_ips:

            try:
                new_monitor = IpMonitor(owner=current_user,
                                        ip_address=ip_address,
                                        lookup_interval=set_interval,
                                        next_lookup=lookup_time)
                new_monitor = self.update_monitor(new_monitor)
                new_monitor.save()
            except:
                LOGGER.exception("Error saving IP monitor from %s for %s", current_user, ip_address)

    def update_monitor(self, monitor):
        """
        Update an indicator monitor.

        The default implementation will return the monitor unmodified.  Subclasses may override this method if they
        provide additional information for the monitor.

        :param monitor: The monitor to be updated.  This will be a subclass of IndicatorLookupBase.
        :return: The updated monitor
        """
        return monitor


class SubmissionWithHosts(forms.Form):
    """
    A Django form for submitting a list of hosts.

    This is intended as a superclass for any monitor forms that would allow the user to specify initial hosts rather
    than considering the initial hosts to be an empty field.  (This means that not all resolved hosts will necessarily
    be considered new the first time the monitor is run.)

    Users may specify any number of hosts.  Multiple hosts are delimited with a comma, semicolon, pipe, or whitespace.
    Subclasses may access validated hosts via the 'valid_hosts' member.  Should subclasses require additional host
    validation (e.g. enforcing only IP addresses as hosts), they should override 'clean_hosts.'

    Finally, this class provides the 'update_monitor' method that will set the 'last_hosts' member of a provided
    IndicatorLookupBase monitor to the hosts provided in the form input.
    """

    hosts = forms.CharField(label="Hosts (separate with comma, semicolon, or space)",
                            widget=forms.TextInput(),
                            required=False)
    """The hosts to be associated with any submitted indicators.  Multiple hosts may be submitted separated by a comma,
    semicolon, pipe, or space."""

    def __init__(self, *args, **kwargs):
        super(SubmissionWithHosts, self).__init__(*args, **kwargs)
        self.valid_hosts = list()

    def clean_hosts(self):
        """
        Clean the values of the 'hosts' form field.

        Note: There's Django magic in this method name.  All method names "clean_foo" are used to clean the data member
        "foo."  Thus this method is used to clean the data member "hosts."

        :return: This method returns no values
        """
        try:
            submission = self.cleaned_data.get("hosts")
            if submission is not None and len(submission) > 0:
                self.valid_hosts = re.split(r"[,;|\n\r ]+", submission)
        except Exception as e:
            LOGGER.exception("Unexpected exception cleaning hosts")
            raise e

    def update_monitor(self, monitor):
        """
        Update an IndicatorLookupBase subclass monitor with the provided last hosts.

        :param monitor: The monitor to be updated
        :return: The updated monitor
        """
        # Note: Even though this class doesn't inherit from MonitorSubmission, using this method signature will ensure
        # that it "just works" if you do multiple inheritance to have both indicator values and hosts (i.e.
        # MonitorSubmissionWithHosts, below).
        monitor.last_hosts = list(self.valid_hosts)
        return monitor


class MonitorSubmissionWithHosts(MonitorSubmission, SubmissionWithHosts):
    """
    A Django form allowing users to submit IP or Domain indicators for monitoring with an optional initial list of
    hosts.
    """
    # Note: The idea is that, if they ever want to allow initial hosts to be specified with IPs or Domains, they can
    # just start using this class instead of MonitorSubmission.  (Note that they would still have to update the
    # 'add.html' template, however!)
    def __init__(self, *args, **kwargs):
        super(MonitorSubmissionWithHosts, self).__init__(*args, **kwargs)


class CertificateSubmission(SubmissionWithHosts):
    """
    A Django form for submitting a monitor for a certificate indicator.

    Users submit a certificate fragment.  They may optionally also submit one or more hosts.
    """

    fragment = forms.CharField(label="Certificate Fragment", widget=forms.TextInput())
    """The certificate value to be used as a monitor"""

    def __init__(self, *args, **kwargs):
        super(CertificateSubmission, self).__init__(*args, **kwargs)

    def save_submission(self, request):
        """
        Save a CertificateMonitor based upon the contents of this form.

        :param request: The request being processed
        :return:  This method returns no values
        """
        indicator = self.cleaned_data.get("fragment")
        if indicator is None:
            LOGGER.debug("No certificate specified")
            return
        user = User.objects.get(email__exact=request.user)
        lookup_time = time_jump(minutes=2)
        interval = 24

        # Build the 'resolutions' monitor member.  We're not actually going to do full resolutions now (which would
        # entail doing geo-location and domain lookup for each IP host).   Rather, we'll just use placeholder values
        # until the monitor runs for the first time (as a periodic task).  This is important because it means that we
        # will have a set of hosts already saved for this monitor.  Therefore, when this monitor runs for the first time
        # it will have a previous set of hosts to which to compare.  (In other words, the first time it runs not every
        # host will necessarily be new, and there may be some missing hosts on the first run.)
        resolutions = dict()
        for host in self.valid_hosts:
            if host not in resolutions:
                resolutions[host] = dict()
            resolution = resolutions[host]
            resolution[GEOLOCATION_KEY] = PENDING
            resolution[DOMAIN_KEY] = [PENDING]

        # Finally, we can construct the actual monitor object and save it to the database.
        monitor = CertificateMonitor(owner=user,
                                     certificate_value=indicator,
                                     lookup_interval=interval,
                                     next_lookup=lookup_time,
                                     last_hosts=self.valid_hosts,
                                     resolutions=resolutions)
        monitor = self.update_monitor(monitor)
        try:
            monitor.save()
            LOGGER.info("New certificate monitor from %s for '%s' (initial hosts: %s)",
                        user,
                        indicator,
                        self.valid_hosts)
        except:
            LOGGER.exception("Error saving certificate monitor")
