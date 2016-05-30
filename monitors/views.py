import csv

import datetime
import django.template
import logging
from django.views.generic import TemplateView, ListView, FormView, View
from django.shortcuts import render
from django.http import HttpResponse
from django.shortcuts import redirect
from django.core.urlresolvers import reverse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model

from core.utilities import discover_type

from .models import CertificateMonitor, DomainMonitor, IpMonitor, IndicatorAlert, IndicatorTag
from .forms import MonitorSubmission, CertificateSubmission
from .tasks import GEOLOCATION_KEY, DOMAIN_KEY, COUNTRY_KEY

from braces.views import LoginRequiredMixin

LOGGER = logging.getLogger(__name__)
"""The logger for this module"""

User = get_user_model()


__GENERIC_EXPORT_HEADER = ["Indicator", "Last Lookup", "Last Hosts", "Tags"]
"""The header row used for "generic" monitor exports"""


# This line creates a new Django template filter for accessing a dictionary key.  Assuming that you have a variable
# 'dict' within a template and want to access the value stored under 'foo,' you would use it like this:
#     {{ dict|key:"foo" }}
django.template.Library().filter("key", lambda d, key: d[key])


class MonitorDashboard(LoginRequiredMixin, TemplateView):

    login_url = "login"
    redirect_unauthenticated_users = True

    template_name = "monitors/dashboard.html"


class DomainList(LoginRequiredMixin, ListView):

    login_url = "login"
    redirect_unauthenticated_users = True

    context_object_name = 'monitored_domains'
    template_name = 'monitors/domain.html'

    def get_queryset(self):
        domains = DomainMonitor.objects.filter(owner=self.request.user)
        return domains


class IpList(LoginRequiredMixin, ListView):

    login_url = "login"
    redirect_unauthenticated_users = True

    context_object_name = 'monitored_ips'
    template_name = 'monitors/ip.html'

    def get_queryset(self):
        ips = IpMonitor.objects.filter(owner=self.request.user)
        return ips


class CertificateList(LoginRequiredMixin, ListView):
    """
    A list view of certificate monitors.

    Within the Django HTML template (defined in monitors/certificate.html), the query set of CertificateMonitor objects
    will be available as "monitored_certificates."

    Login is required in order to use this view.
    """
    login_url = "login"
    redirect_unauthenticated_users = True
    context_object_name = 'monitored_certificates'
    template_name = 'monitors/certificate.html'

    def get_queryset(self):
        return CertificateMonitor.objects.filter(owner=self.request.user)


class AlertList(LoginRequiredMixin, ListView):
    login_url = "login"
    redirect_unauthenticated_users = True

    context_object_name = 'alerts'
    template_name = 'monitors/alerts.html'

    def get_queryset(self):
        time_frame = datetime.datetime.utcnow() + datetime.timedelta(days=-7)
        alerts = IndicatorAlert.objects.filter(recipient=self.request.user,
                                               created__gte=time_frame)
        return alerts


class AddIndicator(LoginRequiredMixin, FormView):
    login_url = "login"
    redirect_unauthenticated_users = True

    form_class = MonitorSubmission
    template_name = "monitors/add.html"

    msg_success = "Indicator(s) added for monitoring"
    msg_failure = "No indicator(s) added for monitoring"

    def get_success_url(self):
        return reverse('monitor_dashboard')

    def form_valid(self, form):
        form.save_submission(self.request)
        messages.add_message(self.request, messages.SUCCESS, self.msg_success)
        return super(AddIndicator, self).form_valid(form)

    def form_invalid(self, form):
        for elist in form.errors.as_data().values():
            for e in elist:
                messages.add_message(self.request, messages.ERROR, e.message)
        messages.add_message(self.request, messages.WARNING, self.msg_failure)
        return redirect('monitor_dashboard')


class AddCertificate(AddIndicator):
    """
    A view for adding a new certificate monitor
    """
    form_class = CertificateSubmission
    template_name = "monitors/add_certificate.html"


class DeleteIndicator(LoginRequiredMixin, View):

    login_url = "login"
    redirect_unauthenticated_users = True
    template_name = "monitors/remove.html"

    msg_success = "Selected indicators removed from monitoring"

    def post(self, request):

        for indicator in request.POST.getlist('choices'):

            indicator_type = discover_type(indicator)

            if indicator_type == "domain":

                try:
                    DomainMonitor.objects.get(domain_name=indicator,
                                              owner=request.user).delete()
                except:
                    LOGGER.exception("Error deleting domain monitor for value: %s", indicator)

            if indicator_type == "ip":

                try:
                    IpMonitor.objects.get(ip_address=indicator,
                                          owner=request.user).delete()
                except:
                    LOGGER.exception("Error deleting IP monitor for value: %s", indicator)

            if indicator_type == "other":
                try:
                    CertificateMonitor.objects.get(certificate_value=indicator,
                                                   owner=request.user).delete()
                except:
                    LOGGER.exception("Error deleting certificate monitor for value: %s", indicator)

        messages.add_message(request, messages.SUCCESS, self.msg_success)
        return redirect('monitor_dashboard')

    def get(self, request):
        return render(request, self.template_name, {})


class TagIndicator(LoginRequiredMixin, View):

    login_url = "login"
    redirect_unauthenticated_users = True
    template_name = "monitors/tagging.html"

    msg_success = "Selected indicators tagged"

    def post(self, request):

        tags = IndicatorTag.objects.filter(tag__in=request.POST.getlist('tags'),
                                           owner=request.user)

        if tags:

            for indicator in request.POST.getlist('choices'):

                indicator_type = discover_type(indicator)
                LOGGER.debug("Applying %d tag(s) to %s indicator: %s", len(tags), indicator_type, indicator)

                if indicator_type == "domain":

                    try:
                        monitor = DomainMonitor.objects.get(domain_name=indicator,
                                                            owner=request.user)
                    except:
                        LOGGER.exception("Error retrieving domain indicator '%s'", indicator)

                    else:
                        for tag in tags:
                            LOGGER.debug("Adding tag '%s' to domain value: %s", tag, indicator)
                            monitor.tags.add(tag)

                if indicator_type == "ip":

                    try:
                        monitor = IpMonitor.objects.get(ip_address=indicator,
                                                        owner=request.user)
                    except:
                        LOGGER.exception("Error retrieving IP indicator '%s'", indicator)

                    else:
                        for tag in tags:
                            LOGGER.debug("Adding tag '%s' to IP value: %s", tag, indicator)
                            monitor.tags.add(tag)

                if indicator_type == "other":
                    try:
                        monitor = CertificateMonitor.objects.get(certificate_value=indicator,
                                                                 owner=request.user)
                    except:
                        LOGGER.exception("Error retrieving certificate indicator '%s'", indicator)
                    else:
                        for tag in tags:
                            LOGGER.debug("Adding tag '%s' to certificate value: %s", tag, indicator)
                            monitor.tags.add(tag)

        messages.add_message(request, messages.SUCCESS, self.msg_success)
        return redirect('monitor_dashboard')

    def get(self, request):

        temp_context = dict()
        temp_context['tags'] = IndicatorTag.objects.filter(owner=request.user)
        return render(request, self.template_name, temp_context)


class UntagIndicator(LoginRequiredMixin, View):

    login_url = "login"
    redirect_unauthenticated_users = True
    template_name = "monitors/untag.html"

    msg_success = "Tags removed from selected indicators"

    def post(self, request):

        for indicator in request.POST.getlist('choices'):

            indicator_type = discover_type(indicator)

            if indicator_type == "domain":

                try:
                    monitor = DomainMonitor.objects.get(domain_name=indicator,
                                                        owner=request.user)
                except:
                    pass

                else:
                    monitor.tags.clear()

            if indicator_type == "ip":

                try:
                    monitor = IpMonitor.objects.get(ip_address=indicator,
                                                    owner=request.user)
                except:
                    pass

                else:
                    monitor.tags.clear()

            if indicator_type == "other":
                try:
                    monitor = CertificateMonitor.objects.get(certificate_value=indicator,
                                                             owner=request.user)
                except:
                    pass
                else:
                    monitor.tags.clear()

        messages.add_message(request, messages.SUCCESS, self.msg_success)
        return redirect('monitor_dashboard')

    def get(self, request):
        return render(request, self.template_name, {})


def _generate_generic_records(indicator, monitor):
    """
    Generate "generic" records for an Indicator Monitor.

    A "record" corresponds to a single line in a CSV file.  This function is a generator, and may produce multiple
    records.  Records produced by this function correspond to the following columns (in order):
        - Indicator: The indicator value being monitored
        - Last Lookup: The last time the monitor was executed
        - Last Hosts: The hosts to which the indicator most recently resolved
        - Tags: The tags associated with this monitor by its owner

    (Records produced by this function are intended for use with a header row corresponding to __GENERIC_EXPORT_HEADER.)

    :param indicator:
    :param monitor:
    :return:
    """
    tags = [item["tag"] for item in monitor.tags.all().values("tag")]
    yield [indicator,
           monitor.modified,
           monitor.last_hosts,
           tags]


def _generate_simple_certificate_records(monitor):
    """
    Generate simple CSV records for a Certificate Monitor.

    A "record" corresponds to a single line in a CSV file.  This function is a generator, and may produce multiple
    records.  Records produced by this function correspond to the following columns (in order):
        - Indicator: The certificate value/fragment being monitored
        - Last Lookup: The last time the indicator was resolved
        - IP: An IP address to which the indicator has been resolved
        - Country: The country to which the IP address has been geo-located
        - Domain: The domain hosts on the IP
        - Tags: Any user tags associated with the monitor

    This version of the record generate combines all information for a monitor into a single record.  This results in
    data similar to the following example (Last Lookup and Tag columns omitted for brevity):

        Certificate                 IP                            Country                         Domain
         CN=abc.def     1.2.3.4, 2.3.4.5, 9.8.7.6     United States, Canada, Yemen     foo.com, bar.com, baz.com

    While this format is brief and contains only one line per individual monitor, it nevertheless potentially valuable
    information (namely, which countries and domains are associated with which resolved IPs).  Therefore, this format is
    NOT recommended.   Please refer to the following methods for alternative formats:
        - _generate_summary_certificate_records
        - _generate_detail_certificate_records (recommended)

    :param monitor: The CertificateMonitor instance being exported
    :return: The CSV record
    """
    tags = [item["tag"] for item in monitor.tags.all().values("tag")]
    ips = list()
    countries = list()
    domains = list()
    for ip, resolution in monitor.resolutions.items():
        geolocation = resolution[GEOLOCATION_KEY]
        country = geolocation[COUNTRY_KEY]
        domain_list = resolution[DOMAIN_KEY]
        ips.append(ip)
        countries.append(country)
        domains.extend(domain_list)
    yield [monitor.certificate_value,
           monitor.modified,
           ips,
           countries,
           domains,
           tags]


def _generate_summary_certificate_records(monitor):
    """
    Generate summary CSV records for a Certificate Monitor.

    A "record" corresponds to a single line in a CSV file.  This function is a generator, and may produce multiple
    records.  Records produced by this function correspond to the following columns (in order):
        - Indicator: The certificate value/fragment being monitored
        - Last Lookup: The last time the indicator was resolved
        - IP: An IP address to which the indicator has been resolved
        - Country: The country to which the IP address has been geo-located
        - Domain: The domain hosts on the IP
        - Tags: Any user tags associated with the monitor

    This version of the record generate creates a discrete record for each resolved IP .   This results in data similar
    to the following example (Last Lookup and Tag columns omitted for brevity):

        Certificate       IP        Country             Domain
         CN=abc.def     1.2.3.4   United States     foo.com, bar.com
         CN=abc.def     2.3.4.5      Canada             baz.com
         CN=abc.def     9.8.7.6      Yemen

    Please refer to the following methods for alternative formats:
        - _generate_simple_certificate_records (NOT recommended)
        - _generate_detail_certificate_records (recommended)

    :param monitor: The CertificateMonitor instance being exported
    :return: The CSV record
    """
    tags = [item["tag"] for item in monitor.tags.all().values("tag")]
    for ip, resolution in monitor.resolutions.items():
        geolocation = resolution[GEOLOCATION_KEY]
        country = geolocation[COUNTRY_KEY]
        domain_list = resolution[DOMAIN_KEY]
        yield [monitor.certificate_value,
               monitor.modified,
               ip,
               country,
               domain_list,
               tags]


def _generate_detail_certificate_records(monitor):
    """
    Generate detailed CSV records for a Certificate Monitor.

    A "record" corresponds to a single line in a CSV file.  This function is a generator, and may produce multiple
    records.  Records produced by this function correspond to the following columns (in order):
        - Indicator: The certificate value/fragment being monitored
        - Last Lookup: The last time the indicator was resolved
        - IP: An IP address to which the indicator has been resolved
        - Country: The country to which the IP address has been geo-located
        - Domain: The domain hosts on the IP
        - Tags: Any user tags associated with the monitor

    This version of the record generate creates a discrete record for each resolved IP AND domain.   This results in
    data similar to the following example (Last Lookup and Tag columns omitted for brevity):

        Certificate       IP        Country             Domain
         CN=abc.def     1.2.3.4   United States         foo.com
         CN=abc.def     1.2.3.4   United States         bar.com
         CN=abc.def     2.3.4.5      Canada             baz.com
         CN=abc.def     9.8.7.6      Yemen

    This format is particularly useful for leveraging spreadsheet capabilities, and is the recommended format.  Please
    refer to the following methods for alternative formats:
        - _generate_simple_certificate_records (NOT recommended)
        - _generate_summary_certificate_records

    :param monitor: The CertificateMonitor instance being exported
    :return: The CSV record
    """
    tags = [item["tag"] for item in monitor.tags.all().values("tag")]
    for ip, resolution in monitor.resolutions.items():
        geolocation = resolution[GEOLOCATION_KEY]
        country = geolocation[COUNTRY_KEY]
        domain_list = resolution[DOMAIN_KEY]
        if domain_list is None or len(domain_list) == 0:
            yield [monitor.certificate_value,
                   monitor.modified,
                   ip,
                   country,
                   "",
                   tags]
        else:
            for domain in domain_list:
                yield [monitor.certificate_value,
                       monitor.modified,
                       ip,
                       country,
                       domain,
                       tags]


def _export_ip_monitors(request, response):
    """
    Export IP monitors.

    This function is only used when writing ONLY IP monitors.  See '_export_all_monitors' for exporting IP monitors
    along with monitors of other types.

    Records in this CSV file include the following fields:
        - Indicator: The indicator value being monitored
        - Last Lookup: The last time the monitor was executed
        - Last Hosts: The hosts to which the indicator most recently resolved
        - Tags: The tags associated with this monitor by its owner

    :param request: The request being processed
    :param response: The HttpResponse instance for writing a response
    :return: This function returns no values
    """
    response['Content-Disposition'] = 'attachment; filename="monitored_ips.csv"'
    monitors = IpMonitor.objects.filter(owner=request.user)
    writer = csv.writer(response)
    writer.writerow(__GENERIC_EXPORT_HEADER)
    for monitor in monitors:
        for record in _generate_generic_records(monitor.ip_address, monitor):
            writer.writerow(record)


def _export_domain_monitors(request, response):
    """
    Export domain monitors.

    This function is only used when writing ONLY domain monitors.  See '_export_all_monitors' for exporting domain
    monitors along with monitors of other types.

    Records in this CSV file include the following fields:
        - Indicator: The indicator value being monitored
        - Last Lookup: The last time the monitor was executed
        - Last Hosts: The hosts to which the indicator most recently resolved
        - Tags: The tags associated with this monitor by its owner

    :param request: The request being processed
    :param response: The HttpResponse instance for writing a response
    :return: This function returns no values
    """
    response['Content-Disposition'] = 'attachment; filename="monitored_domains.csv"'
    monitors = DomainMonitor.objects.filter(owner=request.user)
    writer = csv.writer(response)
    writer.writerow(__GENERIC_EXPORT_HEADER)
    for monitor in monitors:
        for record in _generate_generic_records(monitor.domain_name, monitor):
            writer.writerow(record)


def _export_certificate_monitors(request, response):
    """
    Export certificate monitors.

    This function is only used when writing ONLY certificate monitors.  See '_export_all_monitors' for exporting
    certificate monitors along with monitors of other types.

    Certificate monitors differ from IP and Domain monitors in that they have "multiple resolution."  A certificate
    fragment is first resolved to an IP address.  That IP address is then geo-located and resolved to any domain names
    hosted upon it.  As a result, exporting certificates includes different fields:
        - Indicator: The certificate value/fragment being monitored
        - Last Lookup: The last time the monitor was executed
        - IP: The IP address to which the certificate resolved
        - Country: The geo-location of the resolved IP
        - Domain: The domain names hosted on the resolved IP
        - Tags: The tags associated with this monitor by its owner

    :param request: The request being processed
    :param response: The HttpResponse instance for writing a response
    :return: This function returns no values
    """
    response['Content-Disposition'] = 'attachment; filename="monitored_certificates.csv"'
    monitors = CertificateMonitor.objects.filter(owner=request.user)
    writer = csv.writer(response)
    header = ["Indicator", "Last Lookup", "IP", "Country", "Domain", "Tags"]
    writer.writerow(header)
    # Important Note: There are several formats we debated using for exporting certificates.  We have deliberately left
    # implementations for all three formats in the functions above.  However, only one implementation is actually in use
    # within this function (which is what actually does the export).  Each format is encapsulated in one of the
    # "_generate_*_certificate_records" generator functions, above.  To use a different format, simply replace the
    # function call in this function with the function name for the format you want.  Please refer to the documentation
    # for each of these functions for a more detailed description of the formats with examples.
    #     1. Option A (_generate_simple_certificate_records): Each monitor is on its own line, combining all IPs, all
    #        countries, and all domains.   This format is not recommended.
    #     2. Option B (_generate_summary_certificate_records): Each resolved IP address appears on a separate line, but
    #        the domains for each IP are combined per line.
    #     3. [RECOMMENDED] Option C (_generate_detail_certificate_records): Each resolved domain of each resolved IP
    #        address is on a separate line.   This format will provide the most flexibility within a spreadsheet
    #        application such as Microsoft Excel.
    for monitor in monitors:
        for record in _generate_detail_certificate_records(monitor):
            writer.writerow(record)


def _export_all_monitors(request, response):
    """
    Export all indicator monitors.

    This will use the generic format, which includes the following fields for each line:
        - Indicator: The indicator value being monitored
        - Last Lookup: The last time the monitor was executed
        - Last Hosts: The hosts to which the indicator most recently resolved
        - Tags: The tags associated with this monitor by its owner

    :param request: The request being processed
    :param response: The HttpResponse instance for writing a response
    :return: This function returns no values
    """
    response['Content-Disposition'] = 'attachment; filename="monitored_indicators.csv"'
    writer = csv.writer(response)
    writer.writerow(__GENERIC_EXPORT_HEADER)
    for monitor in DomainMonitor.objects.filter(owner=request.user):
        for record in _generate_generic_records(monitor.domain_name, monitor):
            writer.writerow(record)
    for monitor in IpMonitor.objects.filter(owner=request.user):
        for record in _generate_generic_records(monitor.ip_address, monitor):
            writer.writerow(record)
    for monitor in CertificateMonitor.objects.filter(owner=request.user):
        for record in _generate_generic_records(monitor.certificate_value, monitor):
            writer.writerow(record)


@login_required(login_url='login')
def export_indicators(request):
    """
    Export indicator monitors for a requesting user.

    The request may contain a filtering string under the 'filter' keyword.  The following filtering values are
    supported:
        - domain: Export only domain monitors
        - ip: Export only IP monitors
        - certificate: Export only certificate monitors

    If there is no filtering, or filtering does not match one of the above values, ALL indicator monitors owned by the
    requesting user will be exported in a generic format.

    :param request: The request being processed
    :return: The HttpResponse instance
    """
    filtering = request.GET.get('filter', '')
    response = HttpResponse(content_type='text/csv')
    if filtering == "domain":
        _export_domain_monitors(request, response)
    elif filtering == "ip":
        _export_ip_monitors(request, response)
    elif filtering == "certificate":
        _export_certificate_monitors(request, response)
    else:
        if filtering is not None and len(filtering) > 0:
            LOGGER.warn("Ignoring unknown filtering string: %s", filtering)
        _export_all_monitors(request, response)
    return response


class AddTag(LoginRequiredMixin, View):

    login_url = "login"
    redirect_unauthenticated_users = True

    template_name = "monitors/tagging.html"

    def post(self, request):

        new_tags = request.POST.getlist('new_tag')

        for new_tag in new_tags:

            if new_tag:

                try:
                    new_tag = IndicatorTag(tag=new_tag, owner=request.user)
                    new_tag.save()
                except:
                    pass

        temp_context = dict()
        temp_context['tags'] = IndicatorTag.objects.filter(owner=request.user)

        return render(request, self.template_name, temp_context)


class DeleteTags(LoginRequiredMixin, View):

    login_url = "login"
    redirect_unauthenticated_users = True

    msg_success = "Selected tags deleted"

    def post(self, request):

        IndicatorTag.objects.filter(tag__in=request.POST.getlist('tags'),
                                    owner=request.user).delete()

        messages.add_message(request, messages.SUCCESS, self.msg_success)
        return redirect('monitor_dashboard')