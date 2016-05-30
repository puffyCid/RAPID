import csv
import json
import datetime
import logging

from django.http import HttpResponse
from django.shortcuts import render
from django.views.generic.base import View
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned

from .forms import SubmissionForm
from .models import IndicatorRecord, TaskTracker
from core.utilities import time_jump, discover_type
from core.lookups import geolocate_ip
from celery.result import GroupResult
from braces.views import LoginRequiredMixin
from pivoteer.records import RecordType
from pivoteer.writer.censys import CensysCsvWriter
from pivoteer.writer.hosts import HostCsvWriter
from pivoteer.writer.malware import MalwareCsvWriter
from pivoteer.writer.safebrowsing import SafeBrowsingCsvWriter
from pivoteer.writer.search import SearchCsvWriter
from pivoteer.writer.threatcrowd import ThreatCrowdCsvWriter
from pivoteer.writer.whois import WhoIsCsvWriter


LOGGER = logging.getLogger(__name__)


class PivotManager(LoginRequiredMixin, View):

    login_url = "login"
    redirect_unauthenticated_users = True

    template_name = 'pivoteer/pivoteer.html'

    def __init__(self):
        self.template_vars = {'SubmissionForm': SubmissionForm}

    def get(self, request):
        return render(request, self.template_name, self.template_vars)

    def post(self, request):

        task_tracking = {}
        submitted_form = SubmissionForm(request.POST)
        current_time = datetime.datetime.utcnow()
        desired_time = time_jump(hours=-24)

        if submitted_form.is_valid():
            recent_tasks = submitted_form.check_recent_tasks(desired_time)

            # If a recent task exists, use that one instead
            if recent_tasks:
                task_tracking['id'] = recent_tasks.group_id
            else:
                new_task = submitted_form.create_new_task(current_time)

                if new_task:
                    task_tracking['id'] = new_task.id
                else:
                    task_tracking["errors"] = "Unexpected Failure"

        else:  # pass form errors back to user from async request
            task_tracking["errors"] = submitted_form.errors

        json_response = json.dumps(task_tracking)
        return HttpResponse(json_response, content_type="application/json")


# Check if task completed
# https://zapier.com/blog/async-celery-example-why-and-how/
class CheckTask(LoginRequiredMixin, View):

    login_url = "login"
    redirect_unauthenticated_users = True

    template_name = "pivoteer/UnknownRecords.html"

    def __init__(self):
        self.template_vars = {}

    def post(self, request):

        task = request.POST['task_id']
        res = GroupResult.restore(task)

        if res and not res.ready():
            return HttpResponse(json.dumps({"status": "loading"}), content_type="application/json")

        # Task completion allows for origin information to be pulled
        try:
            task_origin = TaskTracker.objects.get(group_id=task)
            record_type = task_origin.type
            indicator = task_origin.keyword

        except MultipleObjectsReturned:
            task_origin = TaskTracker.objects.filter(group_id=task).latest('date')
            record_type = task_origin.type
            indicator = task_origin.keyword

        except ObjectDoesNotExist:
            record_type = None
            indicator = None

        # Pull data according to the record type
        if record_type == "Recent":

            self.template_name = "pivoteer/RecentRecords.html"

            # Current hosting records
            host_record = IndicatorRecord.objects.recent_hosts(indicator)

            # We must lookup the country for each IP address for use in the template.
            # We do this outside the task because we don't know the IP addresses until the task completes.
            host_records_complete = []
            for record in host_record:
                info = getattr(record, 'info')
                record.location = geolocate_ip(info['ip'])
                host_records_complete.append(record)

            self.template_vars["current_hosts"] = host_records_complete

            # Current WHOIS record
            whois_record = IndicatorRecord.objects.recent_whois(indicator)
            self.template_vars["current_whois"] = whois_record

            # Current ThreatCrowd record
            tc_info = IndicatorRecord.objects.recent_tc(indicator)
            self.template_vars["tc_info"] = tc_info

            cert_info = IndicatorRecord.objects.recent_cert(indicator)
            self.template_vars["cert_info"] = cert_info

        elif record_type == "Historical":

            self.template_name = "pivoteer/HistoricalRecords.html"

            # Historical hosting records
            host_records = IndicatorRecord.objects.historical_hosts(indicator, request)

            # We must lookup the country for each IP address for use in the template.
            # We do this outside the task because we don't know the IP addresses until the task completes.
            host_records_complete = []
            for record in host_records:
                info = getattr(record, 'info')
                record.location = geolocate_ip(info['ip'])
                host_records_complete.append(record)

            self.template_vars["hosting_records"] = host_records_complete

            # Historical WHOIS records
            whois_record = IndicatorRecord.objects.historical_whois(indicator)
            self.template_vars["historical_whois"] = whois_record

        elif record_type == "Malware":

            self.template_name = "pivoteer/MalwareRecords.html"

            malware_records = IndicatorRecord.objects.malware_records(indicator)
            self.template_vars["malware_records"] = malware_records

            self.template_vars["origin"] = indicator

        elif record_type == "SafeBrowsing":

            safebrowsing_records = IndicatorRecord.objects.safebrowsing_record(indicator)
            self.template_name = "pivoteer/Google.html"
            self.template_vars["records"] = safebrowsing_records
            self.template_vars["google_url"] = settings.GOOGLE_SAFEBROWSING_URL + indicator

            self.template_vars["origin"] = indicator

        elif record_type == "Search":
            self.template_name = "pivoteer/SearchRecords.html"
            search_records = IndicatorRecord.objects.get_search_records(indicator)
            self.template_vars["search_records"] = search_records
            
        elif record_type == "External":
            self.template_name = "pivoteer/ExternalRecords.html"
            self.template_vars['indicator'] = indicator
            self.template_vars['type'] = discover_type(indicator)

        return render(request, self.template_name, self.template_vars)


class ExportRecords(LoginRequiredMixin, View):
    # ---------------------------------------------------
    # HELP!  I want to add export support for a new type!
    # ---------------------------------------------------
    # Follow these simple steps:
    # 1. Create a pivoteer.writer.core.CsvWriter subclass that processes your record type.
    # 2. Update ExportRecords._get_csv_writer to return an instance of the writer you created in Step 1.
    # 3. Add a new method to ExportRecords that performs two steps:
    #     a. Retrieve IndicatorRecords (via a method on pivoteer/models/IndicatorManager)
    #     b. Call self._write_records with your record type, the indicator value, and the records obtained in Step A
    #         Note: If Step A returns a single record, you must wrap it in a list for Step B
    # 4. Update ExportRecords.get to call the method you created in Step 3.

    login_url = "login"
    redirect_unauthenticated_users = True

    def __init__(self):

        # Create the HttpResponse object with the appropriate CSV header.
        self.response = HttpResponse(content_type='text/csv')
        self.response['Content-Disposition'] = 'attachment; filename="exported_records.csv"'
        self.writer = csv.writer(self.response)

    def get(self, request):
        indicator = request.GET.get('indicator', '')
        filtering = request.GET.get('filter', '')
        LOGGER.debug("EXPORTING '%s' with filter: %s", indicator, filtering)

        if indicator and filtering == '':
            self.export_recent(indicator)
            self.line_separator()
            self.export_historical(indicator, request)
            self.line_separator()
            self.export_malware(indicator)
            self.line_separator()
            self.export_search_records(indicator)
            self.line_separator()
            self.export_safebrowsing_records(indicator)

        elif indicator and filtering == 'recent':
            self.export_recent(indicator)

        elif indicator and filtering == 'historical':
            self.export_historical(indicator, request)

        elif indicator and filtering == 'malware':
            self.export_malware(indicator)

        elif indicator and filtering == 'search':
            self.export_search_records(indicator)

        elif indicator and filtering == 'safebrowsing':
            self.export_safebrowsing_records(indicator)

        return self.response

    def export_safebrowsing_records(self, indicator):
        """
        Export recent 'SB' (SafeBrowsing) indicator records to CSV.

        :param indicator: The indicator whose records are to be exported
        :return: This method returns no values
        """
        safebrowsing_records = IndicatorRecord.objects.safebrowsing_record(indicator)
        self._write_records(RecordType.SB, indicator, safebrowsing_records)

    def export_recent_hosts(self, indicator):
        """
        Export recent 'HR' (Host Record) indicator records to CSV.

        This method is called as part of 'export_recent.'

        :param indicator: The indicator to be exported
        :return: This method returns no values
        """
        hosts = IndicatorRecord.objects.recent_hosts(indicator)
        self._write_records(RecordType.HR, indicator, hosts)

    def export_recent_whois(self, indicator):
        """
        Export recent 'WR' (Whois Record) indicator records to CSV.

        This method is called as part of 'export_recent'

        :param indicator: The indicator to be exported
        :return: This method returns no values
        """
        whois = IndicatorRecord.objects.recent_whois(indicator)
        self._write_records(RecordType.WR, indicator, [whois])

    def export_recent_threatcrowd(self, indicator):
        """
        Export the most recent 'TR' (ThreatCrowd Record) indicator records to CSV.

        This method is called as part of 'export_recent'

        :param indicator: The indicator to be exported
        :return: This method returns no values
        """
        tc_info = IndicatorRecord.objects.recent_tc(indicator)
        self._write_records(RecordType.TR, indicator, [tc_info])

    def export_recent_certificates(self, indicator):
        """
        Export recent 'CE' (Censys Record) indicator records in CSV format.

        This method is called as part of 'export_recent'

        :param indicator: The indicator to be exported
        :return: This method returns no values
        """
        latest = IndicatorRecord.objects.recent_cert(indicator)
        self._write_records(RecordType.CE, indicator, [latest])

    def export_recent(self, indicator):
        """
        Export all data from the "Recent Activity" tab to CSV.

        This method calls the various 'export_recent_*' methods (with a call to 'line_separator' between each) to
        perform the actual work of exporting to CSV.

        :param indicator: The indicator to be exported
        :return: This method returns no values
        """
        self.export_recent_hosts(indicator)
        self.line_separator()
        self.export_recent_whois(indicator)
        self.line_separator()
        self.export_recent_threatcrowd(indicator)
        self.line_separator()
        self.export_recent_certificates(indicator)

    def export_historical_hosts(self, indicator, request):
        """
        Export historical Host Records (IndicatorRecords with record type "HR").

        :param indicator: The indicator whose historical records are to be exported
        :param request: The request being processed
        :return: This method returns no values
        """
        hosts = IndicatorRecord.objects.historical_hosts(indicator, request)
        self._write_records(RecordType.HR, indicator, hosts)

    def export_historical_whois(self, indicator):
        """
        Export historical Who Is Records (IndicatorRecords with record type "WR")

        :param indicator: The indicator whose historical records are to be exported
        :return: This method returns no values
        """
        whois = IndicatorRecord.objects.historical_whois(indicator)
        self._write_records(RecordType.WR, indicator, whois)

    def export_historical(self, indicator, request):
        """
        Export all data from the "Historical Activity" tab to CSV.

        :param indicator: The indicator whose historical activity is to be exported
        :param request: The request being processed
        :return: This method returns no values
        """
        self.export_historical_hosts(indicator, request)
        self.line_separator()
        self.export_historical_whois(indicator)

    def export_malware(self, indicator):
        """
        Export all Malware Records (IndicatorRecords with a record type of "MR") for an indicator to CSV.

        :param indicator: The indicator whose malware records are to be exported
        :return: This method returns no values
        """
        malware = IndicatorRecord.objects.malware_records(indicator)
        self._write_records(RecordType.MR, indicator, malware)

    def export_search_records(self, indicator):
        """
        Export IndicatorRecords with a record type of 'SR' (Search Record).

        This will produce a CSV file containing three columns:
            title: The title of the search result
            url: The URL of the search result
            content: A brief summary of the content of the result

        :param indicator: The indicator whose search results are to be exported
        :return: This method does not return any values
        """
        records = IndicatorRecord.objects.get_search_records(indicator)
        self._write_records(RecordType.SR, indicator, records)

    def _write_records(self, record_type, indicator, records):
        """
        Write a list of records of a given type.

        :param record_type: The record type (which should be one of the values from IndicatoRecord.record_choices)
        :param indicator: The indicator value
        :param records: The records to be written
        :return: This method returns no values
        """
        record_writer = self._get_csv_writer(record_type)
        LOGGER.debug("Writing %d record(s) of type %s (%s) for indicator '%s' using writer type %s",
                     len(records),
                     record_type.name,
                     record_type.title,
                     indicator,
                     type(record_writer).__name__)
        if records is None or 0 == len(records):
            LOGGER.warn("No '%s' records to write for indicator '%s'", record_type, indicator)
        else:
            record_writer.write(indicator, records)

    def _get_csv_writer(self, record_type):
        """
        Get a CsvWriter for the given record type

        :param record_type: The record type.  This should match one of the values defined in
        IndicatorRecord.record_choices.
        :return: An instantiated CsvWriter
        """
        if RecordType.SR is record_type:
            return SearchCsvWriter(self.writer)
        elif RecordType.HR is record_type:
            return HostCsvWriter(self.writer)
        elif RecordType.WR is record_type:
            return WhoIsCsvWriter(self.writer)
        elif RecordType.TR is record_type:
            return ThreatCrowdCsvWriter(self.writer)
        elif RecordType.CE is record_type:
            return CensysCsvWriter(self.writer)
        elif RecordType.SB is record_type:
            return SafeBrowsingCsvWriter(self.writer)
        elif RecordType.MR is record_type:
            return MalwareCsvWriter(self.writer)
        else:
            msg = "No writer for record type: " + record_type
            LOGGER.error(msg)
            raise RuntimeError(msg)

    def line_separator(self):
        """
        Add a blank line in the CSV output.

        :return: This method does not return any values
        """
        self.writer.writerow([])
