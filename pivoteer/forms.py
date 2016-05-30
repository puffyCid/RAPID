from django import forms
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from core.utilities import discover_type
from .models import TaskTracker
from .tasks import *

from celery import group
from pivoteer.records import RecordSource, RecordType


class SubmissionForm(forms.Form):
    indicator = forms.CharField(label='Indicator Submission', widget=forms.TextInput())
    record_type = forms.CharField(widget=forms.TextInput())
    indicator_type = "unknown"

    def clean_indicator(self):
        indicator = self.cleaned_data.get('indicator').strip().lower()
        self.indicator_type = discover_type(indicator)

        return indicator

    def check_recent_tasks(self, desired_time):
        """
        Check if a recent task has been submitted for this indicator
        """

        indicator = self.cleaned_data['indicator']
        record_type = self.cleaned_data['record_type']

        try:
            recent_tasks = TaskTracker.objects.get(keyword=indicator,
                                                   type=record_type,
                                                   date__gte=desired_time)

        except MultipleObjectsReturned:
            recent_tasks = TaskTracker.objects.filter(keyword=indicator,
                                                      type=record_type,
                                                      date__gte=desired_time).latest('date')

        except ObjectDoesNotExist:
            recent_tasks = None

        return recent_tasks

    def create_new_task(self, current_time):
        """
        Create a task for a newly submitted indicator
        """
        indicator = self.cleaned_data['indicator']
        record_type = self.cleaned_data['record_type']

        if record_type == "Recent":

            if self.indicator_type == "domain":
                new_task = group([domain_whois.s(indicator),
                                  domain_hosts.s(indicator),
                                  domain_thc.s(indicator),
                                  certificate_cen.s(indicator)])()

            elif self.indicator_type == "ip":
                new_task = group([ip_whois.s(indicator),
                                  ip_hosts.s(indicator),
                                  ip_thc.s(indicator),
                                  certificate_cen.s(indicator)])()
            elif self.indicator_type == "other":
                new_task = group([certificate_cen.s(indicator)])()
            else:
                new_task = None

        elif record_type == "Historical":
            if self.indicator_type != "other":
                new_task = group([passive_hosts.s(indicator, RecordSource.VTO),
                                  # passive_hosts.s(indicator, RecordSource.PTO),
                                  passive_hosts.s(indicator, RecordSource.IID)])()
            else:
                new_task = None

        elif record_type == "Malware":
            if self.indicator_type != "other":
                new_task = group([malware_samples.s(indicator, RecordSource.TEX),
                                  malware_samples.s(indicator, RecordSource.VTO),
                                  totalhash_ip_domain_search.s(indicator),
                                  malwr_ip_domain_search.s(indicator)])()
            else:
                new_task = None

        elif record_type == "SafeBrowsing":
            if self.indicator_type != "other":
                new_task = group(google_safebrowsing.s(indicator))()
            else:
                new_task = None

        elif record_type == "Search":
            new_task = group([make_indicator_search_records.s(indicator, self.indicator_type)])()

        elif record_type == "External":
            new_task = group([empty_task.s(indicator)])()

        else:
            new_task = None

        if new_task:  # Enforce saving of group meta for tracking
            new_task.save()

            TaskTracker(group_id=new_task.id, keyword=indicator,
                        type=record_type, date=current_time).save()

        return new_task
