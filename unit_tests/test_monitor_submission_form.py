from monitors.forms import MonitorSubmission
from monitors.models import DomainMonitor
from profiles.models import Profile
from django.test import TestCase, RequestFactory
from django.core.urlresolvers import reverse


class TestMonitorSubmissionForm(TestCase):
    indicator = "twitter.com"
    ip_indicator = "199.59.150.7"

    # Basic validation of the form.
    def test_valid_monitor_submission_form(self):
        post = {}
        post['indicators'] = self.indicator
        post['indicator_type'] = "domain"
        form = MonitorSubmission(post)
        self.assertTrue(form.is_valid())

    # Store only one indicator.
    def test_clean_indicators_single(self):
        post = {}
        post['indicators'] = "TWITTER.COM"
        post['record_type'] = "domain"
        form = MonitorSubmission(post)

        # This creates the cleaned_data attribute on the form. This is how Django normalizes and stores form input.
        form.is_valid()

        # This method uses cleaned_data.get() to return the lower case indicator value.
        self.assertTrue("twitter.com" in form.valid_domains)
        self.assertFalse("TWITTER.COM" in form.valid_domains)

    # Store many indicators.
    def test_clean_indicators_multiple(self):
        post = {}
        post['indicators'] = "TWITTER.COM, ebay.com"
        post['record_type'] = "domain"
        form = MonitorSubmission(post)

        # This creates the cleaned_data attribute on the form. This is how Django normalizes and stores form input.
        form.is_valid()

        # This method uses cleaned_data.get() to return the lower case indicator value.
        self.assertTrue("twitter.com" in form.valid_domains)
        self.assertFalse("TWITTER.COM" in form.valid_domains)
        self.assertTrue("ebay.com" in form.valid_domains)

    def test_clean_indicators_ip(self):
        post = {}
        post['indicators'] = self.ip_indicator
        post['record_type'] = "ip"
        form = MonitorSubmission(post)

        # This creates the cleaned_data attribute on the form. This is how Django normalizes and stores form input.
        form.is_valid()

        # This method uses cleaned_data.get() to return the lower case indicator value.
        self.assertTrue(self.ip_indicator in form.valid_ips)

    # This method takes both IPs and domains, but stores them differently.
    def test_clean_indicators_distinguish_ip_from_domain(self):
        post = {}
        post['indicators'] = self.ip_indicator
        post['record_type'] = "ip"
        form = MonitorSubmission(post)

        # This creates the cleaned_data attribute on the form. This is how Django normalizes and stores form input.
        form.is_valid()

        # This method uses cleaned_data.get() to return the lower case indicator value.
        # The IP indicator should not be in the domain list.
        self.assertFalse(self.ip_indicator in form.valid_domains)
        self.assertTrue(self.ip_indicator in form.valid_ips)

    # This method takes both IPs and domains, but stores them differently.
    def test_clean_indicators_distinguish_domain_from_ip(self):
        post = {}
        post['indicators'] = self.indicator
        post['record_type'] = "domain"
        form = MonitorSubmission(post)

        # This creates the cleaned_data attribute on the form. This is how Django normalizes and stores form input.
        form.is_valid()

        # This method uses cleaned_data.get() to return the lower case indicator value.
        self.assertTrue(self.indicator in form.valid_domains)

        # The domain indicator should not be in the IP list.
        self.assertFalse(self.indicator in form.valid_ips)

    # This test isn't quite perfect because it relies on the retreival method  DomainMonitor.objects.filter().
    def test_save_submission_domain(self):
        factory = RequestFactory()
        url = reverse("add_indicators")
        request = factory.get(url)

        # Even though we have a request, we still need to submit a post with an indicator to save.
        post = {}
        post['indicators'] = self.indicator
        post['record_type'] = "domain"
        form = MonitorSubmission(post)

        # This creates the cleaned_data attribute on the form. This is how Django normalizes and stores form input.
        form.is_valid()

        # Attach a user to the request, save the record, and then retreive it.
        request.user = Profile.objects.create_user(email='test@test.com', password='test', is_admin=False)
        MonitorSubmission.save_submission(form, request)
        record = DomainMonitor.objects.filter(owner=request.user)
        self.assertIsNotNone(record)

    # This test isn't quite perfect because it relies on the retreival method  DomainMonitor.objects.filter().
    def test_save_submission_ip(self):
        factory = RequestFactory()
        url = reverse("add_indicators")
        request = factory.get(url)

        # Even though we have a request, we still need to submit a post with an indicator to save.
        post = {}
        post['indicators'] = self.ip_indicator
        post['record_type'] = "ip"
        form = MonitorSubmission(post)

        # This creates the cleaned_data attribute on the form. This is how Django normalizes and stores form input.
        form.is_valid()

        # Attach a user to the request, save the record, and then retreive it.
        request.user = Profile.objects.create_user(email='test@test.com', password='test', is_admin=False)
        MonitorSubmission.save_submission(form, request)
        record = DomainMonitor.objects.filter(owner=request.user)
        self.assertIsNotNone(record)
