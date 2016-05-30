from monitors.views import MonitorDashboard, AddIndicator, DomainMonitor, DeleteIndicator
from profiles.models import Profile
from django.test import TestCase, RequestFactory
from django.core.urlresolvers import reverse
from django.contrib.auth.models import AnonymousUser
from django.http import HttpResponseRedirect
import datetime


class TestMonitorDashboard(TestCase):
    indicator = "twitter.com"
    ip_indicator = "199.59.150.7"

    def setUp(self):
        self.factory = RequestFactory()
        self.url = reverse("monitor_dashboard")
        self.request = self.factory.get(self.url)

    # We test each role, authenticated users first.
    def test_monitor_dashboard_auth_get(self):

        # Spin up a user and run a request through the view.
        self.request.user = Profile.objects.create_user(email='test@test.com', password='test', is_admin=False)
        response = MonitorDashboard.as_view()(self.request)

        # This view returns a template response, so we must manually render.
        response = response.render()
        self.assertEqual(response.status_code, 200)
        self.assertTrue("DomainPanel" in response.content.decode("utf-8"))
        self.assertTrue("IpPanel" in response.content.decode("utf-8"))
        self.assertTrue("AlertPanel" in response.content.decode("utf-8"))

    # Admin users.
    def test_monitor_dashboard_admin_get(self):
        # Spin up a user and run a request through the view.
        self.request.user = Profile.objects.create_user(email='test@test.com', password='test', is_admin=True)
        response = MonitorDashboard.as_view()(self.request)

        # This view returns a template response, so we must manually render.
        response = response.render()
        self.assertEqual(response.status_code, 200)
        self.assertTrue("DomainPanel" in response.content.decode("utf-8"))
        self.assertTrue("IpPanel" in response.content.decode("utf-8"))
        self.assertTrue("AlertPanel" in response.content.decode("utf-8"))

    # Staff users.
    def test_monitor_dashboard_staff_get(self):
        # Spin up a user and run a request through the view.
        self.request.user = Profile.objects.create_user(email='test@test.com', password='test', is_admin=False, is_staff=True)
        response = MonitorDashboard.as_view()(self.request)

        # This view returns a template response, so we must manually render.
        response = response.render()
        self.assertEqual(response.status_code, 200)
        self.assertTrue("DomainPanel" in response.content.decode("utf-8"))
        self.assertTrue("IpPanel" in response.content.decode("utf-8"))
        self.assertTrue("AlertPanel" in response.content.decode("utf-8"))

    # Anon users should be restricted.
    def test_monitor_dashboard_anon_get(self):
        # Spin up a user and run a request through the view.
        self.request.user = AnonymousUser()
        response = MonitorDashboard.as_view()(self.request)

        # Anon users will be redirected, so we don't render().
        self.assertNotEqual(response.status_code, 200)
        self.assertTrue("DomainPanel" not in response.content.decode("utf-8"))
        self.assertTrue("IpPanel" not in response.content.decode("utf-8"))
        self.assertTrue("AlertPanel" not in response.content.decode("utf-8"))


class TestAddIndicator(TestCase):
    indicator = "twitter.com"
    ip_indicator = "199.59.150.7"

    def setUp(self):
        self.factory = RequestFactory()
        self.url = reverse("add_indicators")
        self.request = self.factory.get(self.url)

    # We test each role, authenticated users first.
    def test_add_indicator_auth(self):
        # Spin up a user and run a request through the view.
        self.request.user = Profile.objects.create_user(email='test@test.com', password='test', is_admin=False)
        response = AddIndicator.as_view()(self.request)

        # This view returns a template response, so we must manually render.
        response = response.render()
        self.assertEqual(response.status_code, 200)
        self.assertTrue("New monitor submissions" in response.content.decode("utf-8"))

    def test_add_indicator_admin(self):
        # Spin up a user and run a request through the view.
        self.request.user = Profile.objects.create_user(email='test@test.com', password='test', is_admin=True)
        response = AddIndicator.as_view()(self.request)
        response = response.render()
        self.assertEqual(response.status_code, 200)
        self.assertTrue("New monitor submissions" in response.content.decode("utf-8"))

        # To test methods in the view, we must not use .as_view() because it will return a response.
        # What we really need is just an instance of the class.
        view = AddIndicator()
        url = view.get_success_url()
        self.assertEqual(url, "/monitors/")

    def test_add_indicator_auth(self):
        # Spin up a user and run a request through the view.
        self.request.user = Profile.objects.create_user(email='test@test.com', password='test', is_admin=False)
        response = AddIndicator.as_view()(self.request)

        # This view returns a template response, so we must manually render.
        response = response.render()
        self.assertEqual(response.status_code, 200)
        self.assertTrue("New monitor submissions" in response.content.decode("utf-8"))

        # To test methods in the view, we must not use .as_view() because it will return a response.
        # What we really need is just an instance of the class.
        view = AddIndicator()
        url = view.get_success_url()
        self.assertEqual(url, "/monitors/")

    def test_add_indicator_staff(self):
        # Spin up a user and run a request through the view.
        self.request.user = Profile.objects.create_user(email='test@test.com', password='test', is_staff=True)
        response = AddIndicator.as_view()(self.request)

        # This view returns a template response, so we must manually render.
        response = response.render()
        self.assertEqual(response.status_code, 200)
        self.assertTrue("New monitor submissions" in response.content.decode("utf-8"))

        # To test methods in the view, we must not use .as_view() because it will return a response.
        # What we really need is just an instance of the class.
        view = AddIndicator()
        url = view.get_success_url()
        self.assertEqual(url, "/monitors/")

    # Anon users should be redirected to login page.
    def test_add_indicator_anon(self):
        # Spin up a user and run a request through the view.
        self.request.user = AnonymousUser()
        response = AddIndicator.as_view()(self.request)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(isinstance(response, HttpResponseRedirect))
        # Ensure we are redirecting to the correct URL.
        self.assertTrue("/profile/login/?next=/monitors/add_indicators" in response._headers['location'],)

        # To test methods in the view, we must not use .as_view() because it will return a response.
        # What we really need is just an instance of the class.
        view = AddIndicator()
        url = view.get_success_url()
        self.assertEqual(url, "/monitors/")

class TestRemoveIndicator(TestCase):

    indicator = "twitter.com"
    ip_indicator = "199.59.150.7"

    def setUp(self):
        self.factory = RequestFactory()
        self.url = reverse("delete_indicators")
        self.request = self.factory.get(self.url)

    def test_remove_indicator_anon(self):
        # Spin up a user and run a request through the view.
        self.request.user = AnonymousUser()
        response = DeleteIndicator.as_view()(self.request)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(isinstance(response, HttpResponseRedirect))
        # Ensure we are redirecting to the correct URL.
        self.assertTrue("/profile/login/?next=/monitors/delete_indicators" in response._headers['location'])

    def test_remove_indicator_admin(self):
        self.request.user = Profile.objects.create_user(email='rapid@rapid.com', password='test', is_admin=True)
        monitor = DomainMonitor(owner=self.request.user,
                                domain_name=self.indicator,
                                lookup_interval=24,
                                next_lookup= datetime.datetime.utcnow())
        monitor.save()

        response = DeleteIndicator.as_view()(self.request)

        self.assertEqual(response.status_code, 200)
        self.assertFalse(isinstance(response, HttpResponseRedirect))

        # There is a confirmation page.
        self.assertTrue("Confirm Monitor Deletion" in response.content.decode("utf-8"))

    def test_remove_indicator_auth(self):
        self.request.user = Profile.objects.create_user(email='rapid@rapid.com', password='test', is_admin=False)
        monitor = DomainMonitor(owner=self.request.user,
                                domain_name=self.indicator,
                                lookup_interval=24,
                                next_lookup=datetime.datetime.utcnow())
        monitor.save()

        response = DeleteIndicator.as_view()(self.request)

        self.assertEqual(response.status_code, 200)
        self.assertFalse(isinstance(response, HttpResponseRedirect))

        # There is a confirmation page.
        self.assertTrue("Confirm Monitor Deletion" in response.content.decode("utf-8"))

    def test_remove_indicator_staff(self):
        self.request.user = Profile.objects.create_user(email='rapid@rapid.com', password='test', is_staff=True)
        monitor = DomainMonitor(owner=self.request.user,
                                domain_name=self.indicator,
                                lookup_interval=24,
                                next_lookup=datetime.datetime.utcnow())
        monitor.save()

        response = DeleteIndicator.as_view()(self.request)

        self.assertEqual(response.status_code, 200)
        self.assertFalse(isinstance(response, HttpResponseRedirect))

        # There is a confirmation page.
        self.assertTrue("Confirm Monitor Deletion" in response.content.decode("utf-8"))
