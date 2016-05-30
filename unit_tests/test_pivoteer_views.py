from pivoteer.views import PivotManager
from profiles.models import Profile
from django.test import TestCase, RequestFactory
from django.core.urlresolvers import reverse
from django.contrib.auth.models import AnonymousUser


class TestPivotManager(TestCase):
    indicator = "twitter.com"
    ip_indicator = "199.59.150.7"

    def setUp(self):
        self.factory = RequestFactory()

    # We test each role, authenticated users first.
    def test_pivot_manager_auth_get(self):

        # Spin up a user and run a request through the view.
        url = reverse("Pivoteer_Tasks")
        request = self.factory.get(url)
        request.user = Profile.objects.create_user(email='test@test.com', password='test', is_admin=False)
        response = PivotManager.as_view()(request)
        self.assertEqual(response.status_code, 200)
        self.assertTrue("#SafeBrowsingPanel" in response.content.decode("utf-8"))
        self.assertTrue("#MalwarePanel" in response.content.decode("utf-8"))
        self.assertTrue("HistoricalPanel" in response.content.decode("utf-8"))
        self.assertTrue("#RecentPanel" in response.content.decode("utf-8"))

    # Administrative users.
    def test_pivot_manager_admin_get(self):

        # Spin up a user and run a request through the view.
        url = reverse("Pivoteer_Tasks")
        request = self.factory.get(url)
        request.user = Profile.objects.create_user(email='test2@test.com', password='test', is_admin=True)
        response = PivotManager.as_view()(request)
        self.assertEqual(response.status_code, 200)
        self.assertTrue("#SafeBrowsingPanel" in response.content.decode("utf-8"))
        self.assertTrue("#MalwarePanel" in response.content.decode("utf-8"))
        self.assertTrue("HistoricalPanel" in response.content.decode("utf-8"))
        self.assertTrue("#RecentPanel" in response.content.decode("utf-8"))

    # Inauthenticated users.
    def test_pivot_manager_anon_get(self):

        # Spin up a user and run a request through the view.
        url = reverse("Pivoteer_Tasks")
        request = self.factory.get(url)
        request.user = AnonymousUser()
        response = PivotManager.as_view()(request)

        # Inauthenticated users should be rejected.
        self.assertNotEqual(response.status_code, 200)
        self.assertTrue("#SafeBrowsingPanel" not in response.content.decode("utf-8"))
        self.assertTrue("#MalwarePanel" not in response.content.decode("utf-8"))
        self.assertTrue("HistoricalPanel" not in response.content.decode("utf-8"))
        self.assertTrue("#RecentPanel" not in response.content.decode("utf-8"))

    # Staff members.
    def test_pivot_manager_staff_sb_get(self):

        # Spin up a user and run a request through the view.
        url = reverse("Pivoteer_Tasks")
        request = self.factory.get(url)
        request.user = Profile.objects.create_user(email='test3@test.com', password='test', is_admin=False, is_staff=True)
        response = PivotManager.as_view()(request)
        self.assertEqual(response.status_code, 200)
        self.assertTrue("#SafeBrowsingPanel" in response.content.decode("utf-8"))
        self.assertTrue("#MalwarePanel" in response.content.decode("utf-8"))
        self.assertTrue("HistoricalPanel" in response.content.decode("utf-8"))
        self.assertTrue("#RecentPanel" in response.content.decode("utf-8"))