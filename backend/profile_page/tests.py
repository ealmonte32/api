from django.test import TestCase, RequestFactory
from django.contrib.auth.models import User
from .views import profile_page
from .models import Profile


class APIPingTest(TestCase):
    def setUp(self):
        self.api = RequestFactory()
        self.user0 = User.objects.create_user('test')
        self.user1 = User.objects.create_user('test-no-profile', email='test@localho.st')
        self.profile0 = Profile.objects.create(user=self.user0)

    def test_profile_page(self):
        request = self.api.get(f'/user/{self.user0.id}')
        request.user = self.user0
        response = profile_page(request, self.user0.id)
        self.assertEqual(response.status_code, 200)

    def test_form_submit_saves_profile(self):
        request = self.api.post(f'/user/{self.user1.id}', {
            'username': self.user1.username,
            'email': self.user1.email,
            'company': 'ACME'
        })
        request.user = self.user1
        self.assertFalse(Profile.objects.filter(user=self.user1).exists())
        response = profile_page(request, self.user1.id)
        self.assertTrue(Profile.objects.filter(user=self.user1).exists())
        self.assertEqual(self.user1.profile.company_name, 'ACME')
