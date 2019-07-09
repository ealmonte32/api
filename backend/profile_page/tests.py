from django.test import TestCase
from django.contrib.auth.models import User
from django.urls import reverse
from django.utils import timezone


class ProfileViewsTest(TestCase):
    def setUp(self):
        self.user0 = User.objects.create_user('test')
        self.user0.set_password('123')
        self.user0.save()
        self.client.login(username='test', password='123')

    def test_get(self):
        response = self.client.get(reverse('profile'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Profile Settings')
        self.assertEqual(self.user0.profile.last_active, timezone.localdate())

    def test_post(self):
        form_data = {'email': 'user@gmail.com', 'first_name': 'John', 'last_name': 'Doe',
                     'company': 'Acme Corporation'}
        response = self.client.post(reverse('profile'), form_data)
        self.assertEqual(response.status_code, 302)
        # Load page for checking its content.
        response = self.client.get(reverse('profile'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'user@gmail.com')
        self.assertContains(response, 'John')
        self.assertContains(response, 'Doe')
        self.assertContains(response, 'Acme Corporation')

    def test_password_change_fail(self):
        form_data = {'old_password': '123', 'new_password1': '321', 'new_password2': '321'}
        response = self.client.post(reverse('profile_password'), form_data)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'This password is entirely numeric')

    def test_password_change_success(self):
        form_data = {'old_password': '123', 'new_password1': 'Hy321_Uh9Gfde', 'new_password2': 'Hy321_Uh9Gfde'}
        response = self.client.post(reverse('profile_password'), form_data)
        self.assertEqual(response.status_code, 302)

    def test_token_page(self):
        response = self.client.get(reverse('profile_token'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Generate token')
        response = self.client.get(reverse('generate_api_token'))
        self.assertEqual(response.status_code, 302)
        response = self.client.get(reverse('profile_token'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.user0.auth_token)
        self.assertContains(response, 'Revoke token')
        response = self.client.get(reverse('revoke_api_token'))
        self.assertEqual(response.status_code, 302)
        response = self.client.get(reverse('profile_token'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Generate token')
