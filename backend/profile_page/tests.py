from django.test import TestCase
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone

from profile_page.forms import RegistrationForm


class ProfileViewsTest(TestCase):
    def setUp(self):
        self.user0 = User.objects.create_user('user@gmail.com')
        self.user0.set_password('123')
        self.user0.save()
        self.client.login(username='user@gmail.com', password='123')

    def test_get(self):
        response = self.client.get(reverse('profile'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Profile Settings')
        self.assertEqual(self.user0.profile.last_active, timezone.localdate())

    def test_post(self):
        form_data = {'email': 'user@gmail.com', 'first_name': 'John', 'last_name': 'Doe',
                     'company': 'Acme Corporation', 'phone': '+79100000000'}
        response = self.client.post(reverse('profile'), form_data)
        self.assertEqual(response.status_code, 302)
        # Load page for checking its content.
        response = self.client.get(reverse('profile'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'user@gmail.com')
        self.assertContains(response, 'John')
        self.assertContains(response, 'Doe')
        self.assertContains(response, 'Acme Corporation')
        self.assertContains(response, '+79100000000')

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


class RegistrationViewTest(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('user@gmail.com', 'user@gmail.com')

    def test_registration_form_success(self):
        form_data = {'email': 'user1@gmail.com', 'password1': 'SomeStrong56_Pass', 'password2': 'SomeStrong56_Pass',
                     'payment_plan': '1', 'first_name': 'John', 'last_name': 'Doe', 'company': 'Acme Corporation',
                     'phone': '+79100000000'}
        form = RegistrationForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_registration_form_week_pass(self):
        form_data = {'email': 'user1@gmail.com', 'password1': '123', 'password2': '123', 'payment_plan': '1',
                     'first_name': 'John', 'last_name': 'Doe', 'company': 'Acme Corporation', 'phone': '+79100000000'}
        form = RegistrationForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertDictEqual(form.errors, {
            'password2': ['This password is too short. It must contain at least 8 characters.',
                          'This password is too common.', 'This password is entirely numeric.']})

    def test_registration_form_email_exists(self):
        form_data = {'email': 'user@gmail.com', 'password1': 'SomeStrong56_Pass', 'password2': 'SomeStrong56_Pass',
                     'payment_plan': '1', 'first_name': 'John', 'last_name': 'Doe', 'company': 'Acme Corporation',
                     'phone': '+79100000000'}
        form = RegistrationForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertDictEqual(form.errors, {'email': ['This email address is already in use. Please supply a different '
                                                     'email address.']})

    def test_post(self):
        data = {'email': 'user1@gmail.com', 'password1': 'SomeStrong56_Pass', 'password2': 'SomeStrong56_Pass',
                'payment_plan': '2', 'first_name': 'John', 'last_name': 'Doe', 'company': 'Acme Corporation',
                'phone': '+79100000000'}
        response = self.client.post(reverse('registration_register'), data)
        self.assertEqual(response.status_code, 302)
        # Load the main page for checking its content.
        response = self.client.get(reverse('root'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'user1@gmail.com')
        self.assertContains(response, "Congratulations! We won&#39;t charge you for this plan for now.")
        # Load the profile page for checking its content.
        response = self.client.get(reverse('profile'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'user1@gmail.com')
        self.assertContains(response, 'John')
        self.assertContains(response, 'Doe')
        self.assertContains(response, 'Acme Corporation')
        self.assertContains(response, '+79100000000')

    def test_email_with_uppercase_letters(self):
        data = {'email': 'uSeR2@gmail.com', 'password1': 'SomeStrong56_Pass', 'password2': 'SomeStrong56_Pass',
                'payment_plan': '2'}
        response = self.client.post(reverse('registration_register'), data)
        self.assertEqual(response.status_code, 302)
        # Load page for checking its content.
        response = self.client.get(reverse('root'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'user2@gmail.com')
        self.assertContains(response, "Congratulations! We won&#39;t charge you for this plan for now.")
        self.client.logout()
        self.client.login(username='user2@gmail.com', password='SomeStrong56_Pass')
        response = self.client.get(reverse('root'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'user2@gmail.com')
