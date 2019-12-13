from unittest.mock import patch, PropertyMock

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone

from .forms import RegistrationForm


class RegistrationFormTests(TestCase):
    def setUp(self):
        self.registration_data = {
            'email': 'user@gmail.com',
            'password1': 'SomeStrong56_Pass',
            'password2': 'SomeStrong56_Pass',
            'first_name': 'John',
            'last_name': 'Doe',
            'company': 'Acme Corporation',
            'phone': '+79100000000',
            'payment_plan': '1',
            'nodes_number': 1
        }

    def test_registration_form_success(self):
        form_data = self.registration_data
        form = RegistrationForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_registration_form_weak_pass(self):
        form_data = self.registration_data.copy()
        form_data['password1'] = '123'
        form_data['password2'] = '123'
        form = RegistrationForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertDictEqual(form.errors, {
            'password2': ['This password is too short. It must contain at least 8 characters.',
                          'This password is too common.', 'This password is entirely numeric.']})

    def test_registration_form_email_exists(self):
        User = get_user_model()
        User.objects.create_user('user@gmail.com', 'user@gmail.com')
        form_data = self.registration_data
        form = RegistrationForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertDictEqual(form.errors, {'email': ['This email address is already in use. Please supply a different '
                                                     'email address.']})

    def test_standard_plan(self):
        form_data = self.registration_data.copy()
        form_data['payment_plan'] = '2'
        form_data['payment_method_id'] = 'pm_xxxxxx'
        form = RegistrationForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_payment_method_id_validation(self):
        form_data = self.registration_data.copy()
        form_data['payment_plan'] = '2'
        form_data['payment_method_id'] = 'xxxxxx'  # Wrong value.
        form = RegistrationForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertDictEqual(form.errors, {'__all__': ['Wrong card info provided.']})


class ProfileViewsTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('user@gmail.com')
        self.user.set_password('123')
        self.user.save()
        self.client.login(username='user@gmail.com', password='123')

    def test_get(self):
        response = self.client.get(reverse('profile'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Settings')
        self.assertEqual(self.user.profile.last_active, timezone.localdate())

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
        self.assertContains(response, 'Generate your API Token')
        response = self.client.get(reverse('generate_api_token'))
        self.assertEqual(response.status_code, 302)
        response = self.client.get(reverse('profile_token'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.user.auth_token)
        self.assertContains(response, 'Revoke your API Token')
        response = self.client.get(reverse('revoke_api_token'))
        self.assertEqual(response.status_code, 302)
        response = self.client.get(reverse('profile_token'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Generate your API Token')


class RegistrationViewTests(TestCase):
    def setUp(self):
        self.registration_data = {
            'email': 'user@gmail.com',
            'password1': 'SomeStrong56_Pass',
            'password2': 'SomeStrong56_Pass',
            'first_name': 'John',
            'last_name': 'Doe',
            'company': 'Acme Corporation',
            'phone': '+79100000000',
            'payment_plan': '1',
            'nodes_number': 1
        }

    def test_post(self):
        response = self.client.post(reverse('registration_register'), self.registration_data)
        self.assertRedirects(response, '/')
        # Load the main page for checking its content.
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'user@gmail.com')
        self.assertInHTML('<h1 class="big-text text-center">Welcome User!</h1>', response.rendered_content)
        # Load the profile page for checking its content.
        response = self.client.get(reverse('profile'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'user@gmail.com')
        self.assertContains(response, 'John')
        self.assertContains(response, 'Doe')
        self.assertContains(response, 'Acme Corporation')
        self.assertContains(response, '+79100000000')

    def test_email_with_uppercase_letters(self):
        data = self.registration_data.copy()
        data['email'] = 'uSeR@gmail.com'
        response = self.client.post(reverse('registration_register'), data)
        self.assertRedirects(response, '/')
        # Load page for checking its content.
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'user@gmail.com')
        self.assertInHTML('<h1 class="big-text text-center">Welcome User!</h1>', response.rendered_content)
        self.client.logout()
        self.client.login(username='user@gmail.com', password='SomeStrong56_Pass')
        response = self.client.get(reverse('root'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'user@gmail.com')

    def test_tracking(self):
        response = self.client.post(reverse('registration_register'), self.registration_data, follow=True)
        self.assertTrue(response.context.get('signed_up'))
        self.assertFalse('signed_in' in response.context)


class LoginViewTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.credentials = {
            'username': 'testuser',
            'password': 'secret'}
        User.objects.create_user(**self.credentials)

    def test_tracking(self):
        # Login as user: should have signed_in set once
        response = self.client.post(reverse('auth_login'), self.credentials, follow=True)
        self.assertFalse('signed_up' in response.context)
        self.assertTrue(response.context['signed_in'])

        # should have it reset next time
        response = self.client.get(reverse('profile'))
        self.assertFalse('signed_up' in response.context)
        self.assertFalse('signed_in' in response.context)


class PaymentPlanViewTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user0 = User.objects.create_user('user@gmail.com')
        self.user0.set_password('123')
        self.user0.save()
        self.client.login(username='user@gmail.com', password='123')
        self.billing_data = {
            'payment_plan': '1',
            'nodes_number_hidden': 1
        }
        self.url = reverse('payment_plan')

    @patch('profile_page.models.Profile.current_period_end', new_callable=PropertyMock)
    def test_get(self, mock_current_period_end):
        mock_current_period_end.return_value = timezone.now()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Billing')
        self.client.logout()
        response = self.client.get(self.url)
        self.assertRedirects(response, '/accounts/login/?next=/user/profile/payment/')

    @patch('profile_page.models.Profile.current_period_end', new_callable=PropertyMock)
    def test_post(self, mock_current_period_end):
        mock_current_period_end.return_value = timezone.now()
        response = self.client.post(self.url, self.billing_data)
        self.assertRedirects(response, self.url)
