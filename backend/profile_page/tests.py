from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from django.conf import settings

from freezegun import freeze_time

from profile_page.forms import RegistrationForm
from profile_page.models import Profile
from device_registry.models import Device, HistoryRecord, RecommendedActionStatus, RecommendedAction


class ProfileViewsTest(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user0 = User.objects.create_user('user@gmail.com')
        self.user0.set_password('123')
        self.user0.save()
        self.client.login(username='user@gmail.com', password='123')

    def test_get(self):
        response = self.client.get(reverse('profile'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Settings')
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

    def test_registration_form_success(self):
        form_data = {'email': 'user1@gmail.com', 'password1': 'SomeStrong56_Pass', 'password2': 'SomeStrong56_Pass',
                     'payment_plan': '1', 'first_name': 'John', 'last_name': 'Doe', 'company': 'Acme Corporation',
                     'phone': '+79100000000'}
        form = RegistrationForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_registration_form_weak_pass(self):
        form_data = {'email': 'user1@gmail.com', 'password1': '123', 'password2': '123', 'payment_plan': '1',
                     'first_name': 'John', 'last_name': 'Doe', 'company': 'Acme Corporation', 'phone': '+79100000000'}
        form = RegistrationForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertDictEqual(form.errors, {
            'password2': ['This password is too short. It must contain at least 8 characters.',
                          'This password is too common.', 'This password is entirely numeric.']})

    def test_registration_form_email_exists(self):
        User = get_user_model()
        user = User.objects.create_user('user@gmail.com', 'user@gmail.com')
        form_data = {'email': user.email, 'password1': 'SomeStrong56_Pass', 'password2': 'SomeStrong56_Pass',
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
        self.assertInHTML('<h4>Recommended Actions</h4>',
                          response.rendered_content)
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
        self.assertInHTML('<h4>Recommended Actions</h4>',
                          response.rendered_content)
        self.client.logout()
        self.client.login(username='user2@gmail.com', password='SomeStrong56_Pass')
        response = self.client.get(reverse('root'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'user2@gmail.com')

    def test_tracking(self):
        data = {'email': 'user1@gmail.com', 'password1': 'SomeStrong56_Pass', 'password2': 'SomeStrong56_Pass',
                'payment_plan': '2', 'first_name': 'John', 'last_name': 'Doe', 'company': 'Acme Corporation',
                'phone': '+79100000000'}
        response = self.client.post(reverse('registration_register'), data, follow=True)
        self.assertTrue(response.context['signed_up'])
        self.assertFalse('signed_in' in response.context)


class LoginViewTest(TestCase):
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


class ProfileModelTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('user@gmail.com')
        self.user.save()
        Profile.objects.create(user=self.user)
        self.device = Device.objects.create(device_id='device0.d.wott-dev.local', owner=self.user)

    @freeze_time("2020-04-01 10:00:00", tz_offset=4)
    def test_actions_resolved_today(self):
        now = timezone.now()
        # Take resolved RAs info from RecommendedActionStatus model.
        RecommendedActionStatus.objects.create(
            device=self.device, ra=RecommendedAction.objects.create(action_class='ClassOne'),
            status=RecommendedAction.Status.NOT_AFFECTED, resolved_at=now)
        RecommendedActionStatus.objects.create(
            device=self.device, ra=RecommendedAction.objects.create(action_class='ClassTwo'),
            status=RecommendedAction.Status.NOT_AFFECTED, resolved_at=now)
        self.assertEqual(self.user.profile.actions_resolved_today, 2)
        # Return 0 because the today's history record exists.
        HistoryRecord.objects.create(owner=self.user, recommended_actions_resolved=5)
        self.assertEqual(self.user.profile.actions_resolved_today, 0)

    def test_actions_resolved_this_quarter(self):
        # 2 days ago (previous quarter). this history record should not be counted.
        with freeze_time("2020-03-31 10:00:00", tz_offset=4):
            HistoryRecord.objects.create(owner=self.user, recommended_actions_resolved=5)
        # 1 day ago (current quarter), should be counted.
        with freeze_time("2020-04-01 10:00:00", tz_offset=4):
            HistoryRecord.objects.create(owner=self.user, recommended_actions_resolved=6)
        with freeze_time("2020-04-02 10:00:00", tz_offset=4):
            self.assertEqual(self.user.profile.actions_resolved_this_quarter, 6)
            # Add a RA resolved today, not yet reflected in history records.
            RecommendedActionStatus.objects.create(
                device=self.device, ra=RecommendedAction.objects.create(action_class='ClassTwo'),
                status=RecommendedAction.Status.NOT_AFFECTED, resolved_at=timezone.now() - timezone.timedelta(hours=1))
            self.assertEqual(self.user.profile.actions_resolved_this_quarter, 7)

    def test_current_weekly_streak(self):
        # 1 week ago.
        with freeze_time("2020-03-25 10:00:00", tz_offset=4):
            HistoryRecord.objects.create(owner=self.user, recommended_actions_resolved=settings.MAX_WEEKLY_RA)
        # 2 weeks ago.
        with freeze_time("2020-03-18 10:00:00", tz_offset=4):
            hr = HistoryRecord.objects.create(owner=self.user, recommended_actions_resolved=settings.MAX_WEEKLY_RA)
        # 3 weeks ago.
        with freeze_time("2020-03-11 10:00:00", tz_offset=4):
            HistoryRecord.objects.create(owner=self.user, recommended_actions_resolved=settings.MAX_WEEKLY_RA)
        # Today.
        with freeze_time("2020-04-02 10:00:00", tz_offset=4):
            self.assertEqual(self.user.profile.current_weekly_streak, 3)
            # Reduce the number of resolved RAs 2 weeks ago below the threshold.
            hr.recommended_actions_resolved = settings.MAX_WEEKLY_RA - 1
            hr.save(update_fields=['recommended_actions_resolved'])
            self.assertEqual(self.user.profile.current_weekly_streak, 1)
            # Increase the number of resolved RAs 2 weeks ago above the threshold.
            hr.recommended_actions_resolved = settings.MAX_WEEKLY_RA + 1
            hr.save(update_fields=['recommended_actions_resolved'])
            self.assertEqual(self.user.profile.current_weekly_streak, 3)
            # Delete the history record for 2 weeks ago.
            hr.delete()
            self.assertEqual(self.user.profile.current_weekly_streak, 1)
        # Yesterday (current week).
        with freeze_time("2020-04-01 10:00:00", tz_offset=4):
            HistoryRecord.objects.create(owner=self.user, recommended_actions_resolved=settings.MAX_WEEKLY_RA)
        # Today.
        with freeze_time("2020-04-02 10:00:00", tz_offset=4):
            self.assertEqual(self.user.profile.current_weekly_streak, 2)
