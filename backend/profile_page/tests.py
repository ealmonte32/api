from django.test import TestCase, RequestFactory
from django.contrib.auth.models import User
from django.urls import reverse


class ProfileViewTest(TestCase):
    def setUp(self):
        self.user0 = User.objects.create_user('test')
        self.user0.set_password('123')
        self.user0.save()

    def test_get(self):
        self.client.login(username='test', password='123')
        response = self.client.get(reverse('profile'))
        print(response)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Profile Settings')

    def test_comment(self):
        self.client.login(username='test', password='123')
        form_data = {'email': 'user@gmail.com', 'first_name': 'John', 'last_name': 'Doe',
                     'company': 'Acme Corporation'}
        # Submit form data.
        response = self.client.post(reverse('profile'), form_data)
        self.assertEqual(response.status_code, 200)
        # Load page for checking its content.
        response = self.client.get(reverse('profile'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'user@gmail.com')
        self.assertContains(response, 'John')
        self.assertContains(response, 'Doe')
        self.assertContains(response, 'Acme Corporation')
