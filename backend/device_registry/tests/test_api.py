from django.urls import reverse
from django.contrib.auth import get_user_model

from rest_framework.test import APITestCase

from device_registry.models import Credential, Device


class AjaxCredsTest(APITestCase):
    def setUp(self):
        self.url = reverse('ajax-creds')
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()
        self.client.login(username='test', password='123')

        self.credential = Credential.objects.create(owner=self.user, name='name1', key='key1', value='as9dfyaoiufhoah')
        self.device0 = Device.objects.create(device_id='device0.d.wott-dev.local', owner=self.user)
        self.headers = {
            'HTTP_SSL_CLIENT_SUBJECT_DN': 'CN=device0.d.wott-dev.local',
            'HTTP_SSL_CLIENT_VERIFY': 'SUCCESS'
        }

    def test_create_invalid(self):
        # 1. try to create 'Name1' while 'name1' already exists
        form_data = {
            'name': 'Name1',
            'key': 'key1',
            'value': 'as9dfyaoiufhoah',
            'method': 'create',
        }
        response = self.client.post(
            self.url,
            form_data,
            **self.headers,
            format='json'
        )
        self.assertEqual(response.status_code, 200)
        self.assertDictEqual(response.data, {'error': 'Invalid data supplied'})

        # 2. try to create 'Name+1' - incorrect name
        form_data['name'] = 'name+1'
        response = self.client.post(
            self.url,
            form_data,
            **self.headers,
            format='json'
        )
        self.assertEqual(response.status_code, 200)
        self.assertDictEqual(response.data, {'error': 'Invalid data supplied'})

    def test_update_invalid(self):
        # 1. try to rename 'name1' to 'Name+1' ('+' - incorrect symbol)
        form_data = {
            'name': 'Name+1',
            'key': 'key1',
            'value': 'as9dfyaoiufhoah',
            'pk': self.credential.pk,
            'method': 'update',
        }
        response = self.client.post(
            self.url,
            form_data,
            **self.headers,
            format='json'
        )
        self.assertEqual(response.status_code, 200)
        self.assertDictEqual(response.data, {'error': 'Invalid data supplied'})
