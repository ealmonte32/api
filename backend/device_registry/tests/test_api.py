from collections import OrderedDict
from uuid import uuid4
from unittest.mock import patch, mock_open

from django.urls import reverse
from django.contrib.auth import get_user_model

from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework import serializers

from device_registry.models import Credential, Device, DeviceInfo


def datetime_to_str(value):
    field = serializers.DateTimeField()
    return field.to_representation(value)


class CACertViewTest(APITestCase):
    def setUp(self):
        self.url = reverse('get_ca')

    def test_get(self):
        with patch('cfssl.cfssl.CFSSL.info') as info:
            info.return_value = {'certificate': '010101'}
            response = self.client.get(self.url)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertDictEqual(response.data, {'ca_certificate': '010101'})


class CABundleViewTest(APITestCase):
    def setUp(self):
        self.url = reverse('get_ca_bundle')

    @patch('builtins.open', mock_open(read_data='010101'))
    def test_get(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertDictEqual(response.data, {'ca_bundle': '010101'})


class ClaimByLinkTest(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()
        self.claim_token = uuid4()
        self.device = Device.objects.create(device_id='device0.d.wott-dev.local', claim_token=self.claim_token)
        self.client.login(username='test', password='123')
        self.url = reverse('claim_by_link')

    def test_get_success(self):
        device = Device.objects.get(pk=self.device.pk)
        self.assertFalse(device.claimed)
        url = self.url + '?claim-token=%s&device-id=%s' % (self.claim_token, self.device.device_id)
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, 'Device device0.d.wott-dev.local claimed!')
        device = Device.objects.get(pk=self.device.pk)
        self.assertTrue(device.claimed)

    def test_get_fail(self):
        device = Device.objects.get(pk=self.device.pk)
        self.assertFalse(device.claimed)
        url = self.url + '?claim-token=abc&device-id=%s' % self.device.device_id
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)
        device = Device.objects.get(pk=self.device.pk)
        self.assertFalse(device.claimed)


class DeviceListViewTest(APITestCase):
    def setUp(self):
        self.url = reverse('list_devices')
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()
        self.device = Device.objects.create(device_id='device0.d.wott-dev.local', owner=self.user)
        self.device_info = DeviceInfo.objects.create(
            device=self.device,
            device_manufacturer='Raspberry Pi',
            device_model='900092',
            selinux_state={'enabled': True, 'mode': 'enforcing'},
            app_armor_enabled=True,
            logins={'pi': {'failed': 1, 'success': 1}}
        )
        self.client.login(username='test', password='123')

    def test_get(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.maxDiff = None
        self.assertListEqual(response.data, [OrderedDict([('id', self.device_info.id),
                                                          ('device', OrderedDict(
                                                              [('id', self.device.id),
                                                               ('device_id', self.device.device_id),
                                                               ('created', datetime_to_str(self.device.created)),
                                                               ('last_ping', None), ('certificate', None),
                                                               ('certificate_csr', None),
                                                               ('certificate_expires', None),
                                                               ('comment', None), ('claim_token', ''),
                                                               ('fallback_token', ''), ('name', ''),
                                                               ('agent_version', None),
                                                               ('owner', self.user.id)])),
                                                          (
                                                              'device_manufacturer',
                                                              self.device_info.device_manufacturer),
                                                          ('device_model', self.device_info.device_model),
                                                          ('device_architecture', None),
                                                          ('device_operating_system', None),
                                                          ('device_operating_system_version', None),
                                                          ('distr_id', None), ('distr_release', None),
                                                          ('trust_score', None), ('fqdn', None),
                                                          ('ipv4_address', None),
                                                          ('selinux_state', {'mode': 'enforcing', 'enabled': True}),
                                                          ('app_armor_enabled', True),
                                                          ('logins', {'pi': {'failed': 1, 'success': 1}}),
                                                          ('default_password', None), ('detected_mirai', False)])])


class CredentialsViewTest(APITestCase):
    def setUp(self):
        self.url = reverse('ajax_creds')
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()
        self.credential = Credential.objects.create(owner=self.user, name='name1', key='key1', value='value1')
        self.client.login(username='test', password='123')

    def test_get(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertDictEqual(response.data, {'data': [OrderedDict(
            [('name', 'name1'), ('key', 'key1'), ('value', 'value1'), ('pk', self.credential.pk)])]})


class DeleteCredentialViewTest(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()
        self.credential = Credential.objects.create(owner=self.user, name='name1', key='key1', value='value1')
        self.url = reverse('ajax_creds_delete', kwargs={'pk': self.credential.pk})
        self.client.login(username='test', password='123')

    def test_delete(self):
        self.assertEqual(Credential.objects.count(), 1)
        response = self.client.delete(self.url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(Credential.objects.count(), 0)


class UpdateCredentialViewTest(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()
        self.credential = Credential.objects.create(owner=self.user, name='name1', key='key1', value='value1')
        self.url = reverse('ajax_creds_update', kwargs={'pk': self.credential.pk})
        self.client.login(username='test', password='123')
        self.data = {'name': 'name2', 'key': 'key2', 'value': 'value2'}

    def test_patch(self):
        self.assertEqual(Credential.objects.count(), 1)
        response = self.client.patch(self.url, self.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertDictEqual(response.data, {'name': 'name2', 'key': 'key2', 'value': 'value2'})
        self.assertEqual(Credential.objects.count(), 1)


class CreateCredentialViewTest(APITestCase):
    def setUp(self):
        self.url = reverse('ajax_creds_create')
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()
        self.client.login(username='test', password='123')
        self.data = {'name': 'name1', 'key': 'key1', 'value': 'value1'}

    def test_post(self):
        self.assertEqual(Credential.objects.count(), 0)
        response = self.client.post(self.url, self.data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertDictEqual(response.data, {'name': 'name1', 'key': 'key1', 'value': 'value1'})
        self.assertEqual(Credential.objects.count(), 1)


class AjaxCredsTest(APITestCase):
    def setUp(self):
        self.url = reverse('ajax-creds')
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()
        self.client.login(username='test', password='123')

        self.credential = Credential.objects.create(owner=self.user, name='name1', key='key1', value='value1')
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
            'value': 'value1',
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
            'value': 'value1',
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
