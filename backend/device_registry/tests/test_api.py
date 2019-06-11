from collections import OrderedDict
from uuid import uuid4
from unittest.mock import patch, mock_open

from django.urls import reverse
from django.utils import timezone
from django.contrib.auth import get_user_model

from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework import serializers

from device_registry.models import Credential, Device, DeviceInfo

TEST_CERT = """-----BEGIN CERTIFICATE-----
MIIC5TCCAc2gAwIBAgIJAPMjGMrzQcI/MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV
BAMMCWxvY2FsaG9zdDAeFw0xOTAzMDUyMDE5MjRaFw0xOTA0MDQyMDE5MjRaMBQx
EjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAOgfhzltW1Bx/PLve7sk228G9FeBQmTVkEwiU1tgagvIzM8fhoeDnXoMVRf5
GPWZr4h0E4BtDRQUO7NqgW+r3RQMq4nJljTV9f8Om3Owx41BM5M5w5YH75JZzcZ1
OVBmJRPOG06I3Hk/uQjCGo1YN7ZggAdUmFQqQ03GdstqQhd6UzbV2dPphq+R2npV
oAjByawBwuxi+NJXxz20dUVkXrrxGgDUKcUn4NPsIUGf9hSHZcDMZ3XQcQQ/ykD9
i/zeVU6jGnsMOO+YZUguBlq/GKI2fzezfG7fv394oAJP9mV0T8k9ArciTigUehuv
a8sHA+vrvRXCNbpV8vEQbRh/+0sCAwEAAaM6MDgwFAYDVR0RBA0wC4IJbG9jYWxo
b3N0MAsGA1UdDwQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATANBgkqhkiG9w0B
AQsFAAOCAQEAL+KRDdqbbAFiMROy7eNkbMUj3Dp4S24y5QnGjFl4eSFLWu9UhBT+
FcElSbo1vKaW5DJi+XG9snyZfqEuknQlBEDTuBlOEqguGpmzYE/+T0wt9zLTByN8
N44fGr4f9ORj6Y6HJkzdlp+XCDdzHb2+3ienNle6bWlmBpbQaMVrayDxJ5yxldgJ
czUUClEc0OJDMw8PsHyYvrl+jk0JFXgDqBgAutPzSiC+pWL3H/5DO8t/NcccNNlR
2UZyh8r3qmVWo1jROR98z/J59ytNgMfYTmVI+ClUWKF5OWEOneKTf7dvic0Bqiyb
1lti7kgwF5QeRU2eEn3VC2F5JreBMpTkeA==
-----END CERTIFICATE-----
"""


def datetime_to_str(value):
    field = serializers.DateTimeField()
    return field.to_representation(value)


class DeviceCertViewTest(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.expires = timezone.now() + timezone.timedelta(days=7)
        self.device = Device.objects.create(
            device_id='device0.d.wott-dev.local',
            certificate_expires=self.expires,
            owner=self.user,
            certificate=TEST_CERT
        )
        self.url = reverse('get_device_cert', kwargs={'device_id': self.device.device_id})

    def test_simple_get(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.content, bytes)
        self.assertEqual(response.content, TEST_CERT.encode('utf8'))

    def test_get_with_format(self):
        response = self.client.get(self.url + '?format')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data, dict)
        self.assertDictEqual(response.data, {'certificate': TEST_CERT, 'certificate_expires': self.expires,
                                             'is_expired': False, 'device_id': self.device.device_id})


class DeviceIDViewTest(APITestCase):
    def setUp(self):
        self.url = reverse('get_device_id')

    def test_get(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data, dict)
        self.assertTrue('device_id' in response.data)
        self.assertIsInstance(response.data['device_id'], str)
        self.assertTrue(response.data['device_id'])  # Not empty.


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
