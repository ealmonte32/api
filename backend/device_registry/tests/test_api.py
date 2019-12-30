from collections import OrderedDict
import uuid
from unittest.mock import patch, mock_open
import json
import datetime

from django.urls import reverse
from django.utils import timezone
from django.utils.http import urlencode
from django.contrib.auth import get_user_model
from django.conf import settings

from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework import serializers
from rest_framework.exceptions import ErrorDetail
from rest_framework.authtoken.models import Token

from device_registry.models import Credential, Device, DeviceInfo, Tag, FirewallState, PortScan, PairingKey, \
    RecommendedAction
from device_registry.serializers import DeviceListSerializer
from device_registry.recommended_actions import ActionMeta, DefaultCredentialsAction
from device_registry.models import GlobalPolicy
from profile_page.models import Profile

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

OPEN_PORTS_INFO = [{"host": "192.168.1.178", "port": 22, "proto": "tcp", "state": "open", "ip_version": 4}]

OPEN_CONNECTIONS_INFO = [
    {'ip_version': 4, 'type': 'tcp', 'local_address': ['192.168.1.178', 4567],
     'remote_address': ['192.168.1.177', 5678], 'status': 'open', 'pid': 3425}
]

TEST_RULES = {'INPUT': [{'src': '15.15.15.50/32', 'target': 'DROP'}, {'src': '15.15.15.51/32', 'target': 'DROP'}],
              'OUTPUT': [], 'FORWARD': []}


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
        self.claim_token = uuid.uuid4()
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


# implements simple tags container dictionaries equality assertion
class AssertTaggedMixin:
    """
    Assert equality of two dicts contains tags.
    check that dict1 equal to dict2 and tags of dict1 all in tags of dict2

    In fact tags can be sorted or not. So for comparing tags used only
    their names. And ignored their order. And for simplisity, as it
    for test data we check only that dict1.tags is full in dict2.tags
    """

    def assertTaggedEqual(self, dict1, dict2):
        for key in dict1:
            assert key in dict2
            if key == 'tags':
                for i, _ in enumerate(dict1['tags']):
                    assert 'name' in dict1['tags'][i]
                    assert 'name' in dict2['tags'][i]
                    assert dict1['tags'][i]['name'] == dict2['tags'][i]['name']
            else:
                self.assertEqual(dict1[key], dict2[key])


class DeviceListViewTest(APITestCase):
    def setUp(self):
        self.url = reverse('list_devices')
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()
        self.device = Device.objects.create(
            device_id='device0.d.wott-dev.local',
            owner=self.user,
            tags='tag1,tag2')
        self.device_info = DeviceInfo.objects.create(
            device=self.device,
            device_manufacturer='Raspberry Pi',
            device_model='900092',
            selinux_state={'enabled': True, 'mode': 'enforcing'},
            app_armor_enabled=True,
            logins={'pi': {'failed': 1, 'success': 1}},
            device_metadata={'test-key': 'test-value'}
        )

    def test_get(self):
        self.client.login(username='test', password='123')
        response = self.client.get(self.url)
        self.client.logout()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertListEqual(response.data, [OrderedDict([('device', OrderedDict(
            [('id', self.device.id), ('device_id', self.device.device_id), ('owner', self.user.id),
             ('created', datetime_to_str(self.device.created)), ('last_ping', None), ('certificate_expires', None),
             ('comment', None), ('name', ''), ('agent_version', None), ('trust_score', None),
             ('tags', list(self.device.tags.values_list('pk', flat=True)))])),
                                                          (
                                                              'device_manufacturer',
                                                              self.device_info.device_manufacturer),
                                                          ('device_model', self.device_info.device_model),
                                                          ('device_architecture', None),
                                                          ('device_operating_system', None),
                                                          ('device_operating_system_version', None),
                                                          ('fqdn', None), ('ipv4_address', None),
                                                          ('selinux_state', {'mode': 'enforcing', 'enabled': True}),
                                                          ('app_armor_enabled', True),
                                                          ('logins', {'pi': {'failed': 1, 'success': 1}}),
                                                          ('default_password', None), ('detected_mirai', False),
                                                          ('device_metadata', {'test-key': 'test-value'})])])

    def test_get_token_auth_success(self):
        token = Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token %s' % token.key)
        response = self.client.get(self.url)
        self.client.credentials()  # Reset previously set HTTP headers.
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertListEqual(response.data, [OrderedDict([('device', OrderedDict(
            [('id', self.device.id), ('device_id', self.device.device_id), ('owner', self.user.id),
             ('created', datetime_to_str(self.device.created)), ('last_ping', None), ('certificate_expires', None),
             ('comment', None), ('name', ''), ('agent_version', None), ('trust_score', None),
             ('tags', list(self.device.tags.values_list('pk', flat=True)))])),
                                                          (
                                                              'device_manufacturer',
                                                              self.device_info.device_manufacturer),
                                                          ('device_model', self.device_info.device_model),
                                                          ('device_architecture', None),
                                                          ('device_operating_system', None),
                                                          ('device_operating_system_version', None),
                                                          ('fqdn', None), ('ipv4_address', None),
                                                          ('selinux_state', {'mode': 'enforcing', 'enabled': True}),
                                                          ('app_armor_enabled', True),
                                                          ('logins', {'pi': {'failed': 1, 'success': 1}}),
                                                          ('default_password', None), ('detected_mirai', False),
                                                          ('device_metadata', {'test-key': 'test-value'})])])

    def test_get_token_auth_fail(self):
        Token.objects.create(user=self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token random_string')
        response = self.client.get(self.url)
        self.client.credentials()  # Reset previously set HTTP headers.
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class CredentialsViewTest(APITestCase):
    def setUp(self):
        self.url = reverse('ajax-credentials')
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()
        self.credential = Credential.objects.create(owner=self.user, name='name1', data={'key1': 'value1'},
                                                    tags="tag1,tag2", linux_user='nobody')
        self.tags = self.credential.tags.tags
        self.client.login(username='test', password='123')

    def test_get(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertDictEqual(response.data, {'data': [OrderedDict(
            [('name', 'name1'), ('linux_user', 'nobody'), ('pk', self.credential.pk),
             ('tags_data', [OrderedDict([('name', 'tag1'), ('pk', self.tags[0].pk)]),
                            OrderedDict([('name', 'tag2'), ('pk', self.tags[1].pk)])]
              ), ('data', {'key1': 'value1'})])]})


class DeleteCredentialViewTest(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()
        self.credential = Credential.objects.create(owner=self.user, name='name1', data={'key1': 'value1'},
                                                    tags="tag1,tag2")
        self.url = reverse('ajax-credentials-delete', kwargs={'pk': self.credential.pk})
        self.client.login(username='test', password='123')

    def test_delete(self):
        self.assertEqual(Credential.objects.count(), 1)
        response = self.client.delete(self.url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(Credential.objects.count(), 0)
        self.assertEqual(Tag.objects.filter(protected=False).count(), 0)


class UpdateCredentialViewTest(APITestCase, AssertTaggedMixin):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()
        self.credential1 = Credential.objects.create(owner=self.user, name='name1', data={'key1': 'value1'})
        self.url = reverse('ajax-credentials-update', kwargs={'pk': self.credential1.pk})
        self.client.login(username='test', password='123')
        self.data = {'name': 'name2', 'data': {'key2': 'value2'}, 'linux_user': 'nobody',
                     'tags': [{'name': 'tag1'}, {'name': 'tag2'}]}

    def test_patch(self):
        self.assertEqual(Credential.objects.count(), 1)
        response = self.client.patch(self.url, self.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTaggedEqual(response.data, self.data)
        self.assertEqual(Credential.objects.count(), 1)

    def test_patch_duplication(self):
        # check for deny to update with duplicate Name/Key/File owner combination
        self.assertEqual(Credential.objects.count(), 1)
        credential2 = Credential.objects.create(owner=self.user, name='name2', data={'key2': 'value2'},
                                                linux_user='nobody')
        self.assertEqual(Credential.objects.count(), 2)
        response = self.client.patch(self.url, self.data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(response.data, {'error': "'Name'/'File owner' combination should be unique"})
        self.assertEqual(Credential.objects.count(), 2)
        # check for update the record itself
        url2 = reverse('ajax-credentials-update', kwargs={'pk': credential2.pk})
        response = self.client.patch(url2, self.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTaggedEqual(response.data, self.data)
        self.assertEqual(Credential.objects.count(), 2)


class CreateCredentialViewTest(APITestCase, AssertTaggedMixin):

    def setUp(self):
        self.url = reverse('ajax-credentials-create')
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()
        self.client.login(username='test', password='123')
        self.data = {'name': 'name1', 'data': {'key1': 'value1'}, 'linux_user': 'nobody',
                     'tags': [{'name': 'tag1'}, {'name': 'tag2'}]}

    def test_post(self):
        self.assertEqual(Credential.objects.count(), 0)
        response = self.client.post(self.url, self.data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTaggedEqual(response.data, self.data)
        self.assertEqual(Credential.objects.count(), 1)

    def test_post_duplication(self):
        self.assertEqual(Credential.objects.count(), 0)
        Credential.objects.create(owner=self.user, name='name1', data={'key1': 'value3'}, linux_user='nobody')
        self.assertEqual(Credential.objects.count(), 1)
        response = self.client.post(self.url, self.data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(response.data, {'error': "'Name'/'File owner' combination should be unique"})
        self.assertEqual(Credential.objects.count(), 1)


class SignNewDeviceViewTest(APITestCase):
    def setUp(self):
        self.url = reverse('sign_device_cert')
        self.expires = timezone.now() - timezone.timedelta(days=1)
        self.uuid = uuid.uuid4()
        self.post_data = {'device_id': 'device1.d.wott-dev.local', 'csr': 'asdfsdf',
                          'device_operating_system': 'linux', 'device_operating_system_version': '2',
                          'device_architecture': '386', 'fqdn': 'domain.com', 'ipv4_address': '192.168.1.15'}

    def test_post_success(self):
        with patch('cfssl.cfssl.CFSSL.sign') as sign, \
                patch('device_registry.ca_helper.get_certificate_expiration_date') as gced, \
                patch('uuid.uuid4') as uuid4:
            sign.return_value = '010101'
            gced.return_value = self.expires
            uuid4.return_value = self.uuid

            self.assertEqual(Device.objects.count(), 0)
            self.assertEqual(DeviceInfo.objects.count(), 0)
            response = self.client.post(self.url, self.post_data)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertDictEqual(response.data, {
                'certificate': '010101',
                'certificate_expires': self.expires,
                'claim_token': self.uuid,
                'fallback_token': self.uuid
            })
            self.assertEqual(Device.objects.count(), 1)
            self.assertEqual(DeviceInfo.objects.count(), 1)

    def test_post_failed_sign_csr(self):
        with patch('cfssl.cfssl.CFSSL.sign') as sign, \
                patch('device_registry.ca_helper.get_certificate_expiration_date') as gced, \
                patch('uuid.uuid4') as uuid4:
            sign.return_value = False
            gced.return_value = self.expires
            uuid4.return_value = self.uuid

            self.assertEqual(Device.objects.count(), 0)
            self.assertEqual(DeviceInfo.objects.count(), 0)
            response = self.client.post(self.url, self.post_data)
            self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
            self.assertEqual(response.data, 'Unknown error')
            self.assertEqual(Device.objects.count(), 0)
            self.assertEqual(DeviceInfo.objects.count(), 0)


class RenewExpiredCertViewTest(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.device = Device.objects.create(
            device_id='device0.d.wott-dev.local',
            owner=self.user,
            fallback_token='0000000',
            certificate_expires=timezone.now() - timezone.timedelta(days=1)
        )
        DeviceInfo.objects.create(device=self.device)
        self.url = reverse('sign_expired_cert')
        self.expires = timezone.now() + timezone.timedelta(days=3)
        self.uuid = uuid.uuid4()
        self.post_data = {'device_id': 'device0.d.wott-dev.local', 'csr': 'asdfsdf', 'fallback_token': '0000000',
                          'device_operating_system': 'linux', 'device_operating_system_version': '2',
                          'device_architecture': '386', 'fqdn': 'domain.com', 'ipv4_address': '192.168.1.15'}

    def test_post_success(self):
        with patch('cfssl.cfssl.CFSSL.sign') as sign, \
                patch('device_registry.ca_helper.get_certificate_expiration_date') as gced, \
                patch('device_registry.ca_helper.csr_is_valid') as civ, \
                patch('uuid.uuid4') as uuid4:
            sign.return_value = '010101'
            gced.return_value = self.expires
            civ.return_value = True
            uuid4.return_value = self.uuid

            self.assertEqual(Device.objects.count(), 1)
            self.assertEqual(DeviceInfo.objects.count(), 1)
            response = self.client.post(self.url, self.post_data)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertDictEqual(response.data, {
                'certificate': '010101',
                'certificate_expires': self.expires,
                'claim_token': self.uuid,
                'fallback_token': self.uuid,
                'claimed': self.device.claimed
            })
            self.assertEqual(Device.objects.count(), 1)
            self.assertEqual(DeviceInfo.objects.count(), 1)

    def test_post_wrong_device_id(self):
        post_data = self.post_data.copy()
        post_data['device_id'] = 'no_such_device'
        self.assertEqual(Device.objects.count(), 1)
        self.assertEqual(DeviceInfo.objects.count(), 1)
        response = self.client.post(self.url, post_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(response.data, {'device_id': [ErrorDetail(string='Device not found', code='invalid')]})

    def test_post_certificate_not_expired(self):
        self.device.certificate_expires = timezone.now() + timezone.timedelta(days=1)
        self.device.save(update_fields=['certificate_expires'])
        self.assertEqual(Device.objects.count(), 1)
        self.assertEqual(DeviceInfo.objects.count(), 1)
        response = self.client.post(self.url, self.post_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data, 'Certificate is not expired yet')

    def test_post_wrong_fallback_token(self):
        post_data = self.post_data.copy()
        post_data['fallback_token'] = 'no_such_fallback_token'
        self.assertEqual(Device.objects.count(), 1)
        self.assertEqual(DeviceInfo.objects.count(), 1)
        response = self.client.post(self.url, post_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(
            response.data, {'fallback_token': [ErrorDetail(string='Invalid fallback token', code='invalid')]})

    def test_post_wrong_csr(self):
        with patch('device_registry.ca_helper.csr_is_valid') as civ:
            civ.return_value = False
            response = self.client.post(self.url, self.post_data)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertEqual(response.data, 'Invalid CSR')

    def test_post_fail_sign_csr(self):
        with patch('device_registry.ca_helper.csr_is_valid') as civ, patch('cfssl.cfssl.CFSSL.sign') as sign:
            civ.return_value = True
            sign.return_value = False
            response = self.client.post(self.url, self.post_data)
            self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
            self.assertEqual(response.data, 'Unknown error')


class IsDeviceClaimedViewTest(APITestCase):
    def setUp(self):
        self.url = reverse('mtls-is_claimed')
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.device0 = Device.objects.create(device_id='device0.d.wott-dev.local', owner=self.user)
        self.headers = {
            'HTTP_SSL_CLIENT_SUBJECT_DN': 'CN=device0.d.wott-dev.local',
            'HTTP_SSL_CLIENT_VERIFY': 'SUCCESS'
        }

    def test_get(self):
        response = self.client.get(self.url, **self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertDictEqual(response.json(), {'claim_token': '', 'claimed': True})

    def test_get_fail_wrong_header(self):
        headers = self.headers
        headers['HTTP_SSL_CLIENT_VERIFY'] = 'random_text'
        response = self.client.get(self.url, **headers)
        self.assertEqual(response.status_code, 403)
        self.assertDictEqual(response.json(), {'detail': 'You do not have permission to perform this action.'})

    def test_get_fail_wrong_device_id(self):
        headers = self.headers
        headers['HTTP_SSL_CLIENT_SUBJECT_DN'] = 'CN=device1.d.wott-dev.local'
        response = self.client.get(self.url, **headers)
        self.assertEqual(response.status_code, 403)
        self.assertDictEqual(response.json(), {'detail': 'You do not have permission to perform this action.'})


class MtlsTesterViewTest(APITestCase):
    def setUp(self):
        self.url = reverse('mtls-tester')
        self.device0 = Device.objects.create(device_id='device0.d.wott-dev.local')
        self.headers = {
            'HTTP_SSL_CLIENT_SUBJECT_DN': 'CN=device0.d.wott-dev.local',
            'HTTP_SSL_CLIENT_VERIFY': 'SUCCESS'
        }

    def test_get(self):
        response = self.client.get(self.url, **self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertDictEqual(response.json(), {'message': 'Hello device0.d.wott-dev.local'})


class ActionViewTest(APITestCase):
    def setUp(self):
        self.url = reverse('action', kwargs={'action_id': 77, 'action_name': 'action1'})

    def test_get(self):
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertDictEqual(response.json(), {'id': 77, 'name': 'action1'})


class MtlsCredsViewTest(APITestCase):
    def setUp(self):
        self.url = reverse('mtls-credentials')
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.credential = Credential.objects.create(owner=self.user, name='name1',
                                                    data={'key1': 'as9dfyaoiufhoasdfjh'},
                                                    tags='tag1', linux_user='nobody')
        self.credential2 = Credential.objects.create(owner=self.user, name='name2', data={'key2': 'iuoiuoifpojoijccm'},
                                                     tags='Hardware: Raspberry Pi,')
        self.device = Device.objects.create(device_id='device0.d.wott-dev.local', owner=self.user, tags='tag1,tag2')
        self.deviceinfo = DeviceInfo.objects.create(device=self.device)
        self.headers = {
            'HTTP_SSL_CLIENT_SUBJECT_DN': 'CN=device0.d.wott-dev.local',
            'HTTP_SSL_CLIENT_VERIFY': 'SUCCESS'
        }

    def test_get(self):
        response = self.client.get(self.url, **self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertListEqual(response.json(),
                             [{'name': 'name1', 'data': {'key1': 'as9dfyaoiufhoasdfjh'}, 'linux_user': 'nobody',
                               'pk': self.credential.pk,
                               'tags_data': [{'name': 'tag1', 'pk': self.credential.tags.tags[0].pk}]}])

    def test_get_revoked_device(self):
        Device.objects.create(device_id='device1.d.wott-dev.local')
        headers = {
            'HTTP_SSL_CLIENT_SUBJECT_DN': 'CN=device1.d.wott-dev.local',
            'HTTP_SSL_CLIENT_VERIFY': 'SUCCESS'
        }
        response = self.client.get(self.url, **headers)
        self.assertEqual(response.status_code, 200)
        self.assertListEqual(response.json(), [])

    def test_get_limited_by_meta_tags(self):
        self.deviceinfo.device_manufacturer = 'Raspberry Pi'
        self.deviceinfo.save(update_fields=['device_manufacturer'])
        response = self.client.get(self.url, **self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertListEqual(response.json(),
                             [{'name': 'name1', 'data': {'key1': 'as9dfyaoiufhoasdfjh'}, 'linux_user': 'nobody',
                               'pk': self.credential.pk,
                               'tags_data': [{'name': 'tag1', 'pk': self.credential.tags.tags[0].pk}]},
                              {'name': 'name2', 'data': {'key2': 'iuoiuoifpojoijccm'}, 'linux_user': '',
                               'pk': self.credential2.pk,
                               'tags_data': [{'name': 'Hardware: Raspberry Pi',
                                              'pk': self.credential2.tags.tags[0].pk}]}])


class MtlsDeviceMetadataViewTest(APITestCase):

    def setUp(self):
        self.url = reverse('mtls-device-metadata')
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.device = Device.objects.create(device_id='device0.d.wott-dev.local', owner=self.user,
                                            tags='tag1', name='the-device-name')
        self.device_info = DeviceInfo.objects.create(
            device=self.device,
            device_manufacturer='Raspberry Pi',
            device_model='Zero v1.2',
            device_metadata={"test": "value"}
        )
        self.headers = {
            'HTTP_SSL_CLIENT_SUBJECT_DN': 'CN=device0.d.wott-dev.local',
            'HTTP_SSL_CLIENT_VERIFY': 'SUCCESS'
        }

    def test_get(self):
        response = self.client.get(self.url, **self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertDictEqual(response.json(), {
            'test': 'value',
            'device_id': 'device0.d.wott-dev.local',
            'manufacturer': 'Raspberry Pi',
            'model': 'Zero v1.2',
            'device-name': 'the-device-name'
        })


class MtlsRenewCertViewTest(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.device = Device.objects.create(device_id='device0.d.wott-dev.local', owner=self.user)
        DeviceInfo.objects.create(device=self.device)
        self.url = reverse('mtls-sign-device-cert-test')
        self.headers = {
            'HTTP_SSL_CLIENT_SUBJECT_DN': 'CN=device0.d.wott-dev.local',
            'HTTP_SSL_CLIENT_VERIFY': 'SUCCESS'
        }
        self.expires = timezone.now() + timezone.timedelta(days=3)
        self.uuid = uuid.uuid4()
        self.post_data = {'device_id': 'device0.d.wott-dev.local', 'csr': 'asdfsdf',
                          'device_operating_system': 'linux',
                          'device_operating_system_version': '2', 'device_architecture': '386', 'fqdn': 'domain.com',
                          'ipv4_address': '192.168.1.15'}

    def test_post_success(self):
        with patch('cfssl.cfssl.CFSSL.sign') as sign, \
                patch('device_registry.ca_helper.get_certificate_expiration_date') as gced, \
                patch('device_registry.ca_helper.csr_is_valid') as civ, \
                patch('uuid.uuid4') as uuid4:
            sign.return_value = '010101'
            gced.return_value = self.expires
            civ.return_value = True
            uuid4.return_value = self.uuid

            self.assertEqual(Device.objects.count(), 1)
            self.assertEqual(DeviceInfo.objects.count(), 1)
            response = self.client.post(self.url, self.post_data, **self.headers)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertDictEqual(response.data, {
                'certificate': '010101',
                'certificate_expires': self.expires,
                'claim_token': self.uuid,
                'fallback_token': self.uuid,
                'claimed': self.device.claimed
            })
            self.assertEqual(Device.objects.count(), 1)
            self.assertEqual(DeviceInfo.objects.count(), 1)

    def test_post_wrong_device_id(self):
        post_data = self.post_data.copy()
        post_data['device_id'] = 'no_such_device'
        self.assertEqual(Device.objects.count(), 1)
        self.assertEqual(DeviceInfo.objects.count(), 1)
        response = self.client.post(self.url, post_data, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data, 'Invalid request.')
        self.assertEqual(Device.objects.count(), 1)
        self.assertEqual(DeviceInfo.objects.count(), 1)

    def test_post_invalid_csr(self):
        with patch('device_registry.ca_helper.csr_is_valid') as civ:
            civ.return_value = False
            response = self.client.post(self.url, self.post_data, **self.headers)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertEqual(response.data, 'Invalid CSR.')
            self.assertEqual(Device.objects.count(), 1)
            self.assertEqual(DeviceInfo.objects.count(), 1)

    def test_post_signing_error(self):
        with patch('device_registry.ca_helper.csr_is_valid') as civ, \
                patch('device_registry.ca_helper.sign_csr') as scsr:
            civ.return_value = True
            scsr.return_value = False
            response = self.client.post(self.url, self.post_data, **self.headers)
            self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
            self.assertEqual(response.data, 'Unknown error')
            self.assertEqual(Device.objects.count(), 1)
            self.assertEqual(DeviceInfo.objects.count(), 1)


class MtlsPingViewTest(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test')
        device_id = 'device0.d.wott-dev.local'
        self.device = Device.objects.create(device_id=device_id, owner=self.user)
        self.gp = GlobalPolicy.objects.create(name='gp1', owner=self.user, policy=GlobalPolicy.POLICY_ALLOW,
                                              ports=[['::', 'udp', 5353, True], ['0.0.0.0', 'udp', 5353, False]],
                                              networks=[['192.168.0.100', False]])
        self.ping_payload = {
            'device_operating_system_version': 'linux',
            'fqdn': 'test-device0',
            'ipv4_address': '127.0.0.1',
            'uptime': '0',
            'scan_info': OPEN_PORTS_INFO,
            'netstat': OPEN_CONNECTIONS_INFO,
            'firewall_rules': TEST_RULES,
            'os_release': {'codename': 'jessie'}
        }
        self.url = reverse('mtls-ping')
        self.headers = {
            'HTTP_SSL_CLIENT_SUBJECT_DN': f'CN={device_id}',
            'HTTP_SSL_CLIENT_VERIFY': 'SUCCESS'
        }

    def test_ping_get(self):
        # Take data from device security settings.
        response = self.client.get(self.url, **self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertDictEqual(response.data, {
            'policy': self.device.firewallstate.policy_string,
            'block_ports': [], 'block_networks': settings.SPAM_NETWORKS,
            'deb_packages_hash': ''
        })
        # Take data from a global policy.
        self.device.firewallstate.global_policy = self.gp
        self.device.firewallstate.save(update_fields=['global_policy'])
        response = self.client.get(self.url, **self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertDictEqual(response.data, {'policy': self.gp.policy_string,
                                             'block_ports': self.gp.ports,
                                             'block_networks': self.gp.networks + settings.SPAM_NETWORKS,
                                             'deb_packages_hash': ''})

    def test_pong_data(self):
        # 1st request
        response = self.client.get(self.url, **self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertDictEqual(response.data, {
            'block_ports': [],
            'block_networks': settings.SPAM_NETWORKS,
            'policy': self.device.firewallstate.policy_string,
            'deb_packages_hash': ''
        })
        # 2nd request
        self.device.portscan.block_ports = [['192.168.1.178', 'tcp', 22, False]]
        self.device.portscan.block_networks = [['192.168.1.177', False]]
        self.device.portscan.save(update_fields=['block_ports', 'block_networks'])
        response = self.client.post(self.url, self.ping_payload, **self.headers)
        self.assertEqual(response.status_code, 200)
        # 3rd request
        response = self.client.get(self.url, **self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertDictEqual(response.data, {
            'policy': self.device.firewallstate.policy_string,
            'block_ports': [['192.168.1.178', 'tcp', 22, False]],
            'block_networks': [['192.168.1.177', False]] + settings.SPAM_NETWORKS,
            'deb_packages_hash': ''
        })

    def test_ping_creates_models(self):
        devinfo_obj_count_before = DeviceInfo.objects.count()
        portscan_obj_count_before = PortScan.objects.count()
        self.client.post(self.url, self.ping_payload, **self.headers)
        devinfo_obj_count_after = DeviceInfo.objects.count()
        portscan_obj_count_after = PortScan.objects.count()
        self.assertEqual(devinfo_obj_count_before, 0)
        self.assertEqual(portscan_obj_count_before, 0)
        self.assertEqual(devinfo_obj_count_after, 1)
        self.assertEqual(portscan_obj_count_after, 1)

    def test_ping_writes_scan_info(self):
        self.client.post(self.url, self.ping_payload, **self.headers)
        portscan = PortScan.objects.get(device=self.device)
        scan_info = portscan.scan_info
        self.assertListEqual(scan_info, OPEN_PORTS_INFO)

    def test_ping_writes_netstat(self):
        self.client.post(self.url, self.ping_payload, **self.headers)
        portscan = PortScan.objects.get(device=self.device)
        netstat = portscan.netstat
        self.assertListEqual(netstat, OPEN_CONNECTIONS_INFO)

    def test_ping_writes_firewall_info_pos(self):
        self.client.post(self.url, self.ping_payload, **self.headers)
        firewall_state = FirewallState.objects.get(device=self.device)
        self.assertDictEqual(firewall_state.rules, TEST_RULES)

    def test_ping_writes_firewall_info_neg(self):
        ping_payload = {
            'device_operating_system_version': 'linux',
            'fqdn': 'test-device0',
            'ipv4_address': '127.0.0.1',
            'uptime': '0',
            'scan_info': OPEN_PORTS_INFO,
            'netstat': OPEN_CONNECTIONS_INFO,
            'firewall_rules': {'INPUT': [], 'OUTPUT': [], 'FORWARD': []}
        }
        self.client.post(self.url, ping_payload, **self.headers)
        firewall_state = FirewallState.objects.get(device=self.device)
        self.assertDictEqual(firewall_state.rules, {'INPUT': [], 'OUTPUT': [], 'FORWARD': []})

    def test_ping_converts_json(self):
        scan_info = [{
            "host": "localhost",
            "port": 22,
            "proto": "tcp",
            "state": "open",
            "ip_version": 4
        }]
        firewall_rules = {'INPUT': [], 'OUTPUT': [], 'FORWARD': []}
        ping_payload = {
            'device_operating_system_version': 'linux',
            'fqdn': 'test-device0',
            'ipv4_address': '127.0.0.1',
            'uptime': '0',
            'scan_info': json.dumps(scan_info),
            'firewall_rules': json.dumps(firewall_rules)
        }

        self.client.post(self.url, ping_payload, **self.headers)
        firewall_state = FirewallState.objects.get(device=self.device)
        portscan = PortScan.objects.get(device=self.device)
        self.assertListEqual(scan_info, portscan.scan_info)
        self.assertDictEqual(firewall_rules, firewall_state.rules)

    def test_ping_writes_trust_score(self):
        scan_info = [{
            "host": "localhost",
            "port": 22,
            "proto": "tcp",
            "state": "open",
            "ip_version": 4
        }]
        firewall_rules = {'INPUT': [], 'OUTPUT': [], 'FORWARD': []}
        ping_payload = {
            'device_operating_system_version': 'linux',
            'fqdn': 'test-device0',
            'ipv4_address': '127.0.0.1',
            'uptime': '0',
            'scan_info': json.dumps(scan_info),
            'firewall_rules': json.dumps(firewall_rules)
        }

        self.client.post(self.url, ping_payload, **self.headers)
        self.device.update_trust_score_now()
        self.assertGreater(self.device.trust_score, 0.42)

    def test_ping_writes_packages(self):
        packages = [{'name': 'PACKAGE', 'version': 'VERSION', 'source_name': 'SOURCE', 'source_version': 'VERSION',
                     'arch': 'all'}]
        self.ping_payload['deb_packages'] = {
            'hash': 'abcdef',
            'packages': packages
        }
        self.client.post(self.url, self.ping_payload, **self.headers)

        response = self.client.get(self.url, **self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertDictEqual(response.data, {
            'block_ports': [],
            'block_networks': settings.SPAM_NETWORKS,
            'policy': self.device.firewallstate.policy_string,
            'deb_packages_hash': 'abcdef'
        })
        self.device.refresh_from_db()
        packages[0]['os_release_codename'] = 'jessie'
        self.assertQuerysetEqual(self.device.deb_packages.all(), packages,
                                 transform=lambda p: {'name': p.name, 'version': p.version,
                                                      'source_name': p.source_name,
                                                      'source_version': p.source_version,
                                                      'arch': p.arch,
                                                      'os_release_codename': p.os_release_codename})


class DeviceEnrollView(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test@test.com')
        self.user.set_password('123')
        self.user.save()
        self.claim_token = uuid.uuid4()
        self.device = Device.objects.create(device_id='device0.d.wott-dev.local', claim_token=self.claim_token)
        self.pairing_key = PairingKey.objects.create(owner=self.user)
        self.url = reverse('enroll_by_key')
        Profile.objects.create(user=self.user)

    def test_post_track(self):
        payload = {
            'key': self.pairing_key.key.hex,
            'device_id': self.device.device_id,
            'claim_token': self.device.claim_token
        }
        settings.MIXPANEL_TOKEN = 'abcd'
        with patch('profile_page.models.Mixpanel') as MockMixpanel:
            mixpanel_instance = MockMixpanel.return_value
            mixpanel_instance.track.return_value = None
            response = self.client.post(self.url, data=payload)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            mixpanel_instance.track.assert_called_once_with(self.user.email, 'First Node')

    def test_post_success(self):
        payload = {
            'key': self.pairing_key.key.hex,
            'device_id': self.device.device_id,
            'claim_token': self.device.claim_token
        }
        self.assertFalse(self.device.claimed)
        response = self.client.post(self.url, data=payload)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, None)
        self.device.refresh_from_db()
        self.assertTrue(self.device.claimed)

    def test_post_fail_on_token(self):
        fail_key = uuid.UUID(int=(self.pairing_key.key.int + 1))
        payload = {
            'key': fail_key.hex,
            'device_id': self.device.device_id,
            'claim_token': self.device.claim_token
        }
        self.assertFalse(self.device.claimed)
        response = self.client.post(self.url, data=payload)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data, {'key': [ErrorDetail(string='Pairnig-token not found', code='invalid')]})
        self.device.refresh_from_db()
        self.assertFalse(self.device.claimed)

    def test_post_fail_on_device_id_and_claim_token(self):
        payload = {
            'key': self.pairing_key.key.hex,
            'device_id': 'incorrect-device.d.wott-dev.local',
            'claim_token': 'incorrect-claim-token'
        }
        response = self.client.post(self.url, data=payload)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        error_data = {
            'non_field_errors': [ErrorDetail(string='Node id and claim token do not match', code='invalid')]
        }
        self.assertEqual(response.data, error_data)

    def test_post_fail_on_insufficient_args(self):
        payload = {}
        response = self.client.post(self.url, data=payload)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        error_data = {
            'device_id': [ErrorDetail(string='This field is required.', code='required')],
            'key': [ErrorDetail(string='This field is required.', code='required')],
            'claim_token': [ErrorDetail(string='This field is required.', code='required')]
        }
        self.assertEqual(response.data, error_data)
        self.assertTrue(PairingKey.objects.filter(key=self.pairing_key.key).exists())

    def test_post_fail_on_foreign_claim_token(self):
        claim_token2 = uuid.uuid4()
        device2 = Device.objects.create(device_id='device2.d.wott-dev.local', claim_token=claim_token2)
        payload = {
            'key': self.pairing_key.key.hex,
            'device_id': self.device.device_id,
            'claim_token': device2.claim_token
        }
        response = self.client.post(self.url, data=payload)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        error_data = {
            'non_field_errors': [ErrorDetail(string='Node id and claim token do not match', code='invalid')]
        }
        self.assertEqual(response.data, error_data)
        self.assertTrue(PairingKey.objects.filter(key=self.pairing_key.key).exists())


class PairingKeyListViewTest(APITestCase):

    def setUp(self):
        self.url = reverse('ajax_pairing_keys')
        User = get_user_model()
        self.user = User.objects.create_user('test', password='123')
        self.client.login(username='test', password='123')
        self.key1 = PairingKey.objects.create(owner=self.user, comment="1")
        self.key2 = PairingKey.objects.create(owner=self.user, comment="2")
        self.key3 = PairingKey.objects.create(owner=User.objects.create_user('test1', password='123'))

    def test_get(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = [
            OrderedDict(
                [('key', self.key1.key.__str__()), ('created', self.key1.created.strftime('%Y-%m-%d %H:%M:%S')),
                 ('comment', self.key1.comment)]
            ), OrderedDict(
                [('key', self.key2.key.__str__()), ('created', self.key2.created.strftime('%Y-%m-%d %H:%M:%S')),
                 ('comment', self.key2.comment)]
            )
        ]
        self.assertListEqual(response.data, data)


class DeletePairingKeyViewTest(APITestCase):

    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test', password='123')
        self.client.login(username='test', password='123')
        self.key1 = PairingKey.objects.create(owner=self.user)
        self.url = reverse('ajax_pairing_keys_delete', kwargs={'pk': self.key1.pk})

    def test_delete(self):
        self.assertEqual(PairingKey.objects.count(), 1)
        response = self.client.delete(self.url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(PairingKey.objects.count(), 0)


class CreatePairingKeyViewTest(APITestCase):

    def setUp(self):
        self.url = reverse('ajax_pairing_keys_create')
        User = get_user_model()
        self.user = User.objects.create_user('test', password='123')
        self.client.login(username='test', password='123')
        self.data = {}

    def test_post(self):
        self.assertEqual(PairingKey.objects.count(), 0)
        response = self.client.post(self.url, self.data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(PairingKey.objects.count(), 1)
        self.key1 = PairingKey.objects.get(owner=self.user)
        data = {'key': self.key1.key.__str__(), 'created': self.key1.created.strftime('%Y-%m-%d %H:%M:%S'),
                'comment': self.key1.comment}
        self.assertDictEqual(data, response.data)


class UpdatePairingKeyViewTest(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test', password='123')
        self.key1 = PairingKey.objects.create(owner=self.user)
        self.key2 = PairingKey.objects.create(owner=User.objects.create_user('test1', password='123'))
        self.url = reverse('ajax_pairing_keys_update', kwargs={'pk': self.key1.pk})
        self.url2 = reverse('ajax_pairing_keys_update', kwargs={'pk': self.key2.pk})
        self.client.login(username='test', password='123')
        self.data = {'comment': 'test comment'}

    def test_patch(self):
        self.assertEqual(PairingKey.objects.count(), 2)
        response = self.client.patch(self.url, data=self.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertDictEqual(response.data, self.data)
        self.assertEqual(PairingKey.objects.count(), 2)

    def test_patch_foreign_token(self):
        # check for deny to update with duplicate Name/Key/File owner combination
        self.assertEqual(PairingKey.objects.count(), 2)
        response = self.client.patch(self.url2, data=self.data)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertDictEqual(response.data, {'detail': ErrorDetail(string='Not found.', code='not_found')})
        self.assertEqual(PairingKey.objects.count(), 2)


class GetBatchActionsViewTest(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test', password='123')
        self.client.login(username='test', password='123')
        self.url = reverse('get_batch_list', kwargs={'model_name': 'device'})
        self.bla_url = reverse('get_batch_list', kwargs={'model_name': 'blabla'})

    def test_device(self):
        response = self.client.get(self.url)
        args_control = '<input type="text" name="batch_{name}" id="batch_{name}" action_name="{name}" ' \
                       'data-tagulous data-tag-url="/ajax/tags/autocomplete/" autocomplete="off" style="width:100%;" >'
        js_get = 'function(el){\n' \
                 '            let tags=[];\n' \
                 '            Tagulous.parseTags( el.val(), true, false ).forEach( function (tag) {\n' \
                 '                tags.push({ "name" : tag  })\n' \
                 '            });\n' \
                 '            return tags;\n' \
                 '          }'

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        actions = [{'object': 'device', 'subject': 'Tags', 'name': 'add', 'display_name': 'Add Tags',
                    'args_control': args_control.format(name='add'),
                    'js_postprocess': 'function(el){Tagulous.select2(el);}',
                    'js_get': js_get,
                    'url': '/ajax-batch/apply/device/tags/'},
                   {'object': 'device', 'subject': 'Tags', 'name': 'set', 'display_name': 'Set Tags',
                    'args_control': args_control.format(name='set'),
                    'js_postprocess': 'function(el){Tagulous.select2(el);}',
                    'js_get': js_get,
                    'url': '/ajax-batch/apply/device/tags/'}]

        self.assertListEqual(actions, response.json())

    def test_blabla(self):
        response = self.client.get(self.bla_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertListEqual([], response.json())


class BatchUpdateTagsViewTest(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test', password='123')
        self.client.login(username='test', password='123')
        self.url = reverse('tags_batch', kwargs={'model_name': 'device'})
        self.device = Device.objects.create(device_id='device0.d.wott-dev.local', owner=self.user, tags='tag1,tag2')
        self.device1 = Device.objects.create(device_id='device1.d.wott-dev.local', owner=self.user, tags='tag1,tag2')
        self.device2 = Device.objects.create(device_id='device2.d.wott-dev.local', owner=self.user, tags='tag1,tag2')

    def test_set_ok(self):
        data = {'action': 'set', 'objects': [{'pk': self.device.pk}, {'pk': self.device2.pk}],
                'args': [{'name': 'tag2'}, {'name': 'tag3'}, {'name': 'tag4'}]}
        response = self.client.post(self.url, data=data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        msg = f"Set tags to 2 devices."
        self.assertEqual(response.data, msg)
        self.assertEqual(Device.objects.get(pk=self.device.pk).tags.__str__(), "tag2, tag3, tag4")
        self.assertEqual(Device.objects.get(pk=self.device1.pk).tags.__str__(), "tag1, tag2")
        self.assertEqual(Device.objects.get(pk=self.device2.pk).tags.__str__(), "tag2, tag3, tag4")

    def test_add_ok(self):
        data = {'action': 'add', 'objects': [{'pk': self.device.pk}, {'pk': self.device2.pk}],
                'args': [{'name': 'tag2'}, {'name': 'tag3'}, {'name': 'tag4'}]}
        response = self.client.post(self.url, data=data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        msg = f"Added tags to 2 devices."
        self.assertEqual(response.data, msg)
        self.assertEqual(Device.objects.get(pk=self.device.pk).tags.__str__(), "tag1, tag2, tag3, tag4")
        self.assertEqual(Device.objects.get(pk=self.device1.pk).tags.__str__(), "tag1, tag2")
        self.assertEqual(Device.objects.get(pk=self.device2.pk).tags.__str__(), "tag1, tag2, tag3, tag4")

    def test_invalid_action(self):
        data = {'action': 'unknown', 'objects': [{'pk': self.device.pk}, {'pk': self.device2.pk}],
                'args': [{'name': 'tag2'}, {'name': 'tag3'}, {'name': 'tag4'}]}
        response = self.client.post(self.url, data=data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json(), {'action': ['Invalid argument']})

    def test_invalid_device(self):
        data = {'action': 'set', 'objects': [{'pk': self.device.pk}, {'pk': self.device2.pk + 100}],
                'args': [{'name': 'tag2'}, {'name': 'tag3'}, {'name': 'tag4'}]}
        response = self.client.post(self.url, data=data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json(), {'non_field_errors': ['Invalid argument']})

    def test_foreign_device(self):
        User = get_user_model()
        user2 = User.objects.create_user('test2', password='123')
        device3 = Device.objects.create(device_id='device3.d.wott-dev.local', owner=user2, tags='tag1,tag2')
        data = {'action': 'set', 'objects': [{'pk': self.device.pk}, {'pk': device3.pk}],
                'args': [{'name': 'tag2'}, {'name': 'tag3'}, {'name': 'tag4'}]}
        response = self.client.post(self.url, data=data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json(), {'non_field_errors': ['Invalid argument']})


class DeviceListAjaxViewTest(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()

        self.device0 = Device.objects.create(
            device_id='device0.d.wott-dev.local',
            owner=self.user,
            certificate=TEST_CERT,
            name='First',
            last_ping=timezone.now() - datetime.timedelta(days=1, hours=1)
        )
        self.deviceinfo0 = DeviceInfo.objects.create(
            device=self.device0,
            fqdn='FirstFqdn',
            default_password=False,
        )

        self.device1 = Device.objects.create(
            device_id='device1.d.wott-dev.local',
            owner=self.user,
            certificate=TEST_CERT,
            last_ping=timezone.now() - datetime.timedelta(days=2, hours=23)
        )
        self.deviceinfo1 = DeviceInfo.objects.create(
            device=self.device1,
            fqdn='SecondFqdn',
            default_password=True,
        )
        self.device2 = Device.objects.create(
            device_id='device2.d.wott-dev.local',
            owner=self.user,
            certificate=TEST_CERT,
            last_ping=timezone.now() - datetime.timedelta(days=2, hours=23)
        )
        self.deviceinfo2 = DeviceInfo.objects.create(
            device=self.device2,
            fqdn='ThirdFqdn',
            default_password=True,
        )

    def _dev_list_item(self, device):
        serializer = DeviceListSerializer(instance=device)
        return serializer.data

    def _dev_list_data(self, lst, total=3, draw='-', length=None):
        data = [self._dev_list_item(dev) for dev in lst]
        return {'data': data, 'draw': draw, 'recordsTotal': total,
                'recordsFiltered': len(lst) if length is None else length}

    def _filter_url(self, by, predicate, value):
        return reverse('ajax_device_list') + '?' + urlencode({
            'filter_by': by,
            'filter_predicate': predicate,
            'filter_value': value
        })

    def test_no_filter(self):
        self.client.login(username='test', password='123')
        url = reverse('ajax_device_list')
        response = self.client.get(url)
        self.assertDictEqual(response.data, self._dev_list_data([self.device0, self.device1, self.device2]))

    def test_filter_date(self):
        self.client.login(username='test', password='123')

        url = self._filter_url('last-ping', 'eq', '1,days')
        response = self.client.get(url)
        self.assertDictEqual(response.data, self._dev_list_data([self.device0]))

        url = self._filter_url('last-ping', 'eq', '2,days')
        response = self.client.get(url)
        self.assertDictEqual(response.data, self._dev_list_data([self.device1, self.device2]))

        url = self._filter_url('last-ping', 'lt', '1,days')
        response = self.client.get(url)
        self.assertDictEqual(response.data, self._dev_list_data([self.device0, self.device1, self.device2]))

        url = self._filter_url('last-ping', 'gt', '1,days')
        response = self.client.get(url)
        self.assertDictEqual(response.data, self._dev_list_data([]))

    def test_filter_name(self):
        self.client.login(username='test', password='123')

        url = self._filter_url('device-name', 'eq', 'first')
        response = self.client.get(url)
        self.assertDictEqual(response.data, self._dev_list_data([self.device0]))

        url = self._filter_url('device-name', 'eq', 'firstfqdn')
        response = self.client.get(url)
        self.assertDictEqual(response.data, self._dev_list_data([self.device0]))

        url = self._filter_url('device-name', 'neq', 'firstfqdn')
        response = self.client.get(url)
        self.assertDictEqual(response.data, self._dev_list_data([self.device1, self.device2]))

        url = self._filter_url('device-name', 'c', 'fir')
        response = self.client.get(url)
        self.assertDictEqual(response.data, self._dev_list_data([self.device0]))

        url = self._filter_url('device-name', 'nc', 'fir')
        response = self.client.get(url)
        self.assertDictEqual(response.data, self._dev_list_data([self.device1, self.device2]))

    def test_datatables(self):
        self.client.login(username='test', password='123')

        url = reverse('ajax_device_list') + '?' + urlencode({'length': 2})
        response = self.client.get(url)
        self.assertDictEqual(response.data, self._dev_list_data([self.device0, self.device1], length=3))

        url = reverse('ajax_device_list') + '?' + urlencode({'start': 1})
        response = self.client.get(url)
        self.assertDictEqual(response.data, self._dev_list_data([self.device1, self.device2], length=3))

        url = reverse('ajax_device_list') + '?' + urlencode({'start': 1, 'length': 1})
        response = self.client.get(url)
        self.assertDictEqual(response.data, self._dev_list_data([self.device1], length=3))


class PolicyDeviceNumberViewTests(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test', password='123')
        self.gp = GlobalPolicy.objects.create(name='gp1', owner=self.user, policy=GlobalPolicy.POLICY_ALLOW)
        self.url = reverse('ajax_policy_device_nr', kwargs={'pk': self.gp.pk})

    def test_get(self):
        self.client.login(username='test', password='123')
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertDictEqual(response.data, {'devices_nr': 0})
        device = Device.objects.create(device_id='device0.d.wott-dev.local', owner=self.user)
        FirewallState.objects.create(device=device, global_policy=self.gp)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertDictEqual(response.data, {'devices_nr': 1})

    def test_get_404(self):
        User = get_user_model()
        user2 = User.objects.create_user('test2', password='123')
        gp2 = GlobalPolicy.objects.create(name='gp2', owner=user2, policy=GlobalPolicy.POLICY_ALLOW)
        self.client.login(username='test', password='123')
        response = self.client.get(reverse('ajax_policy_device_nr', kwargs={'pk': gp2.pk}))
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class SnoozeActionViewTest(APITestCase):

    def setUp(self):
        self.url = reverse('snooze_action')
        self.action_class = DefaultCredentialsAction
        User = get_user_model()
        self.user = User.objects.create_user('test', password='123')
        self.device = Device.objects.create(device_id='device0.d.wott-dev.local', owner=self.user)
        DeviceInfo.objects.create(device=self.device, default_password=True)
        PortScan.objects.create(device=self.device)
        FirewallState.objects.create(device=self.device)
        self.client.login(username='test', password='123')
        self.device.generate_recommended_actions()

    def test_snooze_until_ping(self):
        self.assertEqual(self.device.recommendedaction_set.get(
            action_id=self.action_class.action_id).status, RecommendedAction.Status.AFFECTED)
        self.assertEqual(self.device.actions_count, 2)
        # 'duration': None means "snooze until ping"
        response = self.client.post(self.url, {'device_ids': [self.device.pk],
                                               'action_id': self.action_class.action_id,
                                               'duration': None})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.device.refresh_from_db()
        actions = self.device.recommendedaction_set.filter(action_id=self.action_class.action_id)
        self.assertQuerysetEqual(actions.values_list('action_id', flat=True), [str(self.action_class.action_id)])
        self.assertEqual(actions[0].status, RecommendedAction.Status.SNOOZED_UNTIL_PING)
        self.assertEqual(self.device.actions_count, 1)

    def test_snooze_forever(self):
        self.assertEqual(self.device.recommendedaction_set.get(
            action_id=self.action_class.action_id).status, RecommendedAction.Status.AFFECTED)
        self.assertEqual(self.device.actions_count, 2)
        # 'duration': 0 means "snooze forever"
        response = self.client.post(self.url, {'device_ids': [self.device.pk],
                                               'action_id': self.action_class.action_id,
                                               'duration': 0})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.device.refresh_from_db()
        actions = self.device.recommendedaction_set.filter(action_id=self.action_class.action_id)
        self.assertQuerysetEqual(actions.values_list('action_id', flat=True), [str(self.action_class.action_id)])
        self.assertEqual(self.device.recommendedaction_set.get(
            action_id=self.action_class.action_id).status, RecommendedAction.Status.SNOOZED_FOREVER)
        self.assertEqual(self.device.actions_count, 1)

    def test_snooze_until_time(self):
        self.assertEquals(self.device.recommendedaction_set.get(
            action_id=self.action_class.action_id).status, RecommendedAction.Status.AFFECTED)
        self.assertEqual(self.device.actions_count, 2)

        # Snooze for 7 hours
        response = self.client.post(self.url, {'device_ids': [self.device.pk],
                                               'action_id': self.action_class.action_id,
                                               'duration': 7})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.device.refresh_from_db()
        actions = self.device.recommendedaction_set.filter(action_id=self.action_class.action_id)
        self.assertQuerysetEqual(actions.values_list('action_id', flat=True), [str(self.action_class.action_id)])
        ra = self.device.recommendedaction_set.get(action_id=self.action_class.action_id)

        self.assertEqual(ra.status, RecommendedAction.Status.SNOOZED_UNTIL_TIME)
        # Should be snoozed for at least 6 hours from now. It's actually 7 hours minus a couple seconds.
        self.assertGreaterEqual((ra.snoozed_until - timezone.now()).total_seconds() // 3600, 6)

        self.assertEqual(self.device.actions_count, 1)

    def test_wrong_action_id(self):
        self.assertEqual(self.device.recommendedaction_set.get(
            action_id=self.action_class.action_id).status, RecommendedAction.Status.AFFECTED)
        action_id = 9999
        self.assertFalse(ActionMeta.is_action_id(action_id))
        response = self.client.post(self.url, {'device_ids': [self.device.pk],
                                               'action_id': action_id,
                                               'duration': None})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(response.data, {'action_id': [ErrorDetail(string='Invalid recommended action id',
                                                                       code='invalid')]})
        self.assertEqual(self.device.recommendedaction_set.get(
            action_id=self.action_class.action_id).status, RecommendedAction.Status.AFFECTED)

    def test_wrong_device_id(self):
        self.assertEqual(self.device.recommendedaction_set.get(
            action_id=self.action_class.action_id).status, RecommendedAction.Status.AFFECTED)
        response = self.client.post(self.url, {'device_ids': [self.device.pk + 1],
                                               'action_id': self.action_class.action_id,
                                               'duration': None})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(response.data, {'device_ids': [ErrorDetail(string='Invalid device id(s) provided',
                                                                        code='invalid')]})
        self.assertEqual(self.device.recommendedaction_set.get(
            action_id=self.action_class.action_id).status, RecommendedAction.Status.AFFECTED)

    def test_wrong_duration(self):
        self.assertEqual(self.device.recommendedaction_set.get(
            action_id=self.action_class.action_id).status, RecommendedAction.Status.AFFECTED)
        response = self.client.post(self.url, {'device_ids': [self.device.pk],
                                               'action_id': self.action_class.action_id,
                                               'duration': -1})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(response.data, {'duration': [
            ErrorDetail(string='Ensure this value is greater than or equal to 0.', code='min_value')]})
        self.assertEqual(self.device.recommendedaction_set.get(
            action_id=self.action_class.action_id).status, RecommendedAction.Status.AFFECTED)
