from collections import OrderedDict
import uuid
from unittest.mock import patch, mock_open

from django.urls import reverse
from django.utils import timezone
from django.contrib.auth import get_user_model

from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework import serializers
from rest_framework.exceptions import ErrorDetail

from device_registry.models import Credential, Device, DeviceInfo, Tag

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
        self.device = Device.objects.create(device_id='device0.d.wott-dev.local', owner=self.user, tags='tag1,tag2')
        self.device_info = DeviceInfo.objects.create(
            device=self.device,
            device_manufacturer='Raspberry Pi',
            device_model='900092',
            selinux_state={'enabled': True, 'mode': 'enforcing'},
            app_armor_enabled=True,
            logins={'pi': {'failed': 1, 'success': 1}}
        )
        self.tags = self.device.tags.tags
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
                                                               ('owner', self.user.id),
                                                               ('tags', [self.tags[0].pk, self.tags[1].pk])
                                                              ]
                                                          )),
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
        self.credential = Credential.objects.create(owner=self.user, name='name1', key='key1', value='value1',
                                                    tags="tag1,tag2")
        self.tags = self.credential.tags.tags;
        self.client.login(username='test', password='123')

    def test_get(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertDictEqual(response.data, {'data': [OrderedDict(
            [('name', 'name1'), ('key', 'key1'), ('value', 'value1'), ('pk', self.credential.pk),
             ('tags', [OrderedDict([('name', 'tag1'), ('pk', self.tags[0].pk)]),
                       OrderedDict([('name', 'tag2'), ('pk', self.tags[1].pk)])])])]})


class DeleteCredentialViewTest(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()
        self.credential = Credential.objects.create(owner=self.user, name='name1', key='key1', value='value1',
                                                    tags="tag1,tag2")
        self.url = reverse('ajax_creds_delete', kwargs={'pk': self.credential.pk})
        self.client.login(username='test', password='123')

    def test_delete(self):
        self.assertEqual(Credential.objects.count(), 1)
        response = self.client.delete(self.url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(Credential.objects.count(), 0)
        self.assertEqual(Tag.objects.count(), 0)


class UpdateCredentialViewTest(APITestCase, AssertTaggedMixin):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()
        self.credential1 = Credential.objects.create(owner=self.user, name='name1', key='key1', value='value1')
        self.url = reverse('ajax_creds_update', kwargs={'pk': self.credential1.pk})
        self.client.login(username='test', password='123')
        self.data = {'name': 'name2', 'key': 'key2', 'value': 'value2', 'tags': [{'name': 'tag1'}, {'name': 'tag2'}]}

    def test_patch(self):
        self.assertEqual(Credential.objects.count(), 1)
        response = self.client.patch(self.url, self.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTaggedEqual(response.data, self.data)
        self.assertEqual(Credential.objects.count(), 1)

    def test_patch_duplication(self):
        # check for deny to update with duplicate Name/Key combo
        self.assertEqual(Credential.objects.count(), 1)
        credential2 = Credential.objects.create(owner=self.user, name='name2', key='key2', value='value2')
        self.assertEqual(Credential.objects.count(), 2)
        response = self.client.patch(self.url, self.data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(response.data, {'error': 'Name/Key combo should be unique'})
        self.assertEqual(Credential.objects.count(), 2)
        # check for update the record itself
        url2 = reverse('ajax_creds_update', kwargs={'pk': credential2.pk})
        response = self.client.patch(url2, self.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTaggedEqual(response.data, self.data)
        self.assertEqual(Credential.objects.count(), 2)




class CreateCredentialViewTest(APITestCase, AssertTaggedMixin):

    def setUp(self):
        self.url = reverse('ajax_creds_create')
        User = get_user_model()
        self.user = User.objects.create_user('test')
        self.user.set_password('123')
        self.user.save()
        self.client.login(username='test', password='123')
        self.data = {'name': 'name1', 'key': 'key1', 'value': 'value1', 'tags': [{'name': 'tag1'}, {'name': 'tag2'}]}

    def test_post(self):
        self.assertEqual(Credential.objects.count(), 0)
        response = self.client.post(self.url, self.data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTaggedEqual(response.data, self.data)
        self.assertEqual(Credential.objects.count(), 1)

    def test_post_duplication(self):
        self.assertEqual(Credential.objects.count(), 0)
        Credential.objects.create(owner=self.user, name='name1', key='key1', value='value3')
        self.assertEqual(Credential.objects.count(), 1)
        response = self.client.post(self.url, self.data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertDictEqual(response.data, {'error': 'Name/Key combo should be unique'})
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
