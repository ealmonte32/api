from django.conf import settings
from django.urls import path

from rest_framework.schemas import get_schema_view

from device_registry import views, api_views


schema_view = get_schema_view(title='WoTT API')
api_version = 'v0.2'

urlpatterns = []

# API
if settings.IS_API:
    urlpatterns += [
        path('api/{}/list-devices'.format(api_version), api_views.DeviceListView.as_view(), name='list_devices'),
        path('api/{}/ca-bundle'.format(api_version), api_views.CABundleView.as_view(), name='get_ca_bundle'),
        path('api/{}/ca'.format(api_version), api_views.CACertView.as_view(), name='get_ca'),
        path('api/{}/generate-id'.format(api_version), api_views.DeviceIDView.as_view(), name='get_device_id'),
        path('api/{}/device-cert/<str:device_id>'.format(api_version), api_views.DeviceCertView.as_view(),
             name='get_device_cert'),
        path('api/{}/sign-csr'.format(api_version), api_views.SignNewDeviceView.as_view(), name='sign_device_cert'),
        path('api/{}/sign-expired-csr'.format(api_version), api_views.RenewExpiredCertView.as_view(),
             name='sign_expired_cert'),
        path('api/{}/claim-device'.format(api_version), api_views.ClaimByLink.as_view(), name='claim_by_link'),
    ]

# Only load if mTLS
if settings.IS_MTLS_API:
    urlpatterns += [
        path('api/{}/sign-csr'.format(api_version),  # TODO: change to some unique path.
             api_views.MtlsRenewCertView.as_view(),
             name='mtls-sign-device-cert'),
        # Only for tests! We need it because of IS_API and IS_MTLS_API url duplication.
        path('api/{}/sign-csr-test'.format(api_version),
             api_views.MtlsRenewCertView.as_view(),
             name='mtls-sign-device-cert-test'),
        path('api/{}/ping'.format(api_version), api_views.MtlsPingView.as_view(), name='mtls-ping'),
        path('api/{}/hello'.format(api_version), api_views.MtlsTesterView.as_view(), name='mtls-tester'),
        path('api/{}/action/<int:action_id>/<str:action_name>'.format(api_version), api_views.ActionView.as_view(),
             name='action'),
        path('api/{}/claimed'.format(api_version), api_views.IsDeviceClaimedView.as_view(), name='mtls-is_claimed'),
        path('api/{}/creds'.format(api_version), api_views.MtlsCredsView.as_view(), name='mtls-creds'),
        path('api/{}/dev-md'.format(api_version), api_views.MtlsDeviceMetadataView.as_view(), name='mtls-dev-md')
    ]

# Front-end
if settings.IS_DASH:
    urlpatterns += [
        path('',
             views.root_view,
             name='root'),
        path('claim-device/',
             views.claim_device_view,
             name='claim-device'),
        path(
            'devices/<int:pk>/',
            views.DeviceDetailView.as_view(),
            name='device-detail'
        ),
        path(
            'devices/<int:pk>/software/',
            views.DeviceDetailSoftwareView.as_view(),
            name='device-detail-software'
        ),
        path(
            'devices/<int:pk>/security/',
            views.DeviceDetailSecurityView.as_view(),
            name='device-detail-security'
        ),
        path(
            'devices/<int:pk>/network/',
            views.DeviceDetailNetworkView.as_view(),
            name='device-detail-network'
        ),
        path(
            'devices/<int:pk>/hardware/',
            views.DeviceDetailHardwareView.as_view(),
            name='device-detail-hardware'
        ),
        path(
            'devices/<int:pk>/metadata/',
            views.DeviceDetailMetadataView.as_view(),
            name='device-detail-metadata'
        ),
        path('credentials/',
             views.CredentialsView.as_view(),
             name='credentials'),
        path('ajax-creds/', api_views.CredentialsView.as_view(), name='ajax_creds'),
        path('ajax-creds/<int:pk>/delete/', api_views.DeleteCredentialView.as_view(), name='ajax_creds_delete'),
        path('ajax-creds/<int:pk>/update/', api_views.UpdateCredentialView.as_view(), name='ajax_creds_update'),
        path('ajax-creds/create/', api_views.CreateCredentialView.as_view(), name='ajax_creds_create'),
        path('actions/', views.actions_view, name='actions'),
        path('devices/<int:device_pk>/actions/', views.actions_view, name='device_actions'),
        path(
             'ajax/tags/autocomplete/',
             api_views.autocomplete_tags,
             name='ajax-tags-autocomplete',
        ),
        path('devices/device-cert/<str:device_id>/', api_views.DeviceCertView.as_view(), name='download_device_cert')
    ]
