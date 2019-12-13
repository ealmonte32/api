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
        path('api/{}/enroll-device'.format(api_version), api_views.DeviceEnrollView.as_view(), name='enroll_by_key'),
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

        path('api/{}/credentials'.format(api_version), api_views.MtlsCredsView.as_view(), name='mtls-credentials'),
        path('api/{}/device-metadata'.format(api_version), api_views.MtlsDeviceMetadataView.as_view(),
             name='mtls-device-metadata'),

        # TODO: deprecated names should be removed later (/creds, /dev-md)  2019-08-26:
        path('api/{}/creds'.format(api_version), api_views.MtlsCredsView.as_view(), name='mtls-credentials'),
        path('api/{}/dev-md'.format(api_version), api_views.MtlsDeviceMetadataView.as_view(),
             name='mtls-device-metadata')
    ]

# Front-end
if settings.IS_DASH or settings.IS_CELERY:
    urlpatterns += [
        path('', views.DashboardView.as_view(), name='dashboard'),
        path('nodes/', views.RootView.as_view(), name='root'),
        path('policies/', views.GlobalPoliciesListView.as_view(), name='global_policies'),
        path('policies/add/', views.GlobalPolicyCreateView.as_view(), name='create_global_policy'),
        path('policies/<int:pk>/', views.GlobalPolicyEditView.as_view(), name='edit_global_policy'),
        path('policies/<int:pk>/delete/', views.GlobalPolicyDeleteView.as_view(), name='delete_global_policy'),
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
        path('devices/<int:pk>/security/', views.DeviceDetailSecurityView.as_view(),
             name='device-detail-security'),
        path('devices/<int:pk>/security/save-as-policy/', views.GlobalPolicyCreateView.as_view(),
             name='save_as_policy'),
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
        path('ajax-credentials/', api_views.CredentialsView.as_view(), name='ajax-credentials'),
        path('ajax-credentials/<int:pk>/delete/', api_views.DeleteCredentialView.as_view(),
             name='ajax-credentials-delete'),
        path('ajax-credentials/<int:pk>/update/', api_views.UpdateCredentialView.as_view(),
             name='ajax-credentials-update'),
        path('ajax-credentials/create/', api_views.CreateCredentialView.as_view(), name='ajax-credentials-create'),
        path('ajax-policies/<int:pk>/device-nr/', api_views.PolicyDeviceNumberView.as_view(),
             name='ajax_policy_device_nr'),
        path('actions/', views.RecommendedActionsView.as_view(), name='actions'),
        path('devices/<int:pk>/actions/', views.RecommendedActionsView.as_view(), name='device_actions'),
        path('cve/', views.CVEView.as_view(), name='cve'),
        path('devices/<int:device_pk>/cve/', views.CVEView.as_view(), name='device_cve'),
        path('ajax/tags/autocomplete/', api_views.autocomplete_tags, name='ajax-tags-autocomplete'),
        path('pairing-keys/',
             views.PairingKeysView.as_view(),
             name='pairing-keys'),
        path('pairing-keys/download',
             views.PairingKeySaveFileView.as_view(),
             name='pairing-keys-download'),
        path('ajax-pairing-keys/', api_views.PairingKeyListView.as_view(), name='ajax_pairing_keys'),
        path('ajax-pairing-keys/create/', api_views.CreatePairingKeyView.as_view(), name='ajax_pairing_keys_create'),
        path(
            'ajax-pairing-keys/<uuid:pk>/delete/',
            api_views.DeletePairingKeyView.as_view(),
            name='ajax_pairing_keys_delete'
        ),
        path(
            'ajax-pairing-keys/<uuid:pk>/update/',
            api_views.UpdatePairingKeyView.as_view(),
            name='ajax_pairing_keys_update'
        ),
        path('ajax-pairing-keys/add_dev/', api_views.InstallInstructionKeyView.as_view(),
             name='ajax_install_instruction'),
        path('devices/device-cert/<str:device_id>/', api_views.DeviceCertView.as_view(), name='download_device_cert'),
        path('ajax-batch/list/<str:model_name>/', api_views.GetBatchActionsView.as_view(), name='get_batch_list'),
        path('ajax-batch/apply/<str:model_name>/tags/', api_views.BatchUpdateTagsView.as_view(), name='tags_batch'),
        path('ajax-devices/list/', api_views.DeviceListAjaxView.as_view(), name='ajax_device_list'),
        path('snooze-action/', api_views.SnoozeActionView.as_view(), name='snooze_action')
    ]
