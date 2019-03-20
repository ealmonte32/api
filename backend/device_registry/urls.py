from django.conf import settings
from django.urls import path
from device_registry import views, api_views
from rest_framework.schemas import get_schema_view

schema_view = get_schema_view(title='WoTT API')
api_version = 'v0.2'

urlpatterns = []

# API
if settings.IS_API:
    urlpatterns += [
        path('api/{}/list-devices'.format(api_version),
             api_views.device_list_view),
        path('api/{}/ca-bundle'.format(api_version),
             api_views.get_ca_bundle_view,
             name='get-ca-bundle'),
        path('api/{}/ca'.format(api_version),
             api_views.get_ca_view,
             name='get-ca'),
        path('api/{}/generate-id'.format(api_version),
             api_views.generate_device_id_view,
             name='get-device-id'),
        path('api/{}/device-cert/<str:device_id>'.format(api_version),
             api_views.get_device_cert_view,
             name='get-device-cert'),
        path('api/{}/sign-csr'.format(api_version),
             api_views.sign_new_device_view,
             name='sign-device-cert'),
        path('api/{}/claim-device'.format(api_version),
             api_views.claim_by_link,
             name='claim-by-link'),
    ]

# Only load if mTLS
if settings.IS_MTLS_API:
    urlpatterns += [
        path('api/{}/sign-csr'.format(api_version),
             api_views.mtls_renew_cert_view,
             name='mtls-sign-device-cert'),
        path('api/{}/ping'.format(api_version),
             api_views.mtls_ping_view,
             name='mtls-ping'),
        path('api/{}/hello'.format(api_version),
             api_views.mtls_tester_view,
             name='mtls-tester'),
        path('api/{}/hello'.format(api_version),
             api_views.mtls_tester_view,
             name='mtls-tester'),
        path('api/{}/action/<int:action_id>/<str:action_name>'.format(api_version),
             api_views.action_view, name='action')
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
        path('profile/', views.profile_view, name='profile'),
        path('actions/', views.actions_view, name='actions'),
    ]
