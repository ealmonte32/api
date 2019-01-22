from django.urls import path
from rest_framework.routers import DefaultRouter
from device_registry import views
from rest_framework.schemas import get_schema_view

schema_view = get_schema_view(title='WoTT API')
api_version = 'v0.2'

# Create a router and register our viewsets with it.
#router = DefaultRouter()
#router.register(r'device_registry', views.DeviceViewSet)

urlpatterns = [
    path('api/{}/list-devices'.format(api_version),
         views.device_list_view),
    path('api/{}/ca'.format(api_version),
         views.get_ca_view,
         name='get-ca'),
    path('api/{}/generate-id'.format(api_version),
         views.generate_device_id_view,
         name='get-device-id'),
    path('api/{}/device-cert/<str:device_id>'.format(api_version),
         views.get_device_cert_view,
         name='get-device-cert'),
    path('api/{}/sign-csr'.format(api_version),
         views.sign_new_device_view,
         name='sign-device-cert'),
    path('api/{}/mtls/sign-csr'.format(api_version),
         views.mtls_renew_cert_view,
         name='mtls-sign-device-cert'),
]

#urlpatterns += router.urls
