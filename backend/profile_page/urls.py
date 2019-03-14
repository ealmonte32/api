from django.conf import settings
from django.urls import path
from backend.profile_page import views

urlpatterns = []


if settings.IS_DASH:
    urlpatterns += [
        path('',
             views.root_view,
             name='root'),
        path('claim-device/',
             views.claim_device_view,
             name='claim-device'),
        path('devices/', views.DeviceListView.as_view(), name='device-list'),
        path(
            'devices/<int:pk>/',
            views.DeviceDetailView.as_view(),
            name='device-detail'
        ),
    ]
