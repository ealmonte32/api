from django.urls import path

from .views import CeleryPulseTimestampView, ErrorView

urlpatterns = [
    path('celery/', CeleryPulseTimestampView.as_view(), name='celery_pulse'),
    path('error/', ErrorView.as_view(), name='error')
]
