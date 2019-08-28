from django.urls import path

from .views import CeleryPulseTimestampView

urlpatterns = [
    path('celery/', CeleryPulseTimestampView.as_view(), name='celery_pulse')
]
