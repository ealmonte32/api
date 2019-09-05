from django.http import HttpResponse
from django.views.generic import View
from django.contrib.auth.mixins import AccessMixin, LoginRequiredMixin

from .models import CeleryPulseTimestamp


class StaffuserRequiredMixin(AccessMixin):
    """Verify that the current user has `is_staff` set to True."""

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_staff:
            return self.handle_no_permission()
        return super().dispatch(request, *args, **kwargs)


class CeleryPulseTimestampView(LoginRequiredMixin, StaffuserRequiredMixin, View):

    def get(self, request, *args, **kwargs):
        pulse_obj = CeleryPulseTimestamp.objects.order_by('id').first()
        return HttpResponse(str(pulse_obj.timestamp) if pulse_obj else 'None', content_type='text/plain')


class ErrorView(LoginRequiredMixin, StaffuserRequiredMixin, View):
    """
    A view for raising (for testing purposes) an uncaught Django exceptions (500).
    """

    def get(self, request, *args, **kwargs):
        _ = 5 / 0  # ZeroDivisionError
        return HttpResponse('No error', content_type='text/plain')
