from device_registry.forms import ClaimDeviceForm
from django.views.generic.list import ListView
from django.views.generic import View
from django.http import HttpResponse
from device_registry.models import Device, DeviceInfo
from django.shortcuts import render
from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required


@login_required
def root_view(request):
    return render(request, 'root.html')


@login_required
def claim_device_view(request):
    # if this is a POST request we need to process the form data
    if request.method == 'POST':
        form = ClaimDeviceForm(request.POST)

        if form.is_valid():
            get_device = get_object_or_404(
                Device,
                device_id=form.cleaned_data['device_id']
            )
            if get_device.claimed():
                return HttpResponse('Device has already been claimed.')

            if not get_device.claim_token == form.cleaned_data['claim_token']:
                return HttpResponse('Invalid claim/device id pair.')

            get_device.owner = request.user
            get_device.save()
            return HttpResponse('Successfully claimed {}.'.format(form.cleaned_data['device_id']))

    # if a GET (or any other method) we'll create a blank form
    else:
        form = ClaimDeviceForm()

    return render(request, 'claim_device.html', {'form': form})


class DeviceListView(ListView):
    model = Device
    paginate_by = 100  # if pagination is desired
    template_name = 'device_list.html'

    def get_queryset(self):
        if self.request.user.is_authenticated:
            return Device.objects.filter(owner=self.request.user)
        else:
            return Device.objects.none()


class DeviceDetailView(View):
    def get(self, request, *args, **kwargs):
        device_info = get_object_or_404(
            DeviceInfo,
            device__id=kwargs['pk'],
            device__owner=request.user
        )
        device = get_object_or_404(
            Device,
            id=kwargs['pk'],
            owner=request.user
        )
        context = {'device_info': device_info, 'device': device}
        return render(request, 'device_info.html', context)
