from device_registry.forms import ClaimDeviceForm
from django.views.generic.edit import FormView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponseRedirect, HttpResponse
from device_registry.models import Device
from django.shortcuts import render
from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required


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

    return render(request, 'claim-device.html', {'form': form})


class ClaimDeviceView(LoginRequiredMixin, FormView):
    template_name = 'claim-device.html'
    form_class = ClaimDeviceForm
    success_url = '/'

    def form_valid(self, form):
        # This method is called when valid form data has been POSTed.
        # It should return an HttpResponse.
        form.token_is_valid()
        return super().form_valid(form)
