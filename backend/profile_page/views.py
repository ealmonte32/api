from django.shortcuts import render
from django.contrib.auth.views import LogoutView as DjangoLogoutView
from django.contrib.auth import logout
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.contrib import messages
from django.views.generic import View, TemplateView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponseRedirect
from django.urls import reverse

from rest_framework.authtoken.models import Token

from .forms import ProfileForm
from .models import Profile


class ProfileAccountView(LoginRequiredMixin, View):

    def dispatch(self, request, *args, **kwargs):
        self.user = request.user
        self.profile, _ = Profile.objects.get_or_create(user=self.user)
        self.initial_form_data = {'username': self.user.username, 'email': self.user.email,
                                  'first_name': self.user.first_name, 'last_name': self.user.last_name,
                                  'company': self.profile.company_name}
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        form = ProfileForm(initial=self.initial_form_data)
        return render(request, 'profile_account.html', {'form': form})

    def post(self, request, *args, **kwargs):
        form = ProfileForm(request.POST, initial=self.initial_form_data)
        if form.is_valid():
            self.user.email = form.cleaned_data['email']
            self.user.first_name = form.cleaned_data['first_name']
            self.user.last_name = form.cleaned_data['last_name']
            self.profile.company_name = form.cleaned_data['company']
            self.user.save(update_fields=['email', 'first_name', 'last_name'])
            self.profile.save(update_fields=['company_name'])
            return HttpResponseRedirect(reverse('profile'))
        return render(request, 'profile_account.html', {'form': form})


class ProfileAPITokenView(LoginRequiredMixin, TemplateView):
    template_name = 'profile_token.html'


class LogoutView(DjangoLogoutView):
    """
    Overwritten default Django's `LogoutView` in order to make it send a message
     with `django.contrib.messages` app.
    """

    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        logout(request)
        next_page = self.get_next_page()
        if next_page:
            messages.add_message(request, messages.INFO, 'You have successfully logged out. Now you can log in again.')
            # Redirect to this page until the session has been cleared.
            return HttpResponseRedirect(next_page)
        return super().dispatch(request, *args, **kwargs)


class GenerateAPITokenView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        if not hasattr(request.user, 'auth_token'):
            Token.objects.create(user=request.user)
        return HttpResponseRedirect(reverse('profile_token'))


class RevokeAPITokenView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        if hasattr(request.user, 'auth_token'):
            Token.objects.filter(user=request.user).delete()
        return HttpResponseRedirect(reverse('profile_token'))
