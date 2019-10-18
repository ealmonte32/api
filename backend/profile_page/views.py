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
from django.contrib.auth import authenticate
from django.contrib.auth import login

from rest_framework import status
from rest_framework.authtoken.models import Token
from registration.views import RegistrationView as BaseRegistrationView
from registration.signals import user_registered
from rest_framework.response import Response
from rest_framework.views import APIView

from .forms import ProfileForm, RegistrationForm
from .models import Profile


class ProfileAccountView(LoginRequiredMixin, View):

    def dispatch(self, request, *args, **kwargs):
        self.user = request.user
        self.profile, _ = Profile.objects.get_or_create(user=self.user)
        self.initial_form_data = {'username': self.user.username, 'email': self.user.email,
                                  'first_name': self.user.first_name, 'last_name': self.user.last_name,
                                  'company': self.profile.company_name,
                                  'payment_plan': self.profile.get_payment_plan_display()}
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


class RegistrationView(BaseRegistrationView):
    """Overwritten standard registration view from the 'django-registration-redux' 3rd party app."""
    success_url = '/'
    form_class = RegistrationForm
    template_name = 'registration/registration_form.html'

    def register(self, form):
        """Standard `register` method overwritten in order to properly handle our custom `payment_plan` form field."""
        new_user = form.save(commit=False)
        username_field = getattr(new_user, 'USERNAME_FIELD', 'username')
        # Save lowercased email as username.
        setattr(new_user, username_field, form.cleaned_data['email'].lower())
        new_user.save()
        new_user = authenticate(username=getattr(new_user, username_field), password=form.cleaned_data['password1'])
        login(self.request, new_user)
        user_registered.send(sender=self.__class__, user=new_user, request=self.request)
        profile, _ = Profile.objects.get_or_create(user=new_user)
        profile.first_signin = True
        profile.payment_plan = int(form.cleaned_data['payment_plan'])
        profile.save(update_fields=['payment_plan', 'first_signin'])
        if profile.payment_plan != Profile.PAYMENT_PLAN_FREE:
            messages.add_message(self.request, messages.INFO,
                                 'Congratulations! We won\'t charge you for this plan for now.')
        return new_user

    def get_initial(self):
        """
        Take a payment plan GET parameter value and pass it to the form
         as an initial value of its `payment_plan` field.
         All irrelevant values will be simply ignored by the form.
        """
        return {'payment_plan': self.request.GET.get('plan')}


class WizardCompleteView(LoginRequiredMixin, APIView):
    def post(self, request, *args, **kwargs):
        request.user.profile.wizard_shown = True
        request.user.profile.save(update_fields=['wizard_shown'])
        return Response(status=status.HTTP_200_OK)
