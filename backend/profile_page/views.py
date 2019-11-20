from django.shortcuts import render
from django.contrib.auth.views import LogoutView as DjangoLogoutView, LoginView as DjangoLoginView
from django.contrib.auth import logout
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.contrib import messages
from django.views.generic import View, TemplateView
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.contrib.auth import authenticate
from django.contrib.auth import login
from django.contrib.auth.mixins import LoginRequiredMixin
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView

from device_registry.celery_tasks import github_issues
from .forms import AuthenticationForm, GithubForm, ProfileForm, RegistrationForm
from .mixins import LoginTrackMixin
from .models import Profile


class ProfileAccountView(LoginRequiredMixin, LoginTrackMixin, View):

    def dispatch(self, request, *args, **kwargs):
        self.user = request.user
        self.profile, _ = Profile.objects.get_or_create(user=self.user)
        self.initial_form_data = {'username': self.user.username, 'email': self.user.email,
                                  'first_name': self.user.first_name, 'last_name': self.user.last_name,
                                  'company': self.profile.company_name,
                                  'phone': self.profile.phone,
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
            self.profile.phone = form.cleaned_data['phone']
            self.user.save(update_fields=['email', 'first_name', 'last_name'])
            self.profile.save(update_fields=['company_name', 'phone'])
            return HttpResponseRedirect(reverse('profile'))
        return render(request, 'profile_account.html', {'form': form})


class ProfileAPITokenView(LoginRequiredMixin, LoginTrackMixin, TemplateView):
    template_name = 'profile_token.html'


class LoginView(DjangoLoginView):
    form_class = AuthenticationForm

    def form_valid(self, form):
        self.request.session['signed_in'] = True
        return super().form_valid(form)


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


class GenerateAPITokenView(LoginRequiredMixin, LoginTrackMixin, View):
    def get(self, request, *args, **kwargs):
        if not hasattr(request.user, 'auth_token'):
            Token.objects.create(user=request.user)
        return HttpResponseRedirect(reverse('profile_token'))


class RevokeAPITokenView(LoginRequiredMixin, LoginTrackMixin, View):
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
        new_user.first_name = form.cleaned_data['first_name']
        new_user.last_name = form.cleaned_data['last_name']
        new_user.save()
        new_user = authenticate(username=getattr(new_user, username_field), password=form.cleaned_data['password1'])
        login(self.request, new_user)
        user_registered.send(sender=self.__class__, user=new_user, request=self.request)
        profile, _ = Profile.objects.get_or_create(user=new_user)
        self.request.session['signed_up'] = True
        profile.payment_plan = int(form.cleaned_data['payment_plan'])
        profile.company_name = form.cleaned_data['company']
        profile.phone = form.cleaned_data['phone']
        profile.save(update_fields=['payment_plan', 'company_name', 'phone'])
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


class WizardCompleteView(LoginRequiredMixin, LoginTrackMixin, APIView):
    def post(self, request, *args, **kwargs):
        request.user.profile.wizard_shown = True
        request.user.profile.save(update_fields=['wizard_shown'])
        return Response(status=status.HTTP_200_OK)


class GithubIntegrationView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        profile = request.user.profile
        repos = profile.github_repos
        if repos is None:
            profile.github_random_state = 'RANDOM'
            profile.save(update_fields=['github_random_state'])
            context = {
                'github_authorized': False,
                'github_auth_url': f'https://github.com/login/oauth/authorize?'
                                   f'client_id={settings.GITHUB_APP_CLIENT_ID}&'
                                   f'redirect_uri={settings.GITHUB_APP_REDIR_URL}&'
                                   f'state={profile.github_random_state}'
            }
        else:
            if profile.github_repo_id not in repos:
                profile.github_repo_id = None  # Not saving because this is a GET
            form = GithubForm({'repo': profile.github_repo_id},
                              repo_choices=[(repo_id, repo['full_name']) for repo_id, repo in repos.items()])
            context = {
                'form': form,
                'github_authorized': True,
                'github_inst_url': f'https://github.com/apps/{settings.GITHUB_APP_NAME}/installations/new'
            }
        return render(request, 'profile_github.html', context)

    def post(self, request, *args, **kwargs):
        profile = request.user.profile
        repos = profile.github_repos
        form = GithubForm(request.POST,
                          repo_choices=[(repo_id, repo['full_name']) for repo_id, repo in repos.items()])
        profile = request.user.profile
        if form.is_valid():
            repo = form.cleaned_data['repo']
            repo = int(repo) if repo else None
            if profile.github_repo_id != repo:
                profile.github_repo_id = repo
                profile.github_issues = {}
                profile.save(update_fields=['github_repo_id', 'github_issues'])
            return HttpResponseRedirect(reverse('github_integration'))
        return render(request, 'profile_github.html', {'form': form})


class GithubCallbackView(LoginRequiredMixin, View):
    # TODO: <script>window.opener.location.reload(); window.close();</script>
    def get(self, request, *args, **kwargs):
        if request.user.profile.github_random_state != request.GET.get('state'):
            return Response(status=status.HTTP_400_BAD_REQUEST)
        request.user.profile.fetch_oauth_token(request.GET.get('code'))
        return render(request, 'github_callback.html')
