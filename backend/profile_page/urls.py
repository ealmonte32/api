from django.urls import path
from django.contrib.auth.views import PasswordChangeView
from django.urls import reverse_lazy

from .views import GenerateAPITokenView, RevokeAPITokenView, ProfileAccountView, ProfileAPITokenView
from .views import WizardCompleteView, GithubCallbackView, GithubIntegrationView, SlackIntegrationView, PaymentPlanView
from .views import SyncSubscriptionView
from .forms import PasswordChangeForm

urlpatterns = [
    path('profile/', ProfileAccountView.as_view(), name='profile'),
    path('profile/password/', PasswordChangeView.as_view(
        success_url=reverse_lazy('profile_password'),
        template_name='profile_password.html',
        extra_context={'tab_password': 'active'},
        form_class=PasswordChangeForm), name='profile_password'),
    path('profile/wizard-complete/', WizardCompleteView.as_view(), name='wizard-complete'),
    path('profile/token/', ProfileAPITokenView.as_view(), name='profile_token'),
    path('generate-api-token/', GenerateAPITokenView.as_view(), name='generate_api_token'),
    path('revoke-api-token/', RevokeAPITokenView.as_view(), name='revoke_api_token'),
    path('profile/github/', GithubIntegrationView.as_view(), name='github_integration'),
    path('profile/slack/', SlackIntegrationView.as_view(), name='slack_integration'),
    path('profile/payment/', PaymentPlanView.as_view(), name='payment_plan'),
    path('github-callback/', GithubCallbackView.as_view(), name='github_callback'),
    path('sync-subscription/<int:pk>/', SyncSubscriptionView.as_view(), name='sync_subscription')
]
