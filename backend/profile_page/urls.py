from django.urls import path
from django.contrib.auth.views import PasswordChangeView
from django.urls import reverse_lazy

from .views import GenerateAPITokenView, RevokeAPITokenView, ProfileAccountView, ProfileAPITokenView, WizardCompleteView

urlpatterns = [
    path('profile/', ProfileAccountView.as_view(), name='profile'),
    path('profile/password/', PasswordChangeView.as_view(
        success_url=reverse_lazy('profile_password'), template_name='profile_password.html'), name='profile_password'),
    path('profile/wizard-complete', WizardCompleteView.as_view(), name='wizard-complete'),
    path('profile/token/', ProfileAPITokenView.as_view(), name='profile_token'),
    path('generate-api-token/', GenerateAPITokenView.as_view(), name='generate_api_token'),
    path('revoke-api-token/', RevokeAPITokenView.as_view(), name='revoke_api_token')
]
