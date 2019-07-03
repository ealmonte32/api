from django.urls import path

from .views import profile_view, GenerateAPITokenView, RevokeAPITokenView

urlpatterns = [
    path('profile/', profile_view, name='profile'),
    path('generate-api-token/', GenerateAPITokenView.as_view(), name='generate_api_token'),
    path('revoke-api-token/', RevokeAPITokenView.as_view(), name='revoke_api_token')
]
