from django.conf import settings
from django.urls import path
from .views import profile_page

urlpatterns = [
    path('<int:user_id>/', profile_page, name='profile-page')
]
