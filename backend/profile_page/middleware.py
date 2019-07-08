from django.utils import timezone

from .models import Profile


class UserActivityMiddleware:
    """
    Save user last activity date.
    Do actual DB hitting only once a day.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            today = timezone.localdate()
            profile, _ = Profile.objects.get_or_create(user=request.user)
            if profile.last_active != today:
                profile.last_active = today
                profile.save(update_fields=['last_active'])

        response = self.get_response(request)
        return response
