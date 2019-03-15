from django.shortcuts import render, get_object_or_404
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required


@login_required
def profile_page(request, user_id):
    user = get_object_or_404(User, pk=user_id)
    return render(request, 'profile_page.html', {'user': user})
