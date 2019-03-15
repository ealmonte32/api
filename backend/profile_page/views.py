from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from .forms import ProfileForm


@login_required
def profile_page(request, user_id):
    user = get_object_or_404(User, pk=user_id)
    if request.method == 'POST':
        form = ProfileForm(request.POST)
        if form.is_valid():
            user.username = form.cleaned_data['username']
            user.email = form.cleaned_data['email']
            user.save()
            return HttpResponse(f'Profile updated - {user.username}.')
    else:
        form = ProfileForm()
    return render(request, 'profile_page.html', {'user': user, 'form': form})
