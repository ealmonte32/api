from django.shortcuts import render, get_object_or_404
from django.http import HttpResponseRedirect
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from .forms import ProfileForm
from .models import Profile


@login_required
def profile_page(request, user_id):
    user = get_object_or_404(User, pk=user_id)
    profile, _ = Profile.objects.get_or_create(user=user)
    if request.method == 'POST':
        form = ProfileForm(request.POST)
        if form.is_valid():
            user.email = form.cleaned_data['email']
            user.first_name = form.cleaned_data['email']
            user.second_name = form.cleaned_data['email']
            profile.company_name = form.cleaned_data['company']
            profile.save()
            user.save()
            return HttpResponseRedirect(f'/user/{user_id}/')
    else:
        form = ProfileForm()
    return render(request, 'profile_page.html', {'user': user, 'form': form})
