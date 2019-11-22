from django.contrib.auth.mixins import LoginRequiredMixin


class LoginTrackMixin(LoginRequiredMixin):
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['signed_in'] = self.request.session.get('signed_in')
        context['signed_up'] = self.request.session.get('signed_up')
        self.request.session['signed_in'] = False
        self.request.session['signed_up'] = False
        return context
