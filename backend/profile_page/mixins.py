class LoginTrackMixin:
    """
    Set either signed_in or signed_up in context if the user has just signed in or registered.
    One of those will be set only once which allows on-page JS code to take proper actions like send tracking events.
    """
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        for attr in ('signed_in', 'signed_up'):
            if attr in self.request.session:
                context[attr] = self.request.session[attr]
                del self.request.session[attr]
        return context
