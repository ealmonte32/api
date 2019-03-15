from django.test import TestCase, RequestFactory
from django.contrib.auth.models import User
from .views import profile_page


class APIPingTest(TestCase):
    def setUp(self):
        self.api = RequestFactory()
        self.user = User.objects.create_user('test')

    def test_profile_page(self):
        request = self.api.get(f'/user/{self.user.id}')
        response = profile_page(request, self.user.id)
        self.assertEqual(response.status_code, 200)
