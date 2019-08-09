from django.conf import settings

def webpack_bundle(request):
    return {'WEBPACK_BUNDLE': settings.WEBPACK_BUNDLE}