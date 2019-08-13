from django.conf import settings

def webpack_bundle(request):
    return {
        'WEBPACK_BUNDLE_JS': settings.WEBPACK_BUNDLE_JS,
        'WEBPACK_BUNDLE_CSS': settings.WEBPACK_BUNDLE_CSS
    }