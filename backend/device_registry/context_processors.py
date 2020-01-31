import json
from pathlib import Path
from django.conf import settings

WEBPACK_STATS_NAME = 'webpack-stats.json'
webpack_stats_path = Path('/usr/src/misc') / WEBPACK_STATS_NAME
if not webpack_stats_path.is_file():
    webpack_stats_path = Path(settings.BASE_DIR) / '..' / WEBPACK_STATS_NAME


def webpack_bundle(request):
    with webpack_stats_path.open() as webpack_stats_file:
        webpack_bundle_json = json.load(webpack_stats_file)
        WEBPACK_BUNDLE_CSS, WEBPACK_BUNDLE_JS = ['/bundles/' + chunk['name'] for chunk in
                                                 webpack_bundle_json['chunks']['app']][:2]
    return {
        'WEBPACK_BUNDLE': {
            'js': WEBPACK_BUNDLE_JS,
            'css': WEBPACK_BUNDLE_CSS
        },
        'MIXPANEL_TOKEN': settings.MIXPANEL_TOKEN
    }
