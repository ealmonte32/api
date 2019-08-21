import json
from pathlib import Path
from backend.settings.base import BASE_DIR

WEBPACK_STATS_NAME = 'webpack-stats.json'
webpack_stats_path = Path('/usr/src/misc') / WEBPACK_STATS_NAME
if not webpack_stats_path.is_file():
    webpack_stats_path = Path(BASE_DIR) / '..' / WEBPACK_STATS_NAME
with webpack_stats_path.open() as webpack_stats_file:
    webpack_bundle_json = json.load(webpack_stats_file)
    WEBPACK_BUNDLE_CSS, WEBPACK_BUNDLE_JS = ['/bundles/'+chunk['name'] for chunk in webpack_bundle_json['chunks']['app']]


def webpack_bundle(request):
    return {
        'WEBPACK_BUNDLE': {
            'js': WEBPACK_BUNDLE_JS,
            'css': WEBPACK_BUNDLE_CSS
        }
    }