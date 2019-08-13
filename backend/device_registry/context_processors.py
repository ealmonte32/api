import json
import logging
from pathlib import Path


WEBPACK_STATS_NAME = 'webpack-stats.json'
webpack_stats_path = Path('/usr/src/misc') / WEBPACK_STATS_NAME
with webpack_stats_path.open() as webpack_stats_file:
    logging.warning('loading webpack-stats')
    webpack_bundle_json = json.load(webpack_stats_file)
    logging.warning('loaded: {}'.format(webpack_bundle_json))
    WEBPACK_BUNDLE_CSS, WEBPACK_BUNDLE_JS = ['/bundles/'+chunk['name'] for chunk in webpack_bundle_json['chunks']['app']]


def webpack_bundle(request):
    return {
        'WEBPACK_BUNDLE': {
            'js': WEBPACK_BUNDLE_JS,
            'css': WEBPACK_BUNDLE_CSS
        }
    }