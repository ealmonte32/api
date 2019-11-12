import logging
import os
from base64 import b64decode

from github import Github, GithubIntegration

# The following data can be obtained at https://github.com/settings/apps/wott-bot
GITHUB_APP_PEM = os.getenv('GITHUB_APP_PEM')  # Base64 encoded Github app private key: `cat key.pem | base64`
GITHUB_APP_ID = os.getenv('GITHUB_APP_ID')    # Github App ID

logger = logging.getLogger(__name__)


def main(github_repo_owner, github_repo):
    if not GITHUB_APP_ID or not GITHUB_APP_PEM:
        logger.error('Github credentials not specified')
        return
    pem = b64decode(GITHUB_APP_PEM).decode()
    integration = GithubIntegration(GITHUB_APP_ID, pem)
    installation_id = integration.get_installation(github_repo_owner, github_repo)
    integration_accessor = integration.get_access_token(installation_id.id.value)
    g = Github(integration_accessor.token)
    r = g.get_repo(github_repo_owner+'/'+github_repo)
    return r.get_issues()
