import logging
import os
from base64 import b64decode

from github import Github, GithubIntegration, Issue, Repository
from github.GithubException import UnknownObjectException

# The following data can be obtained at https://github.com/settings/apps/wott-bot
GITHUB_APP_PEM = os.getenv('GITHUB_APP_PEM')  # Base64 encoded Github app private key: `cat key.pem | base64`
GITHUB_APP_ID = os.getenv('GITHUB_APP_ID')    # Github App ID

logger = logging.getLogger(__name__)


def open_issue(repo: Repository.Repository, issue_id=None, title_text='', body_text='') -> Issue.Issue:
    """
    Open Github issue specified by issue_id or create new issue with the specified body text.
    If the issue exists its body text will not be changed.
    If the specified issue_id does not exist new issue will also be created.
    :param issue_id: number; may be None in which case new issue will be created
    :param body_text: body text for the newly created issue.
    :return: github.Issue object
    """
    if issue_id is not None:
        try:
            issue = repo.get_issue(issue_id)
            issue.edit(state='open')
        except UnknownObjectException:
            issue = repo.create_issue(title_text, body_text)
    return issue


def close_issue(issue_id):
    pass


def add_comment(issue_id, comment):
    pass


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
    return r
