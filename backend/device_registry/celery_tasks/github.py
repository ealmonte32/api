import logging
import time
from datetime import timedelta

from django.conf import settings
from django.db.models import Q
from django.urls import reverse
from django.utils import timezone

from agithub.GitHub import GitHub
from agithub.base import IncompleteRequest
from jwt import JWT, jwk_from_pem

from device_registry import recommended_actions

HEADERS = {'Accept': 'application/vnd.github.machine-man-preview+json'}
logger = logging.getLogger('django')


class GithubError(Exception):
    pass


def get_token_from_code(code, state):
    """
    Get user-to-server token to be used with list_repos().
    The user should open https://github.com/login/oauth/authorize?client_id=<...>&redirect_uri=<...>&state=<...>
    :param code: Code obtained from /login/oauth/authorize redirect.
    :param state: Random state obtained from /login/oauth/authorize redirect.
    :return: access token (string)
    :raises GithubError
    """
    if not settings.GITHUB_APP_CLIENT_ID or not settings.GITHUB_APP_CLIENT_SECRET:
        raise GithubError('Github credentials not specified')

    github = GitHub(paginate=True, sleep_on_ratelimit=False, api_url='github.com')
    status, body = github.login.oauth.access_token.post(client_id=settings.GITHUB_APP_CLIENT_ID,
                                                        client_secret=settings.GITHUB_APP_CLIENT_SECRET,
                                                        redirect_uri=settings.GITHUB_APP_REDIRECT_URL, state=state,
                                                        code=code, headers={'Accept': 'application/json'})
    if status == 200 and 'access_token' in body:
        return body['access_token']
    else:
        raise GithubError(body)


def list_repos(user_token):
    """
    Enumerate authenticated user's repositories where the app is installed.
    :param user_token: a user-to-server token.
    :return: a dict {id: {owner: ..., name: ..., installation: ..., full_name: ...}}
    :raises GithubError
    """
    github = GitHub(paginate=True, sleep_on_ratelimit=False, token=user_token)
    logger.info('getting installations...')
    status, body = github.user.installations.get(headers=HEADERS)
    repos = {}
    if 'installations' in body:
        installations = body['installations']
        for inst in installations:
            inst_id = inst['id']
            logger.info(f'getting repos for {inst_id}...')
            status, body = github.user.installations[inst['id']].repositories.get(headers=HEADERS)
            logger.info('parsing...')
            if 'repositories' in body:
                repos.update({repo['id']: {
                    'full_name': repo['full_name'],
                    'url': repo['html_url'],
                    'name': repo['name'],
                    'owner': repo['owner']['login'],
                    'installation': inst_id
                 } for repo in body['repositories']})
            else:
                raise GithubError(body)
        return repos
    else:
        raise GithubError(body)


def create_jwt(app_id, private_key: bytes, expiration=60):
    """
    Creates a signed JWT, valid for 60 seconds by default.
    The expiration can be extended beyond this, to a maximum of 600 seconds.
    :param app_id: Github App ID
    :param private_key: Github App Private Key in PEM format
    :param expiration: int
    :return: an encoded JWT
    """
    now = int(time.time())
    payload = {
        "iat": now,
        "exp": now + expiration,
        "iss": int(app_id)
    }
    jwt = JWT()
    return jwt.encode(
        payload,
        jwk_from_pem(private_key),
        "RS256"
    )


def get_access_token(inst_id):
    """
    Get application access token for the provided installation.
    :param inst_id: installation id
    :return: access token (string)
    :raises GithubError
    """
    if not settings.GITHUB_APP_PEM:
        raise GithubError('Github app private key is empty')
    pem = settings.GITHUB_APP_PEM.decode('unicode-escape').encode()
    headers = HEADERS.copy()
    headers['Authorization'] = f"Bearer {create_jwt(settings.GITHUB_APP_ID, pem)}"
    g = GitHub(paginate=True, sleep_on_ratelimit=False)
    status, body = g.app.installations[inst_id].access_tokens.post(headers=headers)
    if status == 201 and 'token' in body:
        return body['token']
    else:
        raise GithubError(body)


class GithubRepo:

    def __init__(self, repo):
        """
        Constructor.
        :param repo: a dict obtained from list_repos().
        """
        self.repo = repo
        inst_id = repo['installation']
        token = get_access_token(inst_id)
        self._github = GitHub(paginate=True, sleep_on_ratelimit=False, token=token)

    def _issues(self, issue_number=None) -> IncompleteRequest:
        # Because agithub.IncompleteRequest gets "complete" after performing an actual request,
        # we need to create a new one for every new request.
        issues_request = self._github.repos[self.repo['owner']][self.repo['name']].issues
        if issue_number is not None:
            return issues_request[issue_number]
        return issues_request

    def list_issues(self):
        """
        Get all issues in the repo, except for locked ones, organized by state.
        :return: {'open': [#, #, #], 'closed': [#, #, #]
        :raises GithubError
        """
        status, body = self._issues().get(state='all', headers=HEADERS)
        if status != 200:
            raise GithubError(body)
        return {state: [issue['number'] for issue in body if issue['state'] == state and not issue['locked']]
                for state in ['open', 'closed']}

    def add_comment(self, issue_number, comment):
        """
        Post a comment in the issue specified by issue_number.
        :param issue_number:
        :param comment:
        :return:
        :raises GithubError
        """
        status, body = self._issues(issue_number).comments.post(body={
            'body': comment
        })
        if status == 201:
            return
        else:
            raise GithubError(body)

    def close_issue(self, issue_number):
        """
        Close Github issue specified by issue_number. Will not fail if the issue does not exist.
        :param issue_number:
        :return:
        :raises GithubError
        """
        logger.info('closing issue')
        status, body = self._issues(issue_number).patch(body={
            'state': 'closed'
        })
        if status == 200:
            logger.info('issue closed')
        elif status == 404:
            logger.info('issue not found')
        else:
            raise GithubError(body)

    def create_issue(self, title_text, body_text):
        """
        Create new Github issue with the specified body text.
        :param title_text: issue title (plaintext only).
        :param body_text: body text for the newly created issue (markdown).
        :return: issue number
        :raises GithubError
        """
        logger.debug(f'creating new issue: "{title_text}"')
        status, body = self._issues().post(body={
            'title': title_text,
            'body': body_text
        })
        if status == 201:
            logger.debug(f'created issue #{body["number"]}')
            return body['number']
        else:
            raise GithubError(body)

    def open_issue(self, issue_number):
        """
        Open an existing closed Github issue
        :param issue_number: issue number
        :return: None
        :raises GithubError
        """
        status, body = self._issues(issue_number).patch(body={
            'state': 'open'
        })
        if status == 200:
            logger.debug('issue reopened')
        else:
            raise GithubError(body)

    def update_issue(self, issue_number, body_text):
        """
        Update issue text and open it if closed.
        :param issue_number: issue number
        :return: None
        :raises GithubError
        """
        status, body = self._issues(issue_number).patch(body={
            'state': 'open',
            'body': body_text
        })
        if status == 200:
            logger.debug('issue updated')
        else:
            raise GithubError(body)


def get_device_link(device):
    url = settings.DASH_URL + reverse('device-detail', kwargs={'pk': device.pk})
    return f'[{device.get_name()}]({url})'


def file_issues():
    from profile_page.models import Profile

    day_ago = timezone.now() - timedelta(hours=24)
    counter = 0

    for profile in Profile.objects.exclude(
            Q(github_repo_id__isnull=True) | Q(github_oauth_token='') | Q(user__devices__isnull=True)):
        try:
            repos = list_repos(profile.github_oauth_token)
        except GithubError:
            logger.exception('failed to get repo list: user may have deauthorized the app')
            # TODO: check if token is valid and erase it if not
            continue

        if profile.github_repo_id not in repos:
            logger.error('repo not found: app not installed or no access')
            continue

        try:
            github_repo = GithubRepo(repos[profile.github_repo_id])
            issues = github_repo.list_issues()
        except GithubError:
            logger.exception('failed to get installation token or list issues')
            continue

        for action_class in recommended_actions.ActionMeta.all_classes(grouped=True):
            logger.debug(f'action class {action_class.action_id}')
            # top-level ints in a JSON dict are auto-converted to strings, so we have to use strings here
            issue_number = profile.github_issues.get(str(action_class.action_id))
            description = action_class.get_description(profile.user, additional_context={'devices': 'your nodes'})
            logger.debug(f'issue #{issue_number}')
            try:
                if description:
                    title, text = description
                    if issue_number:
                        # Issue was created and opened/closed by us. Cloud also be locked in which case it will be
                        # neither in 'open' nor in 'closed' because we can't comment in a locked issue.
                        if issue_number in issues['open'] + issues['closed']:
                            # Issue was opened or closed (and reopened above) by us and not locked => add comment
                            last_updated = timezone.now().strftime('%Y-%m-%d %H:%M')
                            github_repo.update_issue(issue_number, text +
                                                     f"\n\n*Last updated: {last_updated} UTC*")
                            counter += 1
                    else:
                        issue_number = github_repo.create_issue(title, text)
                        counter += 1
                else:
                    if issue_number in issues['open']:
                        github_repo.close_issue(issue_number)
                        counter += 1
            except GithubError:
                logger.exception('failed to process the issue')
            else:
                profile.github_issues[str(action_class.action_id)] = issue_number
        profile.save(update_fields=['github_issues'])
    return counter
