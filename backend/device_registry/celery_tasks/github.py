import logging
import time
from base64 import b64decode
from datetime import timedelta

from agithub.GitHub import GitHub
from django.conf import settings
from django.db.models import Q
from django.urls import reverse
from django.utils import timezone
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
    g = GitHub(paginate=True, sleep_on_ratelimit=False, api_url='github.com')
    status, body = g.login.oauth.access_token.post(client_id=settings.GITHUB_APP_CLIENT_ID, client_secret=settings.GITHUB_APP_CLIENT_SECRET,
                                                   redirect_uri=settings.GITHUB_APP_REDIR_URL, state=state, code=code,
                                                   headers={'Accept': 'application/json'})
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
    g = GitHub(paginate=True, sleep_on_ratelimit=False, token=user_token)
    logger.info('getting installations...')
    status, body = g.user.installations.get(headers=HEADERS)
    repos = {}
    if 'installations' in body:
        installations = body['installations']
        for inst in installations:
            inst_id = inst['id']
            logger.info(f'getting repos for {inst_id}...')
            status, body = g.user.installations[inst['id']].repositories.get(headers=HEADERS)
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
            logger.info(g.getheaders())
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
    encrypted = jwt.encode(
        payload,
        jwk_from_pem(private_key),
        "RS256"
    )

    if isinstance(encrypted, bytes):
        encrypted = encrypted.decode('utf-8')

    return encrypted


def get_access_token(inst_id):
    """
    Get application access token for the provided installation.
    :param inst_id: installation id
    :return: access token (string)
    :raises GithubError
    """
    if not settings.GITHUB_APP_ID or not settings.GITHUB_APP_PEM:
        logger.error('Github credentials not specified')
        return
    pem = b64decode(settings.GITHUB_APP_PEM)

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

    def _issues(self, issue_number = None):
        # Because agithub.IncompleteRequest gets "complete" after performing an actual request,
        # we need to create a new one for every new request.
        res = self._github.repos[self.repo['owner']][self.repo['name']].issues
        if issue_number is not None:
            return res[issue_number]
        return res

    def list_issues(self):
        """
        Get all issues in the repo, except for locked ones, organized by state.
        :return: {'open': [#, #, #], 'closed': [#, #, #]
        :raises GithubError
        """
        status, body = self._issues().get(state='all', headers=HEADERS)
        if status != 200:
            raise GithubError(body)
        return {state: [i['number'] for i in body if i['state']==state and not i['locked']] for state in ['open', 'closed']}

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
            return
        elif status == 404:
            logger.info('issue not found')
        else:
            raise GithubError(body)

    def open_issue(self, issue_number=None, title_text='', body_text=''):
        """
        Open Github issue specified by issue_number or create new issue with the specified body text.
        If the issue exists its body text will not be changed.
        If the specified issue_number does not exist new issue will also be created.
        :param issue_number: number; may be None in which case new issue will be created
        :param body_text: body text for the newly created issue.
        :return: github.Issue object
        """
        if issue_number is not None:
            status, body = self._issues(issue_number).get()
            if status == 200 and 'id' in body:
                if body['state'] == 'open':
                    logger.debug('issue already open')
                    return
                logger.debug('reopening the issue')
                status, body = self._issues(issue_number).patch(body={
                    'state': 'open'
                })
                if status == 200:
                    logger.debug('issue reopened')
                    return
                else:
                    raise GithubError(body)
            elif status == 404:
                logger.debug('issue not found')
                pass
            else:
                raise GithubError(body)
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


def device_full_link(device):
    url = 'https://dash.wott.io' + reverse('device-detail', kwargs={'pk': device.pk})
    return f'[{device.get_name()}]({url})'


def file_issues():
    from profile_page.models import Profile
    device_link = recommended_actions.device_link
    recommended_actions.device_link = device_full_link

    day_ago = timezone.now() - timedelta(hours=24)
    counter = 0

    for p in Profile.objects.exclude(
            Q(github_repo_id__isnull=True) | Q(github_oauth_token__exact='') | Q(devices__isnull=True)):
        try:
            repos = list_repos(p.github_oauth_token)
        except GithubError:
            logger.exception('failed to get repo list: user may have deauthorized the app')
            # TODO: check if token is valid and erase it if not
            continue

        if p.github_repo_id not in repos:
            logger.error('repo not found: app not installed or no access')
            continue

        try:
            gr = GithubRepo(repos[p.github_repo_id])
            issues = gr.list_issues()
        except GithubError:
            logger.exception('failed to get installation token or list issues')
            continue

        for action_class in recommended_actions.action_classes:
            logger.debug(f'action class {action_class.action_id}')
            affected_devices = action_class.affected_devices(p.user).filter(last_ping__gte=day_ago)
            logger.debug(f'affected {affected_devices.count()} devices')

            # top-level ints in a JSON dict are auto-converted to strings, so we have to use strings here
            issue_number = p.github_issues.get(str(action_class.action_id))

            logger.debug(f'issue #{issue_number}')
            try:
                if affected_devices.exists():
                    if issue_number:
                        comment = 'Affected nodes: ' + ', '.join(
                            [recommended_actions.device_link(dev) for dev in affected_devices])
                        if issue_number in issues['closed']:
                            gr.open_issue(issue_number=issue_number)
                        if issue_number in issues['open'] + issues['closed']:
                            gr.add_comment(issue_number, comment)
                            counter += 1
                    else:
                        context = action_class.get_action_description_context(devices_qs=affected_devices)

                        # AutoUpdatesAction will have empty "devices" because it sets "your nodes" as subject.
                        context['devices'] = 'your nodes' if 'subject' not in context else ''

                        action_text = action_class.action_description.format(**context)
                        action_text += '\n\nAffected nodes: ' + ', '.join(
                            [recommended_actions.device_link(dev) for dev in affected_devices])
                        issue_number = gr.open_issue(title_text=action_class.action_title, body_text=action_text)
                        counter += 1
                else:
                    if issue_number in issues['open']:
                        gr.close_issue(issue_number)
                        counter += 1
            except GithubError:
                logger.exception('failed to process the issue')
            else:
                p.github_issues[str(action_class.action_id)] = issue_number
        p.save(update_fields=['github_issues'])
    recommended_actions.device_link = device_link
    return counter
