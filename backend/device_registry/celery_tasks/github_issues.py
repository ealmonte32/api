import jwt
import logging
import os
import time
from base64 import b64decode
from datetime import timedelta

from agithub.GitHub import GitHub
from django.urls import reverse
from django.utils import timezone

from device_registry import recommended_actions


# The following data can be obtained at https://github.com/settings/apps/wott-bot
GITHUB_APP_PEM = os.getenv('GITHUB_APP_PEM')  # Base64 encoded Github app private key: `cat key.pem | base64`
GITHUB_APP_ID = os.getenv('GITHUB_APP_ID')    # Github App ID
GITHUB_APP_NAME = os.getenv('GITHUB_APP_NAME')
GITHUB_APP_CLIENT_ID = os.getenv('GITHUB_APP_CLIENT_ID')
GITHUB_APP_CLIENT_SECRET = os.getenv('GITHUB_APP_CLIENT_SECRET')    # Github App Secret
GITHUB_APP_REDIR_URL = os.getenv('GITHUB_APP_REDIR_URL')    # Github App Redirect URL
USER_TOKEN = 'fa6e702403bac10f7bf2e33b5e3c19897daf80d1' # REMOVE
HEADERS = {'Accept': 'application/vnd.github.machine-man-preview+json'}
logger = logging.getLogger('django')


def get_token_from_code(code):
    """
    Get user-to-server token to be used with list_repos().
    The user should open https://github.com/login/oauth/authorize?client_id=<...>&redirect_uri=<...>&state=<...>
    :param code: Code obtained from /login/oauth/authorize redirect.
    :return: access token (string)
    :raises RuntimeError
    """
    state = 'RANDOM'

    g = GitHub(paginate=True, sleep_on_ratelimit=False, api_url='github.com')
    status, body = g.login.oauth.access_token.post(client_id=GITHUB_APP_CLIENT_ID, client_secret=GITHUB_APP_CLIENT_SECRET,
                                                   redirect_uri=GITHUB_APP_REDIR_URL, state=state, code=code,
                                                   headers={'Accept': 'application/json'})
    if status == 200 and 'access_token' in body:
        return body['access_token']
    else:
        raise RuntimeError(body)


def list_repos(user_token):
    """
    Enumerate authenticated user's repositories where the app is installed.
    :param user_token: a user-to-server token.
    :return: a dict {id: {owner: ..., name: ..., installation: ..., full_name: ...}}
    :raises RuntimeError
    """
    g = GitHub(paginate=True, sleep_on_ratelimit=False, token=user_token)
    print('getting installations...')
    status, body = g.user.installations.get(headers=HEADERS)
    repos = {}
    if 'installations' in body:
        installations = body['installations']
        for inst in installations:
            inst_id = inst['id']
            print('getting repos for {}...'.format(inst_id))
            status, body = g.user.installations[inst['id']].repositories.get(headers=HEADERS)
            print('parsing...')
            if 'repositories' in body:
                repos.update({repo['id']: {
                    'full_name': repo['full_name'],
                    'name': repo['name'],
                    'owner': repo['owner']['login'],
                    'installation': inst_id
                 } for repo in body['repositories']})
            else:
                raise RuntimeError(body)
            print(g.getheaders())
        return repos
    else:
        raise RuntimeError(body)


def create_jwt(app_id, private_key, expiration=60):
    """
    Creates a signed JWT, valid for 60 seconds by default.
    The expiration can be extended beyond this, to a maximum of 600 seconds.
    :param expiration: int
    :return: an encoded JWT
    :raises RuntimeError
    """
    now = int(time.time())
    payload = {
        "iat": now,
        "exp": now + expiration,
        "iss": int(app_id)
    }
    encrypted = jwt.encode(
        payload,
        key=private_key,
        algorithm="RS256"
    )

    if isinstance(encrypted, bytes):
        encrypted = encrypted.decode('utf-8')

    return encrypted


def get_access_token(inst_id):
    """
    Get application access token for the provided installation.
    :param inst_id: installation id
    :return: access token (string)
    """
    if not GITHUB_APP_ID or not GITHUB_APP_PEM:
        logger.error('Github credentials not specified')
        return
    pem = b64decode(GITHUB_APP_PEM).decode()

    headers = HEADERS.copy()
    headers['Authorization'] = "Bearer {}".format(create_jwt(GITHUB_APP_ID, pem))
    g = GitHub(paginate=True, sleep_on_ratelimit=False)
    status, body = g.app.installations[inst_id].access_tokens.post(headers=headers)
    if status == 201 and 'token' in body:
        return body['token']
    else:
        raise RuntimeError(body)


class GithubRepo:
    token_cache = {}

    def __init__(self, repo):
        self.repo = repo
        inst_id = repo['installation']
        if inst_id in self.token_cache:
            token = self.token_cache[inst_id]
        else:
            token = get_access_token(inst_id)
            self.token_cache[inst_id] = token
        self.github = GitHub(paginate=True, sleep_on_ratelimit=False, token=token)

    def _issues(self, issue_number = None):
        # Because agithub.IncompleteRequest gets "complete" after performing an actual request,
        # we need to create a new one for every new request.
        res = self.github.repos[self.repo['owner']][self.repo['name']].issues
        if issue_number is not None:
            return res[issue_number]
        return res

    def list_issues(self):
        return self._issues().get(state='all', headers=HEADERS)

    def add_comment(self, issue_number, comment):
        status, body = self._issues(issue_number).comments.post(body={
            'body': comment
        })
        if status == 201:
            return
        else:
            raise RuntimeError(body)

    def close_issue(self, issue_number):
        print('closing issue')
        status, body = self._issues(issue_number).patch(body={
            'state': 'closed'
        })
        if status == 200:
            print('issue closed')
            return
        elif status == 404:
            print('issue not found')
        else:
            raise RuntimeError(body)

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
                    print('issue already open')
                    return
                print('reopening the issue')
                status, body = self._issues(issue_number).patch(body={
                    'state': 'open'
                })
                if status == 200:
                    print('issue reopened')
                    return
                else:
                    raise RuntimeError(body)
            elif status == 404:
                print('issue not found')
                pass
            else:
                raise RuntimeError(body)
        print('creating new issue')
        status, body = self._issues().post(body={
            'title': title_text,
            'body': body_text
        })
        if status == 201:
            print('created issue #{}'.format(body['number']))
            return body['number']
        else:
            raise RuntimeError(body)


def main():
    from profile_page.models import Profile

    day_ago = timezone.now() - timedelta(hours=24)
    for p in Profile.objects.filter(github_repo_id__isnull=False, github_oauth_token__isnull=False):
        repos = list_repos(p.github_oauth_token)
        if p.github_repo_id not in repos:
            print('repo not found: app not installed or no access')
            continue
        gr = GithubRepo(repos[p.github_repo_id])
        gr.list_issues()

        counter = 0
        if p.user.devices.exists():
            for action_class in recommended_actions.action_classes:
                affected_devices = action_class.affected_devices(p.user).filter(last_ping__gte=day_ago)
                issue_info = p.github_issues.get(action_class.action_id, {})
                if affected_devices.exists():
                    if 'issue_number' in issue_info:
                        comment = 'devices affected: ' + ', '.join(
                            [recommended_actions.device_link(dev) for dev in affected_devices])
                        issue_number = issue_info['issue_number']
                        gr.open_issue(issue_number=p.github_issues)
                        gr.add_comment(issue_number, comment)
                        counter += 1
                    else:
                        # TODO: get_action_description_context
                        context = action_class.get_action_description_context(affected_devices, None)
                        action_text = action_class.action_description.fomat()
                        action_text += '\n\ndevices affected: ' + ', '.join(
                            [recommended_actions.device_link(dev) for dev in affected_devices])
                        issue_number = gr.open_issue(title_text=action_class.action_title, body_text=action_text)
                        issue_info['issue_number'] = issue_number
                        counter += 1
                else:
                    if 'issue_number' in issue_info:
                        gr.close_issue(issue_info['issue_number'])
                    counter += 1
                p.github_issues[action_class.action_id] = issue_info
                p.save(update_fields=['github_issues'])

        return counter

# r=list_repos(USER_TOKEN)
# repo=list(r.values())[2]
#
