import jwt
import logging
import os
import time
from base64 import b64decode

from agithub.GitHub import GitHub


# The following data can be obtained at https://github.com/settings/apps/wott-bot
GITHUB_APP_PEM = os.getenv('GITHUB_APP_PEM')  # Base64 encoded Github app private key: `cat key.pem | base64`
GITHUB_APP_ID = os.getenv('GITHUB_APP_ID')    # Github App ID
GITHUB_APP_SECRET = os.getenv('GITHUB_APP_SECRET')    # Github App Secret
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
    url = 'http://wott.io'
    state = 'RANDOM'

    g = GitHub(paginate=True, sleep_on_ratelimit=False, api_url='github.com')
    status, body = g.login.oauth.access_token.post(client_id=GITHUB_APP_ID, client_secret=GITHUB_APP_SECRET,
                                                   redirect_uri=GITHUB_APP_REDIR_URL, state=state, code=code,
                                                   headers={'Accept': 'application/json'})
    if status == 200 and 'access_token' in body:
        return body['access_token']
    else:
        raise RuntimeError(body)


def list_repos():
    """
    Enumerate authenticated user's repositories where the app is installed.
    :return: a dict {id: {owner: ..., name: ..., installation: ..., full_name: ...}}
    :raises RuntimeError
    """
    g = GitHub(paginate=True, sleep_on_ratelimit=False, token=USER_TOKEN)
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


def list_issues(repo):
    g = GitHub(paginate=True, sleep_on_ratelimit=False, token=get_access_token(repo['installation']))
    # FIXME: "GitHub's REST API v3 considers every pull request an issue, but not every issue is a pull request."
    # https://developer.github.com/v3/issues/#list-issues-for-a-repository what does it mean?
    return g.repos[repo['owner']][repo['name']].issues.get(state='all', headers=HEADERS)


def open_issue(repo, issue_number=None, title_text='', body_text=''):
    """
    Open Github issue specified by issue_number or create new issue with the specified body text.
    If the issue exists its body text will not be changed.
    If the specified issue_number does not exist new issue will also be created.
    :param issue_number: number; may be None in which case new issue will be created
    :param body_text: body text for the newly created issue.
    :return: github.Issue object
    """
    g = GitHub(paginate=True, sleep_on_ratelimit=False, token=get_access_token(repo['installation']))

    def issues():
        # Because agithub.IncompleteRequest gets "complete" after performing an actual request,
        # we need to create a new one for every new request.
        return g.repos[repo['owner']][repo['name']].issues

    if issue_number is not None:
        status, body = issues()[issue_number].get()
        if status == 200 and 'id' in body:
            if body['state'] == 'open':
                print('issue already open')
                return
            print('reopening the issue')
            status, body = issues()[issue_number].patch(body={
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
    status, body = issues().post(body={
        'title': title_text,
        'body': body_text
    })
    if status == 201:
        print('created issue #{}'.format(body['number']))
        return body['number']
    else:
        raise RuntimeError(body)


def close_issue(repo, issue_number):
    g = GitHub(paginate=True, sleep_on_ratelimit=False, token=get_access_token(repo['installation']))

    def issues():
        # Because agithub.IncompleteRequest gets "complete" after performing an actual request,
        # we need to create a new one for every new request.
        return g.repos[repo['owner']][repo['name']].issues

    print('closing issue')
    status, body = issues()[issue_number].patch(body={
        'state': 'closed'
    })
    if status == 200:
        print('issue closed')
        return
    elif status == 404:
        print('issue not found')
    else:
        raise RuntimeError(body)


def add_comment(repo, issue_number, comment):
    g = GitHub(paginate=True, sleep_on_ratelimit=False, token=get_access_token(repo['installation']))

    def issues():
        # Because agithub.IncompleteRequest gets "complete" after performing an actual request,
        # we need to create a new one for every new request.
        return g.repos[repo['owner']][repo['name']].issues

    status, body = issues()[issue_number].comments.post(body={
        'body': comment
    })
    if status == 201:
        return
    else:
        raise RuntimeError(body)


# r=list_repos()
# repo=list(r.values())[2]
