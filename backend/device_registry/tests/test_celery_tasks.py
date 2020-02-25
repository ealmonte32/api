from collections import defaultdict

from django.test import TestCase
from unittest import mock

from device_registry.models import GithubIssue
from device_registry.recommended_actions import SimpleAction, Severity
from profile_page.models import *

TEST_REPO_ID = 1234
TEST_ISSUE_ID = 2345


class mockGithubRepo:
    list_issues = mock.Mock()
    close_issue = mock.Mock()
    update_issue = mock.Mock()
    create_issue = mock.Mock()

    def __init__(self, repo_id):
        self.repo_id = repo_id


@mock.patch('device_registry.celery_tasks.github.list_repos', lambda t: {TEST_REPO_ID: {}})
@mock.patch('device_registry.celery_tasks.github.GithubRepo', mockGithubRepo)
class GithubTest(TestCase):
    def setUp(self):
        hour_ago = timezone.now() - timezone.timedelta(hours=1)
        self.user = User.objects.create_user('test')
        self.profile = Profile.objects.create(user=self.user, github_oauth_token='abcd', github_repo_id=1234)
        self.device = Device.objects.create(
            device_id='device.d.wott-dev.local',
            last_ping=hour_ago,
            owner=self.user,
            name='testdevice'
        )
        self.device1 = Device.objects.create(
            device_id='device1.d.wott-dev.local',
            last_ping=hour_ago,
            owner=self.user,
            name='testdevice1'
        )

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        class TestAction(SimpleAction, metaclass=ActionMeta):
            action_config = defaultdict(str)
            _severity = Severity.LO

        cls.TestAction = TestAction

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        ActionMeta.unregister(cls.TestAction)

    def test_empty(self):
        self.device.owner = None
        self.device.save()
        # No devices - do nothing
        self.assertEqual(github.file_issues(), 0)

    def test_empty_ra(self):
        mockGithubRepo.list_issues.return_value = {}

        self.assertEqual(github.file_issues(), 0)

    def test_create_ra(self):
        ra = RecommendedAction.objects.create(action_class=self.TestAction.__name__, action_param='param')
        RecommendedActionStatus.objects.create(device=self.device, status=RecommendedAction.Status.AFFECTED, ra=ra)
        mockGithubRepo.list_issues.return_value = {}
        mockGithubRepo.create_issue.return_value = TEST_ISSUE_ID

        self.assertEqual(github.file_issues(), 1)
        title, text = mockGithubRepo.create_issue.call_args[0]
        self.assertIn('#### Resolved on: ####\n- [ ] [testdevice]', text)

        issue = GithubIssue.objects.get(number=TEST_ISSUE_ID, owner=self.user)
        self.assertFalse(issue.closed)

    def test_update_ra_open(self):
        ra = RecommendedAction.objects.create(action_class=self.TestAction.__name__, action_param='param')
        RecommendedActionStatus.objects.create(device=self.device, status=RecommendedAction.Status.AFFECTED, ra=ra)
        issue = GithubIssue.objects.create(number=TEST_ISSUE_ID, owner=self.user)
        mockGithubRepo.list_issues.return_value = {
            'open': [TEST_ISSUE_ID],
            'closed': []
        }

        self.assertEqual(github.file_issues(), 1)
        number, text = mockGithubRepo.update_issue.call_args[0]
        self.assertEqual(number, TEST_ISSUE_ID)
        self.assertIn('#### Resolved on: ####\n- [ ] [testdevice]', text)

        issue.refresh_from_db()
        self.assertFalse(issue.closed)

    def test_update_ra_closed(self):
        ra = RecommendedAction.objects.create(action_class=self.TestAction.__name__, action_param='param')
        RecommendedActionStatus.objects.create(device=self.device, status=RecommendedAction.Status.AFFECTED, ra=ra)
        issue = GithubIssue.objects.create(number=TEST_ISSUE_ID, owner=self.user, closed=True)
        mockGithubRepo.list_issues.return_value = {
            'open': [],
            'closed': [TEST_ISSUE_ID]
        }

        self.assertEqual(github.file_issues(), 1)
        number, text = mockGithubRepo.update_issue.call_args[0]
        self.assertEqual(number, TEST_ISSUE_ID)
        self.assertIn('#### Resolved on: ####\n- [ ] [testdevice]', text)

        issue.refresh_from_db()
        self.assertFalse(issue.closed)

    def test_resolve_ra(self):
        ra = RecommendedAction.objects.create(action_class=self.TestAction.__name__, action_param='param')
        RecommendedActionStatus.objects.create(device=self.device, status=RecommendedAction.Status.NOT_AFFECTED,
                                               resolved_at=timezone.now(), ra=ra)
        issue = GithubIssue.objects.create(number=TEST_ISSUE_ID, owner=self.user)
        mockGithubRepo.list_issues.return_value = {
            'open': [TEST_ISSUE_ID],
            'closed': []
        }

        self.assertEqual(github.file_issues(), 1)
        number = mockGithubRepo.close_issue.call_args[0][0]
        self.assertEqual(number, TEST_ISSUE_ID)

        issue.refresh_from_db()
        self.assertTrue(issue.closed)

    def test_partly_resolve_ra(self):
        ra = RecommendedAction.objects.create(action_class=self.TestAction.__name__, action_param='param')
        RecommendedActionStatus.objects.create(device=self.device, status=RecommendedAction.Status.AFFECTED,
                                               ra=ra)
        RecommendedActionStatus.objects.create(device=self.device1, status=RecommendedAction.Status.NOT_AFFECTED,
                                               resolved_at=timezone.now(), ra=ra)
        issue = GithubIssue.objects.create(number=TEST_ISSUE_ID, owner=self.user)
        mockGithubRepo.list_issues.return_value = {
            'open': [TEST_ISSUE_ID],
            'closed': []
        }

        self.assertEqual(github.file_issues(), 1)
        number, text = mockGithubRepo.update_issue.call_args[0]
        self.assertEqual(number, TEST_ISSUE_ID)
        self.assertIn('#### Resolved on: ####\n- [ ] [testdevice]', text)
        self.assertIn('- [x] [testdevice1]', text)

        issue.refresh_from_db()
        self.assertFalse(issue.closed)