"""
RBAC tests for Jira integration endpoints.

Tests that Jira ticket creation and unlinking respect report edit permissions:
- System admins: always allowed
- Org admins/owners: allowed for reports in their org
- Consultants: allowed for reports they created
- Readonly: denied (can view but not edit)
- Non-members: denied
"""
import json
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import app
from app.db import get_adapter
from app.services.auth import get_current_user

client = TestClient(app)


def _make_client_as(user):
    """Return a TestClient that authenticates as the given user."""
    app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app)


def _mock_jira_client():
    """Mock successful Jira client operations."""
    mock_client = type('obj', (object,), {
        'create_issue': lambda *args, **kwargs: (True, "Created TEST-123: https://test.atlassian.net/browse/TEST-123", "TEST-123"),
        'test_connection': lambda *args, **kwargs: (True, "Connected"),
        'list_projects': lambda *args, **kwargs: []
    })()
    return mock_client


def _mock_jira_client_and_connector():
    """Mock successful Jira client operations and connector.
    
    Returns tuple of (client, connector) to match _get_jira_client_or_error signature.
    """
    mock_client = _mock_jira_client()
    mock_connector = type('obj', (object,), {
        'id': 'test-connector-id',
        'config': json.dumps({'url': 'https://test.atlassian.net'}),
        'enabled': True,
        'organization_id': 'test-org-id'
    })()
    return (mock_client, mock_connector)


@pytest.fixture(autouse=True)
def cleanup_overrides():
    """Reset dependency overrides after each test."""
    yield
    app.dependency_overrides.clear()


@pytest.fixture()
def org_with_jira():
    """
    Set up an org with Jira connector and various users.
    
    Returns: (org, system_admin, org_admin, consultant, readonly, report, finding)
    """
    adapter = get_adapter()
    
    # Create org
    org = adapter.create_organization(name="Jira Test Org", slug="jira-test-org")
    
    # Create users with different roles
    system_admin = adapter.upsert_user(
        email="sysadmin@test.com", name="System Admin", provider="local", role="admin"
    )
    
    org_admin = adapter.upsert_user(
        email="orgadmin@test.com", name="Org Admin", provider="local", role="user"
    )
    adapter.create_organization_member(org_id=org.id, user_id=org_admin.id, role="org_admin")
    
    consultant = adapter.upsert_user(
        email="consultant@test.com", name="Consultant", provider="local", role="user"
    )
    adapter.create_organization_member(org_id=org.id, user_id=consultant.id, role="consultant")
    
    readonly = adapter.upsert_user(
        email="readonly@test.com", name="ReadOnly", provider="local", role="user"
    )
    adapter.create_organization_member(org_id=org.id, user_id=readonly.id, role="readonly")
    
    # Create Jira connector
    connector = adapter.create_connector(
        type="jira",
        name="Test Jira",
        config=json.dumps({
            "url": "https://test.atlassian.net",
            "email": "test@example.com",
            "api_token": "fake_token"
        })
    )
    adapter.update_connector(connector.id, connector.name, connector.config, enabled=True)
    
    # Create report by consultant
    client = adapter.create_client("Test Team", organization_id=org.id)
    app_row = adapter.create_application("Test App", organization_id=org.id)
    report = adapter.create_report(
        "Test Report",
        organization_id=org.id,
        created_by=consultant.id,
        client_id=client.id,
        application_id=app_row.id,
    )
    
    # Create finding
    finding = adapter.create_finding(
        report_id=report.id,
        title="Test Vulnerability",
        notes="Test notes",
        template="",
        content_json=json.dumps({
            "Severity": "High",
            "Vulnerability Summary": "Test summary"
        }),
        evidence_payload="{}",
        organization_id=org.id
    )
    
    return org, system_admin, org_admin, consultant, readonly, report, finding


class TestJiraCreateIssuePermissions:
    """Test that only users with EDIT permission can create Jira tickets."""
    
    @patch('app.api.admin._get_jira_client_or_error')
    def test_system_admin_can_create_ticket(self, mock_get_client, org_with_jira):
        """System admin can create Jira ticket for any finding."""
        _, system_admin, _, _, _, _, finding = org_with_jira
        mock_get_client.return_value = _mock_jira_client_and_connector()
        
        client = _make_client_as(system_admin)
        resp = client.post(
            "/api/admin/connectors/jira/create-issue",
            json={
                "finding_id": finding.id,
                "project_key": "TEST",
                "issue_type": "Bug"
            }
        )
        
        assert resp.status_code == 200, f"System admin should be allowed: {resp.text}"
        data = resp.json()
        assert data["success"] is True
        assert data["issue_key"] == "TEST-123"
    
    @patch('app.api.admin._get_jira_client_or_error')
    def test_org_admin_can_create_ticket(self, mock_get_client, org_with_jira):
        """Org admin can create Jira ticket for findings in their org."""
        _, _, org_admin, _, _, _, finding = org_with_jira
        mock_get_client.return_value = _mock_jira_client_and_connector()
        
        client = _make_client_as(org_admin)
        resp = client.post(
            "/api/admin/connectors/jira/create-issue",
            json={
                "finding_id": finding.id,
                "project_key": "TEST",
                "issue_type": "Bug"
            }
        )
        
        assert resp.status_code == 200, f"Org admin should be allowed: {resp.text}"
        data = resp.json()
        assert data["success"] is True
    
    @patch('app.api.admin._get_jira_client_or_error')
    def test_consultant_creator_can_create_ticket(self, mock_get_client, org_with_jira):
        """Consultant who created the report can create Jira ticket."""
        _, _, _, consultant, _, _, finding = org_with_jira
        mock_get_client.return_value = _mock_jira_client_and_connector()
        
        client = _make_client_as(consultant)
        resp = client.post(
            "/api/admin/connectors/jira/create-issue",
            json={
                "finding_id": finding.id,
                "project_key": "TEST",
                "issue_type": "Bug"
            }
        )
        
        assert resp.status_code == 200, f"Report creator should be allowed: {resp.text}"
        data = resp.json()
        assert data["success"] is True
    
    @patch('app.api.admin._get_jira_client_or_error')
    def test_readonly_cannot_create_ticket(self, mock_get_client, org_with_jira):
        """Readonly user cannot create Jira ticket."""
        _, _, _, _, readonly, _, finding = org_with_jira
        mock_get_client.return_value = _mock_jira_client_and_connector()
        
        client = _make_client_as(readonly)
        resp = client.post(
            "/api/admin/connectors/jira/create-issue",
            json={
                "finding_id": finding.id,
                "project_key": "TEST",
                "issue_type": "Bug"
            }
        )
        
        assert resp.status_code == 403, f"Readonly should be denied, got {resp.status_code}: {resp.text}"
    
    @patch('app.api.admin._get_jira_client_or_error')
    def test_non_member_cannot_create_ticket(self, mock_get_client, org_with_jira):
        """User not in org cannot create Jira ticket."""
        _, _, _, _, _, _, finding = org_with_jira
        mock_get_client.return_value = _mock_jira_client_and_connector()
        
        adapter = get_adapter()
        outsider = adapter.upsert_user(
            email="outsider@test.com", name="Outsider", provider="local", role="user"
        )
        
        client = _make_client_as(outsider)
        resp = client.post(
            "/api/admin/connectors/jira/create-issue",
            json={
                "finding_id": finding.id,
                "project_key": "TEST",
                "issue_type": "Bug"
            }
        )
        
        assert resp.status_code == 403, f"Non-member should be denied, got {resp.status_code}: {resp.text}"


class TestJiraUnlinkPermissions:
    """Test that only users with EDIT permission can unlink Jira tickets."""
    
    def test_system_admin_can_unlink_ticket(self, org_with_jira):
        """System admin can unlink Jira ticket from any finding."""
        _, system_admin, _, _, _, _, finding = org_with_jira
        
        # First add a ticket link
        adapter = get_adapter()
        adapter.update_finding(
            finding_id=finding.id,
            jira_issue_key="TEST-123",
            jira_issue_url="https://test.atlassian.net/browse/TEST-123"
        )
        
        client = _make_client_as(system_admin)
        resp = client.delete(f"/api/admin/connectors/jira/unlink/{finding.id}")
        
        assert resp.status_code == 200, f"System admin should be allowed: {resp.text}"
        
        # Verify it was unlinked
        updated = adapter.get_finding(finding.id)
        assert updated.jira_issue_key == ""
        assert updated.jira_issue_url == ""
    
    def test_org_admin_can_unlink_ticket(self, org_with_jira):
        """Org admin can unlink Jira ticket from findings in their org."""
        _, _, org_admin, _, _, _, finding = org_with_jira
        
        adapter = get_adapter()
        adapter.update_finding(
            finding_id=finding.id,
            jira_issue_key="TEST-456",
            jira_issue_url="https://test.atlassian.net/browse/TEST-456"
        )
        
        client = _make_client_as(org_admin)
        resp = client.delete(f"/api/admin/connectors/jira/unlink/{finding.id}")
        
        assert resp.status_code == 200, f"Org admin should be allowed: {resp.text}"
        
        updated = adapter.get_finding(finding.id)
        assert updated.jira_issue_key == ""
    
    def test_consultant_creator_can_unlink_ticket(self, org_with_jira):
        """Consultant who created the report can unlink Jira ticket."""
        _, _, _, consultant, _, _, finding = org_with_jira
        
        adapter = get_adapter()
        adapter.update_finding(
            finding_id=finding.id,
            jira_issue_key="TEST-789",
            jira_issue_url="https://test.atlassian.net/browse/TEST-789"
        )
        
        client = _make_client_as(consultant)
        resp = client.delete(f"/api/admin/connectors/jira/unlink/{finding.id}")
        
        assert resp.status_code == 200, f"Report creator should be allowed: {resp.text}"
        
        updated = adapter.get_finding(finding.id)
        assert updated.jira_issue_key == ""
    
    def test_readonly_cannot_unlink_ticket(self, org_with_jira):
        """Readonly user cannot unlink Jira ticket."""
        _, _, _, _, readonly, _, finding = org_with_jira
        
        adapter = get_adapter()
        adapter.update_finding(
            finding_id=finding.id,
            jira_issue_key="TEST-999",
            jira_issue_url="https://test.atlassian.net/browse/TEST-999"
        )
        
        client = _make_client_as(readonly)
        resp = client.delete(f"/api/admin/connectors/jira/unlink/{finding.id}")
        
        assert resp.status_code == 403, f"Readonly should be denied, got {resp.status_code}: {resp.text}"
        
        # Verify it was NOT unlinked
        updated = adapter.get_finding(finding.id)
        assert updated.jira_issue_key == "TEST-999"
    
    def test_non_member_cannot_unlink_ticket(self, org_with_jira):
        """User not in org cannot unlink Jira ticket."""
        _, _, _, _, _, _, finding = org_with_jira
        
        adapter = get_adapter()
        adapter.update_finding(
            finding_id=finding.id,
            jira_issue_key="TEST-111",
            jira_issue_url="https://test.atlassian.net/browse/TEST-111"
        )
        
        outsider = adapter.upsert_user(
            email="outsider@test.com", name="Outsider", provider="local", role="user"
        )
        
        client = _make_client_as(outsider)
        resp = client.delete(f"/api/admin/connectors/jira/unlink/{finding.id}")
        
        assert resp.status_code == 403, f"Non-member should be denied, got {resp.status_code}: {resp.text}"
        
        # Verify it was NOT unlinked
        updated = adapter.get_finding(finding.id)
        assert updated.jira_issue_key == "TEST-111"


class TestJiraEndToEnd:
    """Test the full Jira workflow with proper permissions."""
    
    @patch('app.api.admin._get_jira_client_or_error')
    def test_create_and_unlink_workflow(self, mock_get_client, org_with_jira):
        """Test creating a ticket and then unlinking it."""
        _, _, org_admin, _, _, _, finding = org_with_jira
        mock_get_client.return_value = _mock_jira_client_and_connector()
        
        adapter = get_adapter()
        client = _make_client_as(org_admin)
        
        # 1. Create ticket
        resp = client.post(
            "/api/admin/connectors/jira/create-issue",
            json={
                "finding_id": finding.id,
                "project_key": "TEST",
                "issue_type": "Bug"
            }
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["issue_key"] == "TEST-123"
        assert data["issue_url"] == "https://test.atlassian.net/browse/TEST-123"
        
        # 2. Verify finding was updated
        updated = adapter.get_finding(finding.id)
        assert updated.jira_issue_key == "TEST-123"
        assert updated.jira_issue_url == "https://test.atlassian.net/browse/TEST-123"
        
        # 3. Unlink ticket
        resp = client.delete(f"/api/admin/connectors/jira/unlink/{finding.id}")
        assert resp.status_code == 200
        
        # 4. Verify finding was cleared
        updated = adapter.get_finding(finding.id)
        assert updated.jira_issue_key == ""
        assert updated.jira_issue_url == ""
    
    @patch('app.api.admin._get_jira_client_or_error')
    def test_cannot_create_duplicate_ticket(self, mock_get_client, org_with_jira):
        """Prevent duplicate ticket creation: finding already linked should return 400."""
        _, _, org_admin, _, _, _, finding = org_with_jira
        mock_get_client.return_value = _mock_jira_client_and_connector()
        
        adapter = get_adapter()
        
        # Set existing ticket
        adapter.update_finding(
            finding_id=finding.id,
            jira_issue_key="OLD-123",
            jira_issue_url="https://test.atlassian.net/browse/OLD-123"
        )
        
        client = _make_client_as(org_admin)
        
        # Attempt to create new ticket (should be rejected)
        resp = client.post(
            "/api/admin/connectors/jira/create-issue",
            json={
                "finding_id": finding.id,
                "project_key": "TEST",
                "issue_type": "Bug"
            }
        )
        
        assert resp.status_code == 400
        assert "already linked" in resp.json()['detail'].lower()
        
        # Verify old ticket was NOT replaced
        updated = adapter.get_finding(finding.id)
        assert updated.jira_issue_key == "OLD-123"
        assert updated.jira_issue_url == "https://test.atlassian.net/browse/OLD-123"
    
    def test_atomic_jira_link_prevents_race_condition(self, org_with_jira):
        """Test that atomic_set_jira_link prevents concurrent requests from creating duplicate tickets."""
        _, _, org_admin, _, _, _, finding = org_with_jira
        adapter = get_adapter()
        
        # Simulate race: two threads try to link different Jira issues to the same finding
        success1, existing1 = adapter.atomic_set_jira_link(
            finding_id=finding.id,
            jira_issue_key="RACE-111",
            jira_issue_url="https://test.atlassian.net/browse/RACE-111"
        )
        
        success2, existing2 = adapter.atomic_set_jira_link(
            finding_id=finding.id,
            jira_issue_key="RACE-222",
            jira_issue_url="https://test.atlassian.net/browse/RACE-222"
        )
        
        # First should succeed, second should fail
        assert success1 is True
        assert existing1 is None
        
        assert success2 is False
        assert existing2 == "RACE-111", "Should return the key that won the race"
        
        # Verify finding has the first key
        updated = adapter.get_finding(finding.id)
        assert updated.jira_issue_key == "RACE-111"
        assert updated.jira_issue_url == "https://test.atlassian.net/browse/RACE-111"


class TestCrossOrgJiraIsolation:
    """Test that Jira operations respect org boundaries."""
    
    @patch('app.api.admin._get_jira_client_or_error')
    def test_cannot_create_ticket_for_other_org_finding(self, mock_get_client, org_with_jira):
        """User in org A cannot create Jira ticket for org B's finding."""
        org_a, _, _, _, _, _, finding_a = org_with_jira
        mock_get_client.return_value = _mock_jira_client_and_connector()
        
        adapter = get_adapter()
        
        # Create second org and user
        org_b = adapter.create_organization(name="Org B", slug="org-b")
        user_b_admin = adapter.upsert_user(
            email="userb@test.com", name="User B", provider="local", role="user"
        )
        adapter.create_organization_member(org_id=org_b.id, user_id=user_b_admin.id, role="org_admin")
        
        # Try to create ticket for org A's finding as org B admin
        client = _make_client_as(user_b_admin)
        resp = client.post(
            "/api/admin/connectors/jira/create-issue",
            json={
                "finding_id": finding_a.id,
                "project_key": "TEST",
                "issue_type": "Bug"
            }
        )
        
        assert resp.status_code == 403, f"Cross-org access should be denied, got {resp.status_code}"
    
    def test_cannot_unlink_ticket_for_other_org_finding(self, org_with_jira):
        """User in org A cannot unlink Jira ticket from org B's finding."""
        org_a, _, _, _, _, _, finding_a = org_with_jira
        
        adapter = get_adapter()
        
        # Set ticket on finding A
        adapter.update_finding(
            finding_id=finding_a.id,
            jira_issue_key="TEST-999",
            jira_issue_url="https://test.atlassian.net/browse/TEST-999"
        )
        
        # Create second org and user
        org_b = adapter.create_organization(name="Org B", slug="org-b")
        user_b_admin = adapter.upsert_user(
            email="userb@test.com", name="User B", provider="local", role="user"
        )
        adapter.create_organization_member(org_id=org_b.id, user_id=user_b_admin.id, role="org_admin")
        
        # Try to unlink org A's finding as org B admin
        client = _make_client_as(user_b_admin)
        resp = client.delete(f"/api/admin/connectors/jira/unlink/{finding_a.id}")
        
        assert resp.status_code == 403, f"Cross-org access should be denied, got {resp.status_code}"
        
        # Verify ticket was NOT unlinked
        updated = adapter.get_finding(finding_a.id)
        assert updated.jira_issue_key == "TEST-999"
