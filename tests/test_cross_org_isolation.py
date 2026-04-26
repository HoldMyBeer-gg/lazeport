"""
Critical Security Tests: Cross-Organization Data Isolation

These tests verify that users from one organization CANNOT access
resources (clients, applications, reports, findings) from another organization.

This is a fundamental security requirement for multi-tenant systems.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db import get_adapter
from app.services.auth import get_current_user


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def setup_two_orgs(client):
    """Create two organizations with users, clients, reports, and findings."""
    adapter = get_adapter()
    adapter.init()
    
    # Organization A
    org_a = adapter.create_organization(name="Org A", slug="org-a")
    user_a = adapter.upsert_user(email="usera@test.com", name="User A", provider="local", role="user")
    adapter.create_organization_member(org_id=org_a.id, user_id=user_a.id, role="consultant")
    client_a = adapter.create_client("Team A", organization_id=org_a.id)
    app_a = adapter.create_application("App A", organization_id=org_a.id)
    report_a = adapter.create_report("Report A", organization_id=org_a.id, created_by=user_a.id, client_id=client_a.id, application_id=app_a.id)
    finding_a = adapter.create_finding(
        report_id=report_a.id,
        title="Finding A",
        notes="notes a",
        template="",
        content_json="{}",
        organization_id=org_a.id
    )
    
    # Organization B
    org_b = adapter.create_organization(name="Org B", slug="org-b")
    user_b = adapter.upsert_user(email="userb@test.com", name="User B", provider="local", role="user")
    adapter.create_organization_member(org_id=org_b.id, user_id=user_b.id, role="consultant")
    client_b = adapter.create_client("Team B", organization_id=org_b.id)
    app_b = adapter.create_application("App B", organization_id=org_b.id)
    report_b = adapter.create_report("Report B", organization_id=org_b.id, created_by=user_b.id, client_id=client_b.id, application_id=app_b.id)
    finding_b = adapter.create_finding(
        report_id=report_b.id,
        title="Finding B",
        notes="notes b",
        template="",
        content_json="{}",
        organization_id=org_b.id
    )
    
    return {
        "org_a": org_a,
        "user_a": user_a,
        "client_a": client_a,
        "app_a": app_a,
        "report_a": report_a,
        "finding_a": finding_a,
        "org_b": org_b,
        "user_b": user_b,
        "client_b": client_b,
        "app_b": app_b,
        "report_b": report_b,
        "finding_b": finding_b,
    }


def test_user_cannot_list_other_org_clients(client, setup_two_orgs):
    """User A cannot see clients from Org B."""
    data = setup_two_orgs
    
    # Authenticate as User A
    app.dependency_overrides[get_current_user] = lambda: data["user_a"]
    
    response = client.get("/api/admin/clients")
    assert response.status_code == 200
    clients = response.json()
    client_names = [t["name"] for t in clients]
    
    # User A should see Team A
    assert "Team A" in client_names
    # User A should NOT see Team B
    assert "Team B" not in client_names
    
    app.dependency_overrides.clear()


def test_user_cannot_update_other_org_client(client, setup_two_orgs):
    """User A cannot update a client from Org B."""
    data = setup_two_orgs
    
    # Authenticate as User A
    app.dependency_overrides[get_current_user] = lambda: data["user_a"]
    
    response = client.put(
        f"/api/admin/clients/{data['client_b'].id}",
        json={"name": "Hacked Team B"}
    )
    
    # Should be forbidden
    assert response.status_code == 403
    assert "different organization" in response.json()["detail"].lower()
    
    app.dependency_overrides.clear()


def test_user_cannot_delete_other_org_client(client, setup_two_orgs):
    """User A cannot delete a client from Org B."""
    data = setup_two_orgs
    
    # Authenticate as User A
    app.dependency_overrides[get_current_user] = lambda: data["user_a"]
    
    response = client.delete(f"/api/admin/clients/{data['client_b'].id}")
    
    # Should be forbidden
    assert response.status_code == 403
    assert "different organization" in response.json()["detail"].lower()
    
    app.dependency_overrides.clear()


def test_user_cannot_list_other_org_applications(client, setup_two_orgs):
    """User A cannot see applications from Org B."""
    data = setup_two_orgs
    
    # Authenticate as User A
    app.dependency_overrides[get_current_user] = lambda: data["user_a"]
    
    response = client.get("/api/admin/applications")
    assert response.status_code == 200
    apps = response.json()
    app_names = [a["name"] for a in apps]
    
    # User A should see App A
    assert "App A" in app_names
    # User A should NOT see App B
    assert "App B" not in app_names
    
    app.dependency_overrides.clear()


def test_user_cannot_update_other_org_application(client, setup_two_orgs):
    """User A cannot update an application from Org B."""
    data = setup_two_orgs
    
    # Authenticate as User A
    app.dependency_overrides[get_current_user] = lambda: data["user_a"]
    
    response = client.put(
        f"/api/admin/applications/{data['app_b'].id}",
        json={"name": "Hacked App B"}
    )
    
    # Should be forbidden
    assert response.status_code == 403
    assert "different organization" in response.json()["detail"].lower()
    
    app.dependency_overrides.clear()


def test_user_cannot_view_other_org_report(client, setup_two_orgs):
    """User A cannot view a report from Org B."""
    data = setup_two_orgs
    
    # Authenticate as User A
    app.dependency_overrides[get_current_user] = lambda: data["user_a"]
    
    response = client.get(f"/api/admin/reports/{data['report_b'].id}")
    
    # Should be forbidden (can_view_report checks org membership)
    assert response.status_code == 403
    
    app.dependency_overrides.clear()


def test_user_cannot_list_other_org_reports(client, setup_two_orgs):
    """User A cannot see reports from Org B in list."""
    data = setup_two_orgs
    
    # Authenticate as User A
    app.dependency_overrides[get_current_user] = lambda: data["user_a"]
    
    response = client.get("/api/admin/reports")
    assert response.status_code == 200
    reports = response.json()
    report_names = [r["name"] for r in reports]
    
    # User A should see Report A
    assert "Report A" in report_names
    # User A should NOT see Report B
    assert "Report B" not in report_names
    
    app.dependency_overrides.clear()


def test_user_cannot_update_other_org_finding(client, setup_two_orgs):
    """User A cannot update a finding from Org B."""
    data = setup_two_orgs
    
    # Authenticate as User A
    app.dependency_overrides[get_current_user] = lambda: data["user_a"]
    
    response = client.put(
        f"/api/admin/findings/{data['finding_b'].id}",
        json={
            "title": "Hacked Finding B",
            "content_json": "{}",
            "notes": "hacked",
            "template": ""
        }
    )
    
    # Should be forbidden (via _require_report_edit)
    assert response.status_code == 403
    
    app.dependency_overrides.clear()


def test_user_cannot_delete_other_org_finding(client, setup_two_orgs):
    """User A cannot delete a finding from Org B."""
    data = setup_two_orgs
    
    # Authenticate as User A
    app.dependency_overrides[get_current_user] = lambda: data["user_a"]
    
    response = client.delete(f"/api/admin/findings/{data['finding_b'].id}")
    
    # Should be forbidden
    assert response.status_code == 403
    
    app.dependency_overrides.clear()


def test_user_cannot_cancel_other_org_import_session(client, setup_two_orgs):
    """User A cannot cancel import sessions belonging to Org B reports."""
    data = setup_two_orgs
    adapter = get_adapter()
    sess_b = adapter.create_burp_import_session(
        report_id=data["report_b"].id,
        file_name="org-b.sarif",
        content_hash="org-b-cancel-test",
        tasks_json='[{"index":0,"status":"pending","finding":{"name":"B"}}]',
    )

    app.dependency_overrides[get_current_user] = lambda: data["user_a"]
    response = client.post(f"/api/admin/import-sessions/{sess_b.id}/cancel-pending")
    assert response.status_code == 403
    app.dependency_overrides.clear()


def test_system_admin_can_access_all_orgs(client, setup_two_orgs):
    """System admin can access resources from any organization."""
    data = setup_two_orgs
    adapter = get_adapter()
    
    # Create system admin
    admin = adapter.upsert_user(email="admin@test.com", name="Admin", provider="local", role="admin")
    
    # Authenticate as system admin
    app.dependency_overrides[get_current_user] = lambda: admin
    
    # Admin can see all clients
    response = client.get("/api/admin/clients")
    assert response.status_code == 200
    clients = response.json()
    client_names = [t["name"] for t in clients]
    assert "Team A" in client_names
    assert "Team B" in client_names
    
    # Admin can access Report A
    response = client.get(f"/api/admin/reports/{data['report_a'].id}")
    assert response.status_code == 200
    
    # Admin can access Report B
    response = client.get(f"/api/admin/reports/{data['report_b'].id}")
    assert response.status_code == 200
    
    app.dependency_overrides.clear()
