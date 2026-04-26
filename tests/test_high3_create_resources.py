"""Tests for HIGH-3: Create Team/Connector Omit organization_id.

Tests verify that clients and connectors are created in the user's organization,
not in the System org, preventing multi-tenant isolation issues.
"""
import pytest
import json
from fastapi.testclient import TestClient
from app.main import app
from app.db import get_adapter
from app.services.auth import get_current_user, hash_password


def _make_client_as(user):
    """Return a TestClient that authenticates as the given user."""
    app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app)


@pytest.fixture(autouse=True)
def cleanup_overrides():
    """Reset dependency overrides after each test."""
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def multi_org_setup():
    """Create two organizations with admins."""
    adapter = get_adapter()
    adapter.init()
    
    # Create Organization A
    org_a = adapter.create_organization(name="Organization A", slug="org-a-res")
    admin_a = adapter.upsert_user(
        email="admin-a@orga.com",
        name="Admin A",
        provider="local",
        role="user"
    )
    adapter.set_user_password_hash(admin_a.id, hash_password("password123"))
    adapter.create_organization_member(org_a.id, admin_a.id, "org_admin")
    
    # Create Organization B
    org_b = adapter.create_organization(name="Organization B", slug="org-b-res")
    admin_b = adapter.upsert_user(
        email="admin-b@orgb.com",
        name="Admin B",
        provider="local",
        role="user"
    )
    adapter.set_user_password_hash(admin_b.id, hash_password("password123"))
    adapter.create_organization_member(org_b.id, admin_b.id, "org_admin")
    
    return {
        "org_a": org_a,
        "org_b": org_b,
        "admin_a": admin_a,
        "admin_b": admin_b,
    }


def test_create_client_uses_user_org_not_system_org(multi_org_setup):
    """Test that creating a client assigns it to user's org, not System org (HIGH-3 fix)."""
    setup = multi_org_setup
    adapter = get_adapter()
    
    # Org A admin creates a client
    client = _make_client_as(setup["admin_a"])
    response = client.post(
        "/api/admin/clients",
        json={"name": "Test Team A"}
    )
    
    assert response.status_code == 200
    client = response.json()
    
    # Verify client is assigned to Org A, not System org
    assert client["organization_id"] == setup["org_a"].id
    assert client["organization_id"] != "00000000-0000-0000-0000-000000000001"
    
    # Double-check in database
    db_client = adapter.get_client(client["id"])
    assert db_client.organization_id == setup["org_a"].id


def test_create_connector_uses_user_org_not_system_org(multi_org_setup):
    """Test that creating a connector assigns it to user's org, not System org (HIGH-3 fix)."""
    setup = multi_org_setup
    adapter = get_adapter()
    
    # Org A admin creates a connector
    client = _make_client_as(setup["admin_a"])
    response = client.post(
        "/api/admin/connectors",
        json={
            "name": "Test Jira A",
            "type": "jira",
            "config": {
                "url": "https://jira-a.example.com",
                "api_token": "test-token",
                "project_key": "TEST"
            },
            "enabled": True
        }
    )
    
    assert response.status_code == 200
    connector = response.json()
    
    # Verify connector is assigned to Org A, not System org
    assert connector["organization_id"] == setup["org_a"].id
    assert connector["organization_id"] != "00000000-0000-0000-0000-000000000001"
    
    # Double-check in database
    db_connector = adapter.get_connector(connector["id"])
    assert db_connector.organization_id == setup["org_a"].id


def test_org_b_creates_client_in_org_b(multi_org_setup):
    """Test that Org B admin creates client in Org B."""
    setup = multi_org_setup
    adapter = get_adapter()
    
    # Org B admin creates a client
    client = _make_client_as(setup["admin_b"])
    response = client.post(
        "/api/admin/clients",
        json={"name": "Test Team B"}
    )
    
    assert response.status_code == 200
    client = response.json()
    
    # Should be in Org B
    assert client["organization_id"] == setup["org_b"].id
    
    # Verify in database
    db_client = adapter.get_client(client["id"])
    assert db_client.organization_id == setup["org_b"].id


def test_org_b_creates_connector_in_org_b(multi_org_setup):
    """Test that Org B admin creates connector in Org B."""
    setup = multi_org_setup
    adapter = get_adapter()
    
    # Org B admin creates a connector
    client = _make_client_as(setup["admin_b"])
    response = client.post(
        "/api/admin/connectors",
        json={
            "name": "Test Jira B",
            "type": "jira",
            "config": {
                "url": "https://jira-b.example.com",
                "api_token": "test-token-b",
                "project_key": "TESTB"
            },
            "enabled": True
        }
    )
    
    assert response.status_code == 200
    connector = response.json()
    
    # Should be in Org B
    assert connector["organization_id"] == setup["org_b"].id
    
    # Verify in database
    db_connector = adapter.get_connector(connector["id"])
    assert db_connector.organization_id == setup["org_b"].id


def test_clients_are_isolated_per_org(multi_org_setup):
    """Test that clients created by different orgs are properly isolated."""
    setup = multi_org_setup
    adapter = get_adapter()
    
    # Org A admin creates a client
    client_a = _make_client_as(setup["admin_a"])
    response_a = client_a.post(
        "/api/admin/clients",
        json={"name": "Isolated Team A"}
    )
    assert response_a.status_code == 200
    client_a = response_a.json()
    
    # Org B admin creates a client
    app.dependency_overrides.clear()
    client_b = _make_client_as(setup["admin_b"])
    response_b = client_b.post(
        "/api/admin/clients",
        json={"name": "Isolated Team B"}
    )
    assert response_b.status_code == 200
    client_b = response_b.json()
    
    # Verify different organizations
    assert client_a["organization_id"] == setup["org_a"].id
    assert client_b["organization_id"] == setup["org_b"].id
    assert client_a["organization_id"] != client_b["organization_id"]
    
    # Verify via adapter that clients exist in correct orgs
    clients_a = list(adapter.list_clients(organization_id=setup["org_a"].id))
    clients_b = list(adapter.list_clients(organization_id=setup["org_b"].id))
    
    client_a_ids = [t.id for t in clients_a]
    client_b_ids = [t.id for t in clients_b]
    
    assert client_a["id"] in client_a_ids
    assert client_a["id"] not in client_b_ids
    assert client_b["id"] in client_b_ids
    assert client_b["id"] not in client_a_ids


def test_connectors_are_isolated_per_org(multi_org_setup):
    """Test that connectors created by different orgs are properly isolated."""
    setup = multi_org_setup
    adapter = get_adapter()
    
    # Org A admin creates a connector
    client_a = _make_client_as(setup["admin_a"])
    response_a = client_a.post(
        "/api/admin/connectors",
        json={
            "name": "Isolated Jira A",
            "type": "jira",
            "config": {
                "url": "https://isolated-a.example.com",
                "api_token": "token-a",
                "project_key": "ISOA"
            },
            "enabled": True
        }
    )
    assert response_a.status_code == 200
    connector_a = response_a.json()
    
    # Org B admin creates a connector
    app.dependency_overrides.clear()
    client_b = _make_client_as(setup["admin_b"])
    response_b = client_b.post(
        "/api/admin/connectors",
        json={
            "name": "Isolated Jira B",
            "type": "jira",
            "config": {
                "url": "https://isolated-b.example.com",
                "api_token": "token-b",
                "project_key": "ISOB"
            },
            "enabled": True
        }
    )
    assert response_b.status_code == 200
    connector_b = response_b.json()
    
    # Verify different organizations
    assert connector_a["organization_id"] == setup["org_a"].id
    assert connector_b["organization_id"] == setup["org_b"].id
    assert connector_a["organization_id"] != connector_b["organization_id"]
    
    # Verify via adapter that connectors exist in correct orgs
    connectors_a = list(adapter.list_connectors(organization_id=setup["org_a"].id))
    connectors_b = list(adapter.list_connectors(organization_id=setup["org_b"].id))
    
    connector_a_ids = [c.id for c in connectors_a]
    connector_b_ids = [c.id for c in connectors_b]
    
    assert connector_a["id"] in connector_a_ids
    assert connector_a["id"] not in connector_b_ids
    assert connector_b["id"] in connector_b_ids
    assert connector_b["id"] not in connector_a_ids


def test_user_without_org_cannot_create_client(multi_org_setup):
    """Test that user without org membership cannot create clients."""
    adapter = get_adapter()
    
    # Create user without org membership
    orphan_user = adapter.upsert_user(
        email="orphan@nowhere.com",
        name="Orphan User",
        provider="local",
        role="user"
    )
    
    client = _make_client_as(orphan_user)
    response = client.post(
        "/api/admin/clients",
        json={"name": "Orphan Team"}
    )
    
    # Should be forbidden
    assert response.status_code == 403


def test_user_without_org_cannot_create_connector(multi_org_setup):
    """Test that user without org membership cannot create connectors."""
    adapter = get_adapter()
    
    # Create user without org membership
    orphan_user = adapter.upsert_user(
        email="orphan@nowhere.com",
        name="Orphan User",
        provider="local",
        role="user"
    )
    
    client = _make_client_as(orphan_user)
    response = client.post(
        "/api/admin/connectors",
        json={
            "name": "Orphan Jira",
            "type": "jira",
            "config": {
                "url": "https://orphan.example.com",
                "api_token": "token",
                "project_key": "ORPHAN"
            },
            "enabled": True
        }
    )
    
    # Should be forbidden
    assert response.status_code == 403


def test_multiple_clients_in_same_org_allowed(multi_org_setup):
    """Test that multiple clients can be created in the same org."""
    setup = multi_org_setup
    
    client = _make_client_as(setup["admin_a"])
    
    # Create first client
    response1 = client.post(
        "/api/admin/clients",
        json={"name": "First Team"}
    )
    assert response1.status_code == 200
    client1 = response1.json()
    
    # Create second client
    response2 = client.post(
        "/api/admin/clients",
        json={"name": "Second Team"}
    )
    assert response2.status_code == 200
    client2 = response2.json()
    
    # Both should be in same org
    assert client1["organization_id"] == setup["org_a"].id
    assert client2["organization_id"] == setup["org_a"].id
    assert client1["id"] != client2["id"]


def test_multiple_connectors_in_same_org_allowed(multi_org_setup):
    """Test that multiple connectors can be created in the same org."""
    setup = multi_org_setup
    
    client = _make_client_as(setup["admin_a"])
    
    # Create first connector
    response1 = client.post(
        "/api/admin/connectors",
        json={
            "name": "First Jira",
            "type": "jira",
            "config": {
                "url": "https://first.example.com",
                "api_token": "token1",
                "project_key": "FIRST"
            },
            "enabled": True
        }
    )
    assert response1.status_code == 200
    connector1 = response1.json()
    
    # Create second connector
    response2 = client.post(
        "/api/admin/connectors",
        json={
            "name": "Second Jira",
            "type": "jira",
            "config": {
                "url": "https://second.example.com",
                "api_token": "token2",
                "project_key": "SECOND"
            },
            "enabled": True
        }
    )
    assert response2.status_code == 200
    connector2 = response2.json()
    
    # Both should be in same org
    assert connector1["organization_id"] == setup["org_a"].id
    assert connector2["organization_id"] == setup["org_a"].id
    assert connector1["id"] != connector2["id"]


def test_client_creation_audit_logs_to_correct_org(multi_org_setup):
    """Test that client creation audit logs to the correct organization."""
    setup = multi_org_setup
    adapter = get_adapter()
    
    # Org A admin creates a client
    client = _make_client_as(setup["admin_a"])
    response = client.post(
        "/api/admin/clients",
        json={"name": "Audited Team"}
    )
    assert response.status_code == 200
    client = response.json()
    
    # Check audit logs for Org A
    logs = list(adapter.list_audit_logs(setup["org_a"].id, limit=10))
    create_logs = [
        log for log in logs
        if log.action == "create" and log.resource_type == "client" and log.resource_id == client["id"]
    ]
    assert len(create_logs) >= 1
    assert create_logs[0].organization_id == setup["org_a"].id


def test_connector_creation_audit_logs_to_correct_org(multi_org_setup):
    """Test that connector creation audit logs to the correct organization."""
    setup = multi_org_setup
    adapter = get_adapter()
    
    # Org B admin creates a connector
    client = _make_client_as(setup["admin_b"])
    response = client.post(
        "/api/admin/connectors",
        json={
            "name": "Audited Jira B",
            "type": "jira",
            "config": {
                "url": "https://audited-b.example.com",
                "api_token": "audit-token",
                "project_key": "AUDIT"
            },
            "enabled": True
        }
    )
    assert response.status_code == 200
    connector = response.json()
    
    # Check audit logs for Org B
    logs = list(adapter.list_audit_logs(setup["org_b"].id, limit=10))
    create_logs = [
        log for log in logs
        if log.action == "create" and log.resource_type == "connector" and log.resource_id == connector["id"]
    ]
    assert len(create_logs) >= 1
    assert create_logs[0].organization_id == setup["org_b"].id
