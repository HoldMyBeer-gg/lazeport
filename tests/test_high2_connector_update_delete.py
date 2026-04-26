"""Tests for HIGH-2: Connector Update/Delete Lack Org Ownership Check.

Tests verify that connector update and delete endpoints properly verify
that the connector belongs to the user's organization, preventing cross-org
resource manipulation.
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
def multi_org_connector_setup():
    """Create two organizations with connectors."""
    adapter = get_adapter()
    adapter.init()
    
    # Create Organization A
    org_a = adapter.create_organization(name="Organization A", slug="org-a")
    
    # Create admin for Org A
    admin_a = adapter.upsert_user(
        email="admin-a@orga.com",
        name="Admin A",
        provider="local",
        role="user"
    )
    adapter.set_user_password_hash(admin_a.id, hash_password("password123"))
    adapter.create_organization_member(org_a.id, admin_a.id, "org_admin")
    
    # Create connector for Org A
    connector_config_a = json.dumps({
        "url": "https://jira-a.example.com",
        "api_token": "token-a",
        "project_key": "PROJA"
    })
    connector_a = adapter.create_connector(
        type="jira",
        name="Jira A",
        config=connector_config_a,
        organization_id=org_a.id
    )
    
    # Create Organization B
    org_b = adapter.create_organization(name="Organization B", slug="org-b")
    
    # Create admin for Org B
    admin_b = adapter.upsert_user(
        email="admin-b@orgb.com",
        name="Admin B",
        provider="local",
        role="user"
    )
    adapter.set_user_password_hash(admin_b.id, hash_password("password123"))
    adapter.create_organization_member(org_b.id, admin_b.id, "org_admin")
    
    # Create connector for Org B
    connector_config_b = json.dumps({
        "url": "https://jira-b.example.com",
        "api_token": "token-b",
        "project_key": "PROJB"
    })
    connector_b = adapter.create_connector(
        type="jira",
        name="Jira B",
        config=connector_config_b,
        organization_id=org_b.id
    )
    
    # Create system admin
    system_admin = adapter.upsert_user(
        email="sysadmin@system.com",
        name="System Admin",
        provider="local",
        role="admin"
    )
    
    return {
        "org_a": org_a,
        "org_b": org_b,
        "admin_a": admin_a,
        "admin_b": admin_b,
        "connector_a": connector_a,
        "connector_b": connector_b,
        "system_admin": system_admin,
    }


def test_org_admin_cannot_update_other_org_connector(multi_org_connector_setup):
    """Test that Org A admin cannot update Org B's connector (HIGH-2 fix)."""
    setup = multi_org_connector_setup
    
    # Org A admin tries to update Org B's connector
    client = _make_client_as(setup["admin_a"])
    response = client.put(
        f"/api/admin/connectors/{setup['connector_b'].id}",
        json={
            "name": "Hacked Jira",
            "type": "jira",
            "config": {
                "url": "https://evil.example.com",
                "api_token": "hacked",
                "project_key": "HACK"
            },
            "enabled": True
        }
    )
    
    # Should be forbidden
    assert response.status_code == 403
    assert "permission" in response.json()["detail"].lower()
    
    # Verify connector was not updated
    adapter = get_adapter()
    connector = adapter.get_connector(setup["connector_b"].id)
    assert connector.name == "Jira B"
    config = json.loads(connector.config)
    assert config["url"] == "https://jira-b.example.com"


def test_org_admin_cannot_delete_other_org_connector(multi_org_connector_setup):
    """Test that Org A admin cannot delete Org B's connector (HIGH-2 fix)."""
    setup = multi_org_connector_setup
    
    # Org A admin tries to delete Org B's connector
    client = _make_client_as(setup["admin_a"])
    response = client.delete(f"/api/admin/connectors/{setup['connector_b'].id}")
    
    # Should be forbidden
    assert response.status_code == 403
    assert "permission" in response.json()["detail"].lower()
    
    # Verify connector still exists
    adapter = get_adapter()
    connector = adapter.get_connector(setup["connector_b"].id)
    assert connector is not None
    assert connector.name == "Jira B"


def test_org_admin_can_update_own_org_connector(multi_org_connector_setup):
    """Test that org admin can update their own org's connector."""
    setup = multi_org_connector_setup
    
    # Org A admin updates their own connector
    client = _make_client_as(setup["admin_a"])
    response = client.put(
        f"/api/admin/connectors/{setup['connector_a'].id}",
        json={
            "name": "Modified Jira A",
            "type": "jira",
            "config": {
                "url": "https://new-jira-a.example.com",
                "api_token": "new-token-a",
                "project_key": "NEWPROJA"
            },
            "enabled": False
        }
    )
    
    # Should succeed
    assert response.status_code == 200
    modified = response.json()
    assert modified["name"] == "Modified Jira A"
    assert modified["enabled"] is False


def test_org_admin_can_delete_own_org_connector(multi_org_connector_setup):
    """Test that org admin can delete their own org's connector."""
    setup = multi_org_connector_setup
    
    # Org A admin deletes their own connector
    client = _make_client_as(setup["admin_a"])
    response = client.delete(f"/api/admin/connectors/{setup['connector_a'].id}")
    
    # Should succeed
    assert response.status_code == 200
    assert response.json()["ok"] is True
    
    # Verify connector is deleted
    adapter = get_adapter()
    connector = adapter.get_connector(setup["connector_a"].id)
    assert connector is None


def test_system_admin_can_update_any_connector(multi_org_connector_setup):
    """Test that system admin can update any org's connector."""
    setup = multi_org_connector_setup
    
    # System admin updates Org B's connector
    client = _make_client_as(setup["system_admin"])
    response = client.put(
        f"/api/admin/connectors/{setup['connector_b'].id}",
        json={
            "name": "System Jira B",
            "type": "jira",
            "config": {
                "url": "https://system-jira-b.example.com",
                "api_token": "system-token",
                "project_key": "PROJB"
            },
            "enabled": True
        }
    )
    
    # Should succeed
    assert response.status_code == 200
    modified = response.json()
    assert modified["name"] == "System Jira B"


def test_system_admin_can_delete_any_connector(multi_org_connector_setup):
    """Test that system admin can delete any org's connector."""
    setup = multi_org_connector_setup
    
    # System admin deletes Org B's connector
    client = _make_client_as(setup["system_admin"])
    response = client.delete(f"/api/admin/connectors/{setup['connector_b'].id}")
    
    # Should succeed
    assert response.status_code == 200
    assert response.json()["ok"] is True


def test_update_nonexistent_connector_returns_404(multi_org_connector_setup):
    """Test that updating non-existent connector returns 404."""
    setup = multi_org_connector_setup
    
    client = _make_client_as(setup["admin_a"])
    response = client.put(
        "/api/admin/connectors/nonexistent-id",
        json={
            "name": "Fake",
            "type": "jira",
            "config": {},
            "enabled": True
        }
    )
    
    assert response.status_code == 404


def test_delete_nonexistent_connector_returns_404(multi_org_connector_setup):
    """Test that deleting non-existent connector returns 404."""
    setup = multi_org_connector_setup
    
    client = _make_client_as(setup["admin_a"])
    response = client.delete("/api/admin/connectors/nonexistent-id")
    
    assert response.status_code == 404


def test_user_without_org_cannot_update_connector(multi_org_connector_setup):
    """Test that user without org membership cannot update connectors."""
    setup = multi_org_connector_setup
    adapter = get_adapter()
    
    # Create user without org membership
    orphan_user = adapter.upsert_user(
        email="orphan@nowhere.com",
        name="Orphan User",
        provider="local",
        role="user"
    )
    
    client = _make_client_as(orphan_user)
    response = client.put(
        f"/api/admin/connectors/{setup['connector_a'].id}",
        json={
            "name": "Hacked",
            "type": "jira",
            "config": {},
            "enabled": True
        }
    )
    
    # Should be forbidden
    assert response.status_code == 403


def test_user_without_org_cannot_delete_connector(multi_org_connector_setup):
    """Test that user without org membership cannot delete connectors."""
    setup = multi_org_connector_setup
    adapter = get_adapter()
    
    # Create user without org membership
    orphan_user = adapter.upsert_user(
        email="orphan@nowhere.com",
        name="Orphan User",
        provider="local",
        role="user"
    )
    
    client = _make_client_as(orphan_user)
    response = client.delete(f"/api/admin/connectors/{setup['connector_a'].id}")
    
    # Should be forbidden
    assert response.status_code == 403


def test_org_b_admin_cannot_update_org_a_connector(multi_org_connector_setup):
    """Test reverse direction: Org B admin cannot update Org A's connector."""
    setup = multi_org_connector_setup
    
    # Org B admin tries to update Org A's connector
    client = _make_client_as(setup["admin_b"])
    response = client.put(
        f"/api/admin/connectors/{setup['connector_a'].id}",
        json={
            "name": "Hacked Jira A",
            "type": "jira",
            "config": {
                "url": "https://evil.example.com",
                "api_token": "hacked",
                "project_key": "HACK"
            },
            "enabled": True
        }
    )
    
    # Should be forbidden
    assert response.status_code == 403
    
    # Verify connector was not updated
    adapter = get_adapter()
    connector = adapter.get_connector(setup["connector_a"].id)
    assert connector.name == "Jira A"


def test_org_b_admin_cannot_delete_org_a_connector(multi_org_connector_setup):
    """Test reverse direction: Org B admin cannot delete Org A's connector."""
    setup = multi_org_connector_setup
    
    # Org B admin tries to delete Org A's connector
    client = _make_client_as(setup["admin_b"])
    response = client.delete(f"/api/admin/connectors/{setup['connector_a'].id}")
    
    # Should be forbidden
    assert response.status_code == 403
    
    # Verify connector still exists
    adapter = get_adapter()
    connector = adapter.get_connector(setup["connector_a"].id)
    assert connector is not None


def test_update_preserves_encrypted_fields_same_org(multi_org_connector_setup):
    """Test that update correctly preserves encrypted fields for same org."""
    setup = multi_org_connector_setup
    
    # Org A admin updates name but not api_token (using ***)
    client = _make_client_as(setup["admin_a"])
    response = client.put(
        f"/api/admin/connectors/{setup['connector_a'].id}",
        json={
            "name": "Changed Jira A",
            "type": "jira",
            "config": {
                "url": "https://jira-a.example.com",
                "api_token": "***",  # Keep existing
                "project_key": "PROJA"
            },
            "enabled": True
        }
    )
    
    # Should succeed
    assert response.status_code == 200
    modified = response.json()
    assert modified["name"] == "Changed Jira A"
    
    # Verify api_token was preserved (check raw config shows value)
    adapter = get_adapter()
    connector = adapter.get_connector(setup["connector_a"].id)
    config = json.loads(connector.config)
    # Should have an api_token, not "***"
    assert config["api_token"] != "***"
    assert config["api_token"] == "token-a"  # Original unencrypted token (encryption happens in endpoint)


def test_org_isolation_with_explicit_org_id_param(multi_org_connector_setup):
    """Test that explicit organization_id param doesn't bypass checks."""
    setup = multi_org_connector_setup
    
    # Org A admin tries to update Org B connector with Org A's org_id in query
    client = _make_client_as(setup["admin_a"])
    response = client.put(
        f"/api/admin/connectors/{setup['connector_b'].id}?organization_id={setup['org_a'].id}",
        json={
            "name": "Hacked",
            "type": "jira",
            "config": {},
            "enabled": True
        }
    )
    
    # Should still be forbidden
    assert response.status_code == 403
