"""Tests for HIGH-6: Tag Assignment for Team/Application Without Org Check.

Tests verify that tag assignment to clients and applications properly verifies
organization ownership, preventing cross-org tag pollution.
"""
import pytest
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
def multi_org_with_clients_apps():
    """Create two organizations with clients and applications."""
    adapter = get_adapter()
    adapter.init()
    
    # Create Organization A
    org_a = adapter.create_organization(name="Organization A", slug="org-a-tagass")
    admin_a = adapter.upsert_user(
        email="admin-a@orga.com",
        name="Admin A",
        provider="local",
        role="user"
    )
    adapter.set_user_password_hash(admin_a.id, hash_password("password123"))
    adapter.create_organization_member(org_a.id, admin_a.id, "org_admin")
    
    # Create client and app in Org A
    client_a = adapter.create_client(name="Team A", organization_id=org_a.id)
    app_a = adapter.create_application(
        name="App A",
        type="web",
        description="",
        organization_id=org_a.id
    )
    
    # Create Organization B
    org_b = adapter.create_organization(name="Organization B", slug="org-b-tagass")
    admin_b = adapter.upsert_user(
        email="admin-b@orgb.com",
        name="Admin B",
        provider="local",
        role="user"
    )
    adapter.set_user_password_hash(admin_b.id, hash_password("password123"))
    adapter.create_organization_member(org_b.id, admin_b.id, "org_admin")
    
    # Create client and app in Org B
    client_b = adapter.create_client(name="Team B", organization_id=org_b.id)
    app_b = adapter.create_application(
        name="App B",
        type="web",
        description="",
        organization_id=org_b.id
    )
    
    return {
        "org_a": org_a,
        "org_b": org_b,
        "admin_a": admin_a,
        "admin_b": admin_b,
        "client_a": client_a,
        "client_b": client_b,
        "app_a": app_a,
        "app_b": app_b,
    }


def test_admin_can_assign_tag_to_own_org_client(multi_org_with_clients_apps):
    """Test that admin can assign tags to clients in their own org."""
    setup = multi_org_with_clients_apps
    
    client = _make_client_as(setup["admin_a"])
    response = client.post(
        "/api/admin/tags/assign",
        json={
            "tag_name": "Important",
            "entity_type": "client",
            "entity_id": setup["client_a"].id
        }
    )
    
    assert response.status_code == 200
    result = response.json()
    assert "tag_id" in result
    assert result["tag_name"] == "Important"


def test_admin_cannot_assign_tag_to_other_org_client(multi_org_with_clients_apps):
    """Test that admin cannot assign tags to clients in other org (HIGH-6 fix)."""
    setup = multi_org_with_clients_apps
    
    # Org A admin tries to tag Org B's client
    client = _make_client_as(setup["admin_a"])
    response = client.post(
        "/api/admin/tags/assign",
        json={
            "tag_name": "Malicious",
            "entity_type": "client",
            "entity_id": setup["client_b"].id
        }
    )
    
    # Should be forbidden
    assert response.status_code == 403


def test_admin_can_assign_tag_to_own_org_application(multi_org_with_clients_apps):
    """Test that admin can assign tags to applications in their own org."""
    setup = multi_org_with_clients_apps
    
    client = _make_client_as(setup["admin_a"])
    response = client.post(
        "/api/admin/tags/assign",
        json={
            "tag_name": "Production",
            "entity_type": "application",
            "entity_id": setup["app_a"].id
        }
    )
    
    assert response.status_code == 200
    result = response.json()
    assert "tag_id" in result
    assert result["tag_name"] == "Production"


def test_admin_cannot_assign_tag_to_other_org_application(multi_org_with_clients_apps):
    """Test that admin cannot assign tags to applications in other org (HIGH-6 fix)."""
    setup = multi_org_with_clients_apps
    
    # Org A admin tries to tag Org B's application
    client = _make_client_as(setup["admin_a"])
    response = client.post(
        "/api/admin/tags/assign",
        json={
            "tag_name": "Malicious",
            "entity_type": "application",
            "entity_id": setup["app_b"].id
        }
    )
    
    # Should be forbidden
    assert response.status_code == 403


def test_admin_can_unassign_tag_from_own_org_client(multi_org_with_clients_apps):
    """Test that admin can unassign tags from clients in their own org."""
    setup = multi_org_with_clients_apps
    adapter = get_adapter()
    
    # Create tag and assign to client
    tag = adapter.create_tag(setup["org_a"].id, "TestTag", created_by=setup["admin_a"].id)
    adapter.add_entity_tag(tag.id, "client", setup["client_a"].id, created_by=setup["admin_a"].id)
    
    # Unassign the tag
    client = _make_client_as(setup["admin_a"])
    response = client.request(
        "DELETE",
        "/api/admin/tags/assign",
        json={
            "tag_id": tag.id,
            "entity_type": "client",
            "entity_id": setup["client_a"].id
        }
    )
    
    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_admin_cannot_unassign_tag_from_other_org_client(multi_org_with_clients_apps):
    """Test that admin cannot unassign tags from clients in other org (HIGH-6 fix)."""
    setup = multi_org_with_clients_apps
    adapter = get_adapter()
    
    # Create tag in Org B and assign to Org B client
    tag_b = adapter.create_tag(setup["org_b"].id, "TagB", created_by=setup["admin_b"].id)
    adapter.add_entity_tag(tag_b.id, "client", setup["client_b"].id, created_by=setup["admin_b"].id)
    
    # Org A admin tries to unassign
    client = _make_client_as(setup["admin_a"])
    response = client.request(
        "DELETE",
        "/api/admin/tags/assign",
        json={
            "tag_id": tag_b.id,
            "entity_type": "client",
            "entity_id": setup["client_b"].id
        }
    )
    
    # Should be forbidden
    assert response.status_code == 403


def test_admin_can_unassign_tag_from_own_org_application(multi_org_with_clients_apps):
    """Test that admin can unassign tags from applications in their own org."""
    setup = multi_org_with_clients_apps
    adapter = get_adapter()
    
    # Create tag and assign to application
    tag = adapter.create_tag(setup["org_a"].id, "AppTag", created_by=setup["admin_a"].id)
    adapter.add_entity_tag(tag.id, "application", setup["app_a"].id, created_by=setup["admin_a"].id)
    
    # Unassign the tag
    client = _make_client_as(setup["admin_a"])
    response = client.request(
        "DELETE",
        "/api/admin/tags/assign",
        json={
            "tag_id": tag.id,
            "entity_type": "application",
            "entity_id": setup["app_a"].id
        }
    )
    
    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_admin_cannot_unassign_tag_from_other_org_application(multi_org_with_clients_apps):
    """Test that admin cannot unassign tags from applications in other org (HIGH-6 fix)."""
    setup = multi_org_with_clients_apps
    adapter = get_adapter()
    
    # Create tag in Org B and assign to Org B app
    tag_b = adapter.create_tag(setup["org_b"].id, "AppTagB", created_by=setup["admin_b"].id)
    adapter.add_entity_tag(tag_b.id, "application", setup["app_b"].id, created_by=setup["admin_b"].id)
    
    # Org A admin tries to unassign
    client = _make_client_as(setup["admin_a"])
    response = client.request(
        "DELETE",
        "/api/admin/tags/assign",
        json={
            "tag_id": tag_b.id,
            "entity_type": "application",
            "entity_id": setup["app_b"].id
        }
    )
    
    # Should be forbidden
    assert response.status_code == 403


def test_system_admin_can_assign_tag_to_any_org_client(multi_org_with_clients_apps):
    """Test that system admin can assign tags to clients in any org."""
    setup = multi_org_with_clients_apps
    adapter = get_adapter()
    
    # Create system admin
    system_admin = adapter.upsert_user(
        email="sysadmin@system.com",
        name="System Admin",
        provider="local",
        role="admin"
    )
    
    # System admin can tag Org B's client
    client = _make_client_as(system_admin)
    response = client.post(
        "/api/admin/tags/assign",
        json={
            "tag_name": "SystemTag",
            "entity_type": "client",
            "entity_id": setup["client_b"].id
        }
    )
    
    assert response.status_code == 200


def test_system_admin_can_assign_tag_to_any_org_application(multi_org_with_clients_apps):
    """Test that system admin can assign tags to applications in any org."""
    setup = multi_org_with_clients_apps
    adapter = get_adapter()
    
    # Create system admin
    system_admin = adapter.upsert_user(
        email="sysadmin@system.com",
        name="System Admin",
        provider="local",
        role="admin"
    )
    
    # System admin can tag Org B's application
    client = _make_client_as(system_admin)
    response = client.post(
        "/api/admin/tags/assign",
        json={
            "tag_name": "SystemAppTag",
            "entity_type": "application",
            "entity_id": setup["app_b"].id
        }
    )
    
    assert response.status_code == 200


def test_assign_tag_to_nonexistent_client_returns_404(multi_org_with_clients_apps):
    """Test that assigning tag to nonexistent client returns 404."""
    setup = multi_org_with_clients_apps
    
    client = _make_client_as(setup["admin_a"])
    response = client.post(
        "/api/admin/tags/assign",
        json={
            "tag_name": "TestTag",
            "entity_type": "client",
            "entity_id": "00000000-0000-0000-0000-999999999999"
        }
    )
    
    assert response.status_code == 404


def test_assign_tag_to_nonexistent_application_returns_404(multi_org_with_clients_apps):
    """Test that assigning tag to nonexistent application returns 404."""
    setup = multi_org_with_clients_apps
    
    client = _make_client_as(setup["admin_a"])
    response = client.post(
        "/api/admin/tags/assign",
        json={
            "tag_name": "TestTag",
            "entity_type": "application",
            "entity_id": "00000000-0000-0000-0000-999999999999"
        }
    )
    
    assert response.status_code == 404
