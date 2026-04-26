"""Tests for HIGH-7: Entity Type "member" Bypasses All Permission Checks.

Tests verify that the "member" entity type has been removed from VALID_ENTITY_TYPES
to prevent bypassing permission checks.
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
def org_with_admin():
    """Create an organization with an admin."""
    adapter = get_adapter()
    adapter.init()
    
    org = adapter.create_organization(name="Test Org", slug="test-org-member")
    admin = adapter.upsert_user(
        email="admin@test.com",
        name="Admin",
        provider="local",
        role="user"
    )
    adapter.set_user_password_hash(admin.id, hash_password("password123"))
    adapter.create_organization_member(org.id, admin.id, "org_admin")
    
    return {
        "org": org,
        "admin": admin,
    }


def test_assign_tag_with_member_entity_type_rejected(org_with_admin):
    """Test that assigning tag with entity_type='member' is rejected (HIGH-7 fix)."""
    setup = org_with_admin
    
    client = _make_client_as(setup["admin"])
    response = client.post(
        "/api/admin/tags/assign",
        json={
            "tag_name": "TestTag",
            "entity_type": "member",
            "entity_id": "00000000-0000-0000-0000-123456789abc"
        }
    )
    
    # Should be rejected with 422 (validation error)
    assert response.status_code == 422
    error = response.json()
    assert "entity_type" in str(error).lower()


def test_unassign_tag_with_member_entity_type_rejected(org_with_admin):
    """Test that unassigning tag with entity_type='member' is rejected (HIGH-7 fix)."""
    setup = org_with_admin
    adapter = get_adapter()
    
    # Create a tag
    tag = adapter.create_tag(setup["org"].id, "TestTag", created_by=setup["admin"].id)
    
    client = _make_client_as(setup["admin"])
    response = client.request(
        "DELETE",
        "/api/admin/tags/assign",
        json={
            "tag_id": tag.id,
            "entity_type": "member",
            "entity_id": "00000000-0000-0000-0000-123456789abc"
        }
    )
    
    # Should be rejected with 422 (validation error)
    assert response.status_code == 422
    error = response.json()
    assert "entity_type" in str(error).lower()


def test_list_entity_tags_with_member_entity_type_rejected(org_with_admin):
    """Test that listing tags with entity_type='member' is rejected (HIGH-7 fix)."""
    setup = org_with_admin
    
    client = _make_client_as(setup["admin"])
    response = client.get(
        "/api/admin/tags/entity/member/00000000-0000-0000-0000-123456789abc"
    )
    
    # Should be rejected with 400
    assert response.status_code == 400
    error = response.json()
    assert "entity_type" in str(error["detail"]).lower()


def test_bulk_list_entity_tags_with_member_entity_type_rejected(org_with_admin):
    """Test that bulk listing tags with entity_type='member' is rejected (HIGH-7 fix)."""
    setup = org_with_admin
    
    client = _make_client_as(setup["admin"])
    response = client.get(
        "/api/admin/tags/entity-bulk/member",
        params={"ids": "00000000-0000-0000-0000-123456789abc,00000000-0000-0000-0000-987654321xyz"}
    )
    
    # Should be rejected with 400
    assert response.status_code == 400
    error = response.json()
    assert "entity_type" in str(error["detail"]).lower()


def test_valid_entity_types_are_still_accepted(org_with_admin):
    """Test that valid entity types (client, application, report, finding) are still accepted."""
    setup = org_with_admin
    adapter = get_adapter()
    
    # Create client and app
    org_client = adapter.create_client("Test Team", organization_id=setup["org"].id)
    app_entity = adapter.create_application(
        name="Test App",
        type="web",
        description="",
        organization_id=setup["org"].id
    )

    http_client = _make_client_as(setup["admin"])

    # Test client
    response = http_client.post(
        "/api/admin/tags/assign",
        json={
            "tag_name": "TeamTag",
            "entity_type": "client",
            "entity_id": org_client.id
        }
    )
    assert response.status_code == 200
    
    # Test application
    response = http_client.post(
        "/api/admin/tags/assign",
        json={
            "tag_name": "AppTag",
            "entity_type": "application",
            "entity_id": app_entity.id
        }
    )
    assert response.status_code == 200
