"""Tests for HIGH-5: Delete Tag Without Org Ownership Check.

Tests verify that tag deletion is properly scoped to the user's organization,
preventing cross-org tag manipulation.
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
def multi_org_with_tags():
    """Create two organizations with admins and tags."""
    adapter = get_adapter()
    adapter.init()
    
    # Create Organization A
    org_a = adapter.create_organization(name="Organization A", slug="org-a-tags")
    admin_a = adapter.upsert_user(
        email="admin-a@orga.com",
        name="Admin A",
        provider="local",
        role="user"
    )
    adapter.set_user_password_hash(admin_a.id, hash_password("password123"))
    adapter.create_organization_member(org_a.id, admin_a.id, "org_admin")
    
    # Create tag in Org A
    tag_a = adapter.create_tag(name="Tag A", organization_id=org_a.id)
    
    # Create Organization B
    org_b = adapter.create_organization(name="Organization B", slug="org-b-tags")
    admin_b = adapter.upsert_user(
        email="admin-b@orgb.com",
        name="Admin B",
        provider="local",
        role="user"
    )
    adapter.set_user_password_hash(admin_b.id, hash_password("password123"))
    adapter.create_organization_member(org_b.id, admin_b.id, "org_admin")
    
    # Create tag in Org B
    tag_b = adapter.create_tag(name="Tag B", organization_id=org_b.id)
    
    return {
        "org_a": org_a,
        "org_b": org_b,
        "admin_a": admin_a,
        "admin_b": admin_b,
        "tag_a": tag_a,
        "tag_b": tag_b,
    }


def test_admin_can_delete_own_org_tag(multi_org_with_tags):
    """Test that org admin can delete tags in their own org."""
    setup = multi_org_with_tags
    adapter = get_adapter()
    
    # Org A admin deletes Org A tag
    client = _make_client_as(setup["admin_a"])
    response = client.delete(f"/api/admin/tags/{setup['tag_a'].id}")
    
    assert response.status_code == 200
    assert response.json() == {"ok": True}
    
    # Verify tag is deleted
    tag = adapter.get_tag(setup["tag_a"].id)
    assert tag is None


def test_admin_cannot_delete_other_org_tag(multi_org_with_tags):
    """Test that org admin cannot delete tags from another org (HIGH-5 fix)."""
    setup = multi_org_with_tags
    adapter = get_adapter()
    
    # Org A admin tries to delete Org B tag
    client = _make_client_as(setup["admin_a"])
    response = client.delete(f"/api/admin/tags/{setup['tag_b'].id}")
    
    # Should be forbidden
    assert response.status_code == 403
    
    # Verify tag still exists
    tag = adapter.get_tag(setup["tag_b"].id)
    assert tag is not None
    assert tag.name == "Tag B"


def test_org_b_admin_cannot_delete_org_a_tag(multi_org_with_tags):
    """Test that Org B admin cannot delete Org A tag."""
    setup = multi_org_with_tags
    adapter = get_adapter()
    
    # Org B admin tries to delete Org A tag
    client = _make_client_as(setup["admin_b"])
    response = client.delete(f"/api/admin/tags/{setup['tag_a'].id}")
    
    # Should be forbidden
    assert response.status_code == 403
    
    # Verify tag still exists
    tag = adapter.get_tag(setup["tag_a"].id)
    assert tag is not None
    assert tag.name == "Tag A"


def test_system_admin_can_delete_any_tag(multi_org_with_tags):
    """Test that system admin can delete tags from any org."""
    setup = multi_org_with_tags
    adapter = get_adapter()
    
    # Create system admin
    system_admin = adapter.upsert_user(
        email="sysadmin@system.com",
        name="System Admin",
        provider="local",
        role="admin"
    )
    
    # System admin can delete Org A tag
    client = _make_client_as(system_admin)
    response = client.delete(f"/api/admin/tags/{setup['tag_a'].id}")
    
    assert response.status_code == 200
    
    # Verify tag is deleted
    tag = adapter.get_tag(setup["tag_a"].id)
    assert tag is None


def test_consultant_cannot_delete_tag(multi_org_with_tags):
    """Test that consultant cannot delete tags (requires org_admin)."""
    setup = multi_org_with_tags
    adapter = get_adapter()
    
    # Create consultant in Org A
    consultant_a = adapter.upsert_user(
        email="consultant-a@orga.com",
        name="Consultant A",
        provider="local",
        role="user"
    )
    adapter.create_organization_member(setup["org_a"].id, consultant_a.id, "consultant")
    
    # Consultant tries to delete tag
    client = _make_client_as(consultant_a)
    response = client.delete(f"/api/admin/tags/{setup['tag_a'].id}")
    
    # Should be forbidden (requires org_admin)
    assert response.status_code == 403


def test_user_without_org_cannot_delete_tag(multi_org_with_tags):
    """Test that user without org membership cannot delete tags."""
    setup = multi_org_with_tags
    adapter = get_adapter()
    
    # Create orphan user
    orphan = adapter.upsert_user(
        email="orphan@nowhere.com",
        name="Orphan",
        provider="local",
        role="user"
    )
    
    client = _make_client_as(orphan)
    response = client.delete(f"/api/admin/tags/{setup['tag_a'].id}")
    
    # Should be forbidden
    assert response.status_code == 403


def test_delete_nonexistent_tag_returns_404(multi_org_with_tags):
    """Test that deleting nonexistent tag returns 404."""
    setup = multi_org_with_tags
    
    client = _make_client_as(setup["admin_a"])
    response = client.delete("/api/admin/tags/00000000-0000-0000-0000-999999999999")
    
    assert response.status_code == 404


def test_tag_deletion_audit_logs_correctly(multi_org_with_tags):
    """Test that tag deletion creates audit log with correct org."""
    setup = multi_org_with_tags
    adapter = get_adapter()
    
    # Org B admin deletes Org B tag
    client = _make_client_as(setup["admin_b"])
    response = client.delete(f"/api/admin/tags/{setup['tag_b'].id}")
    
    assert response.status_code == 200
    
    # Verify audit log in Org B
    logs = list(adapter.list_audit_logs(setup["org_b"].id, limit=10))
    delete_logs = [
        log for log in logs
        if log.action == "delete" and log.resource_type == "tag" and log.resource_id == setup["tag_b"].id
    ]
    assert len(delete_logs) >= 1
    assert delete_logs[0].organization_id == setup["org_b"].id
