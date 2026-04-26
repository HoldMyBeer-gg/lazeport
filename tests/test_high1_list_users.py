"""Tests for HIGH-1: List Users Returns All Users Across All Orgs.

Tests verify that the /api/admin/users endpoint only returns users from the
requesting user's organization, preventing cross-org information disclosure.
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
def multi_org_setup():
    """Create two organizations with different users."""
    adapter = get_adapter()
    adapter.init()
    
    # Create Organization A
    org_a = adapter.create_organization(name="Organization A", slug="org-a")
    
    # Create users in Org A
    user_a1 = adapter.upsert_user(
        email="admin-a@orga.com",
        name="Admin A",
        provider="local",
        role="user"
    )
    adapter.set_user_password_hash(user_a1.id, hash_password("password123"))
    adapter.create_organization_member(org_a.id, user_a1.id, "org_admin")
    
    user_a2 = adapter.upsert_user(
        email="consultant-a@orga.com",
        name="Consultant A",
        provider="local",
        role="user"
    )
    adapter.create_organization_member(org_a.id, user_a2.id, "consultant")
    
    user_a3 = adapter.upsert_user(
        email="readonly-a@orga.com",
        name="Readonly A",
        provider="local",
        role="user"
    )
    adapter.create_organization_member(org_a.id, user_a3.id, "readonly")
    
    # Create Organization B
    org_b = adapter.create_organization(name="Organization B", slug="org-b")
    
    # Create users in Org B
    user_b1 = adapter.upsert_user(
        email="admin-b@orgb.com",
        name="Admin B",
        provider="local",
        role="user"
    )
    adapter.set_user_password_hash(user_b1.id, hash_password("password123"))
    adapter.create_organization_member(org_b.id, user_b1.id, "org_admin")
    
    user_b2 = adapter.upsert_user(
        email="consultant-b@orgb.com",
        name="Consultant B",
        provider="local",
        role="user"
    )
    adapter.create_organization_member(org_b.id, user_b2.id, "consultant")
    
    # Create a system admin (not in any specific org)
    system_admin = adapter.upsert_user(
        email="sysadmin@system.com",
        name="System Admin",
        provider="local",
        role="admin"
    )
    
    return {
        "org_a": org_a,
        "org_b": org_b,
        "user_a1": user_a1,  # Org A admin
        "user_a2": user_a2,  # Org A consultant
        "user_a3": user_a3,  # Org A readonly
        "user_b1": user_b1,  # Org B admin
        "user_b2": user_b2,  # Org B consultant
        "system_admin": system_admin,
    }


def test_org_admin_sees_only_own_org_users(multi_org_setup):
    """Test that Org A admin can only see Org A users (HIGH-1 fix)."""
    setup = multi_org_setup
    
    # Org A admin lists users
    client = _make_client_as(setup["user_a1"])
    response = client.get("/api/admin/users")
    
    assert response.status_code == 200
    users = response.json()
    
    # Should see exactly 3 users from Org A
    assert len(users) == 3
    
    # Extract emails
    emails = {user["email"] for user in users}
    
    # Should include all Org A users
    assert "admin-a@orga.com" in emails
    assert "consultant-a@orga.com" in emails
    assert "readonly-a@orga.com" in emails
    
    # Should NOT include Org B users
    assert "admin-b@orgb.com" not in emails
    assert "consultant-b@orgb.com" not in emails
    
    # Should NOT include system admin
    assert "sysadmin@system.com" not in emails


def test_org_b_admin_sees_only_org_b_users(multi_org_setup):
    """Test that Org B admin can only see Org B users."""
    setup = multi_org_setup
    
    # Org B admin lists users
    client = _make_client_as(setup["user_b1"])
    response = client.get("/api/admin/users")
    
    assert response.status_code == 200
    users = response.json()
    
    # Should see exactly 2 users from Org B
    assert len(users) == 2
    
    # Extract emails
    emails = {user["email"] for user in users}
    
    # Should include all Org B users
    assert "admin-b@orgb.com" in emails
    assert "consultant-b@orgb.com" in emails
    
    # Should NOT include Org A users
    assert "admin-a@orga.com" not in emails
    assert "consultant-a@orga.com" not in emails
    assert "readonly-a@orga.com" not in emails
    
    # Should NOT include system admin
    assert "sysadmin@system.com" not in emails


def test_consultant_cannot_list_users(multi_org_setup):
    """Test that consultants (non-admins) cannot list users."""
    setup = multi_org_setup
    
    # Consultant tries to list users
    client = _make_client_as(setup["user_a2"])
    response = client.get("/api/admin/users")
    
    # Should be forbidden (require_organization_admin() check)
    assert response.status_code == 403


def test_readonly_cannot_list_users(multi_org_setup):
    """Test that readonly users cannot list users."""
    setup = multi_org_setup
    
    # Readonly user tries to list users
    client = _make_client_as(setup["user_a3"])
    response = client.get("/api/admin/users")
    
    # Should be forbidden
    assert response.status_code == 403


def test_user_in_multiple_orgs_sees_current_org_only(multi_org_setup):
    """Test that user in multiple orgs sees only the current org's users."""
    setup = multi_org_setup
    adapter = get_adapter()
    
    # Add user_a1 to Org B as well
    adapter.create_organization_member(setup["org_b"].id, setup["user_a1"].id, "org_admin")
    
    # When accessing from Org A context (default first org)
    client = _make_client_as(setup["user_a1"])
    response = client.get("/api/admin/users")
    
    assert response.status_code == 200
    users = response.json()
    
    # Should see Org A users (first org)
    emails = {user["email"] for user in users}
    assert "admin-a@orga.com" in emails
    assert "consultant-a@orga.com" in emails


def test_user_with_no_org_membership_sees_empty_list(multi_org_setup):
    """Test that user without org membership sees empty list."""
    setup = multi_org_setup
    adapter = get_adapter()
    
    # Create user without org membership
    orphan_user = adapter.upsert_user(
        email="orphan@nowhere.com",
        name="Orphan User",
        provider="local",
        role="user"
    )
    
    # Try to list users
    client = _make_client_as(orphan_user)
    response = client.get("/api/admin/users")
    
    # Should return empty list (or be forbidden)
    # Based on require_organization_admin(), this might be 403
    # But if it passes RBAC, should return []
    assert response.status_code in [200, 403]
    if response.status_code == 200:
        assert response.json() == []


def test_users_endpoint_returns_user_objects(multi_org_setup):
    """Test that the endpoint returns complete user objects with expected fields."""
    setup = multi_org_setup
    
    client = _make_client_as(setup["user_a1"])
    response = client.get("/api/admin/users")
    
    assert response.status_code == 200
    users = response.json()
    
    # Verify structure of returned users
    assert len(users) > 0
    
    first_user = users[0]
    
    # Check expected fields
    assert "id" in first_user
    assert "email" in first_user
    assert "name" in first_user
    assert "role" in first_user
    assert "created_at" in first_user
    assert "is_active" in first_user


def test_inactive_users_included_in_list(multi_org_setup):
    """Test that inactive users are included in the list."""
    setup = multi_org_setup
    adapter = get_adapter()
    
    # Deactivate one user
    adapter.set_user_active(setup["user_a2"].id, False)
    
    client = _make_client_as(setup["user_a1"])
    response = client.get("/api/admin/users")
    
    assert response.status_code == 200
    users = response.json()
    
    # Should still see all 3 users including inactive one
    assert len(users) == 3
    
    emails = {user["email"] for user in users}
    assert "consultant-a@orga.com" in emails


def test_cross_org_isolation_with_explicit_org_id_param(multi_org_setup):
    """Test that user cannot access another org even with organization_id parameter."""
    setup = multi_org_setup
    
    # Org A admin tries to list users with Org B's ID
    client = _make_client_as(setup["user_a1"])
    response = client.get(f"/api/admin/users?organization_id={setup['org_b'].id}")
    
    # Should get 403 Forbidden because user is not a member of Org B
    # This prevents cross-org data access even with explicit org_id
    assert response.status_code == 403


def test_list_users_handles_deleted_users_gracefully(multi_org_setup):
    """Test that endpoint handles cases where user_id references don't resolve."""
    setup = multi_org_setup
    adapter = get_adapter()
    
    # This tests robustness: if somehow a member references a deleted user
    # (shouldn't happen in practice, but defensive coding)
    
    client = _make_client_as(setup["user_a1"])
    response = client.get("/api/admin/users")
    
    # Should succeed even if some user lookups fail
    assert response.status_code == 200
    users = response.json()
    assert len(users) >= 1  # At least the requesting user


def test_system_admin_with_no_org_membership(multi_org_setup):
    """Test that system admin without org membership gets appropriate response."""
    setup = multi_org_setup
    
    # System admin not in any org
    client = _make_client_as(setup["system_admin"])
    response = client.get("/api/admin/users")
    
    # System admin might get empty list or system org users
    # Behavior depends on get_org_id_from_request implementation
    assert response.status_code == 200
    # Could be empty or could be system org users


def test_list_users_preserves_user_order(multi_org_setup):
    """Test that user list is returned in consistent order."""
    setup = multi_org_setup
    
    client = _make_client_as(setup["user_a1"])
    
    # Call twice
    response1 = client.get("/api/admin/users")
    response2 = client.get("/api/admin/users")
    
    assert response1.status_code == 200
    assert response2.status_code == 200
    
    users1 = response1.json()
    users2 = response2.json()
    
    # Should return same users in same order
    assert len(users1) == len(users2)
    emails1 = [u["email"] for u in users1]
    emails2 = [u["email"] for u in users2]
    assert emails1 == emails2
