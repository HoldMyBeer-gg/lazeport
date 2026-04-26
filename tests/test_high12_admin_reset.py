"""Tests for HIGH-12: Admin Reset Leaves User Stuck with Mandatory Policy.

Tests verify that users who have their 2FA reset by an admin can still log in
and enroll in 2FA when the organization has a mandatory 2FA policy.

This leverages the CRIT-4 fix where pending_2fa_user_id allows access to enrollment.
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
def org_with_mandatory_2fa(monkeypatch):
    """Create an org with mandatory 2FA policy and a user with 2FA enabled."""
    # Enable auth for these tests (HIGH-12 requires real authentication)
    monkeypatch.setenv("AUTH_DISABLED", "0")
    
    adapter = get_adapter()
    adapter.init()
    
    # Create organization with mandatory 2FA
    org = adapter.create_organization(name="Mandatory 2FA Org", slug="mandatory-2fa-reset")
    org_settings = {"twofa_policy": "mandatory"}
    with adapter._session() as session:
        from app.db import models
        db_org = session.get(models.Organization, org.id)
        db_org.settings = json.dumps(org_settings)
        session.commit()
    
    # Create system admin
    system_admin = adapter.upsert_user(
        email="sysadmin@system.com",
        name="System Admin",
        provider="local",
        role="admin"
    )
    adapter.set_user_password_hash(system_admin.id, hash_password("admin123"))
    
    # Create regular user with 2FA enabled
    user = adapter.upsert_user(
        email="user@mandatory.com",
        name="User With 2FA",
        provider="local",
        role="user"
    )
    adapter.set_user_password_hash(user.id, hash_password("userpass123"))
    adapter.create_organization_member(org.id, user.id, "consultant")
    
    # Enable 2FA for user
    import pyotp
    secret = pyotp.random_base32()
    with adapter._session() as session:
        from app.db import models
        db_user = session.get(models.User, user.id)
        db_user.twofa_secret = secret
        db_user.twofa_enabled = True
        db_user.twofa_backup_codes = json.dumps(["code1", "code2"])
        session.commit()
    
    return {
        "org": org,
        "system_admin": system_admin,
        "user": user,
        "secret": secret,
    }


def test_reset_user_can_login_with_password(org_with_mandatory_2fa):
    """Test that user can login with password after 2FA reset (HIGH-12 fix via CRIT-4)."""
    setup = org_with_mandatory_2fa
    adapter = get_adapter()
    
    # System admin resets user's 2FA
    admin_client = _make_client_as(setup["system_admin"])
    response = admin_client.post(f"/api/admin/users/{setup['user'].id}/2fa/reset")
    assert response.status_code == 200
    
    # Verify 2FA is disabled
    user_after_reset = adapter.get_user_by_id(setup["user"].id)
    assert user_after_reset.twofa_enabled is False
    
    # Clear dependency overrides for actual login test
    app.dependency_overrides.clear()
    
    # User should be able to login with password
    client = TestClient(app)
    response = client.post(
        "/auth/login",
        json={"email": "user@mandatory.com", "password": "userpass123"}
    )
    
    # Should succeed and indicate 2FA is required but not enrolled
    assert response.status_code == 200
    result = response.json()
    assert result["requires_2fa"] is True
    assert result["enrolled"] is False


def test_reset_user_can_access_enrollment_endpoints(org_with_mandatory_2fa):
    """Test that reset user can access 2FA enrollment endpoints (HIGH-12 fix via CRIT-4)."""
    setup = org_with_mandatory_2fa
    adapter = get_adapter()
    
    # System admin resets user's 2FA
    admin_client = _make_client_as(setup["system_admin"])
    response = admin_client.post(f"/api/admin/users/{setup['user'].id}/2fa/reset")
    assert response.status_code == 200
    
    # Clear overrides
    app.dependency_overrides.clear()
    
    # User logs in
    client = TestClient(app)
    login_response = client.post(
        "/auth/login",
        json={"email": "user@mandatory.com", "password": "userpass123"}
    )
    assert login_response.status_code == 200
    
    # User should be able to access enrollment endpoint
    # (CRIT-4 fix allows pending_2fa_user_id to access this)
    enroll_response = client.post("/auth/2fa/enroll")
    
    # Should succeed (not 403)
    assert enroll_response.status_code == 200
    assert "qr_code" in enroll_response.json()
    assert "secret" in enroll_response.json()


def test_reset_user_can_complete_enrollment(org_with_mandatory_2fa):
    """Test that reset user can complete full 2FA enrollment flow."""
    setup = org_with_mandatory_2fa
    adapter = get_adapter()
    
    # Reset user's 2FA
    admin_client = _make_client_as(setup["system_admin"])
    response = admin_client.post(f"/api/admin/users/{setup['user'].id}/2fa/reset")
    assert response.status_code == 200
    
    # Clear overrides
    app.dependency_overrides.clear()
    
    # User logs in
    client = TestClient(app)
    login_response = client.post(
        "/auth/login",
        json={"email": "user@mandatory.com", "password": "userpass123"}
    )
    assert login_response.status_code == 200
    
    # Start enrollment
    enroll_start = client.post("/auth/2fa/enroll")
    assert enroll_start.status_code == 200
    secret = enroll_start.json()["secret"]
    
    # Generate valid TOTP code
    import pyotp
    totp = pyotp.TOTP(secret)
    code = totp.now()
    
    # Complete enrollment
    enroll_verify = client.post(
        "/auth/2fa/verify-enrollment",
        json={"code": code}
    )
    assert enroll_verify.status_code == 200
    assert enroll_verify.json()["success"] is True
    assert "backup_codes" in enroll_verify.json()
    
    # Verify user now has 2FA enabled
    user_after = adapter.get_user_by_id(setup["user"].id)
    assert user_after.twofa_enabled is True


def test_reset_user_can_login_fully_after_re_enrollment(org_with_mandatory_2fa):
    """Test that reset user can complete full login flow after re-enrolling."""
    setup = org_with_mandatory_2fa
    adapter = get_adapter()
    
    # Reset and re-enroll (abbreviated)
    admin_client = _make_client_as(setup["system_admin"])
    response = admin_client.post(f"/api/admin/users/{setup['user'].id}/2fa/reset")
    assert response.status_code == 200
    
    # Clear overrides
    app.dependency_overrides.clear()
    
    # Login, enroll, and complete
    client = TestClient(app)
    client.post("/auth/login", json={"email": "user@mandatory.com", "password": "userpass123"})
    enroll_start = client.post("/auth/2fa/enroll")
    assert enroll_start.status_code == 200
    enroll_data = enroll_start.json()
    secret = enroll_data.get("secret") or enroll_data.get("twofa_secret")
    
    import pyotp
    totp = pyotp.TOTP(secret)
    code = totp.now()
    client.post("/auth/2fa/verify-enrollment", json={"code": code})
    
    # Now log out and log back in with 2FA
    client.post("/auth/logout")
    
    # Login again with password
    login_response = client.post(
        "/auth/login",
        json={"email": "user@mandatory.com", "password": "userpass123"}
    )
    assert login_response.status_code == 200
    assert login_response.json()["requires_2fa"] is True
    assert login_response.json()["enrolled"] is True
    
    # Complete 2FA verification
    new_code = totp.now()
    verify_response = client.post(
        "/auth/2fa/verify",
        json={"code": new_code}
    )
    assert verify_response.status_code == 200


def test_non_admin_cannot_reset_2fa(org_with_mandatory_2fa):
    """Test that non-admin users cannot reset 2FA."""
    setup = org_with_mandatory_2fa
    adapter = get_adapter()
    
    # Create another regular user
    other_user = adapter.upsert_user(
        email="other@mandatory.com",
        name="Other User",
        provider="local",
        role="user"
    )
    adapter.create_organization_member(setup["org"].id, other_user.id, "org_admin")
    
    # Org admin tries to reset (should fail - requires system admin)
    client = _make_client_as(other_user)
    response = client.post(f"/api/admin/users/{setup['user'].id}/2fa/reset")
    
    # Should be forbidden
    assert response.status_code == 403


def test_reset_user_without_2fa_returns_400(org_with_mandatory_2fa):
    """Test that resetting 2FA for user without 2FA returns 400."""
    setup = org_with_mandatory_2fa
    adapter = get_adapter()
    
    # Create user without 2FA
    user_no_2fa = adapter.upsert_user(
        email="no2fa@mandatory.com",
        name="No 2FA User",
        provider="local",
        role="user"
    )
    adapter.set_user_password_hash(user_no_2fa.id, hash_password("pass123"))
    
    # Try to reset (should fail - no 2FA enabled)
    client = _make_client_as(setup["system_admin"])
    response = client.post(f"/api/admin/users/{user_no_2fa.id}/2fa/reset")
    
    # Should return 400
    assert response.status_code == 400
