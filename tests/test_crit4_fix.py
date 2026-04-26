"""Direct tests for CRIT-4 fix: pending_2fa_user_id support in _get_user_from_session.

Tests verify that _get_user_from_session correctly checks both user_id (fully authenticated)
and pending_2fa_user_id (password authenticated, awaiting 2FA), preventing the deadlock
where new users in mandatory-2FA orgs cannot enroll.
"""
import pytest
from unittest.mock import Mock
from app.services.auth import _get_user_from_session
from app.db import get_adapter, models


@pytest.fixture
def adapter():
    """Get database adapter."""
    return get_adapter()


@pytest.fixture
def test_user(adapter):
    """Create a test user."""
    return adapter.upsert_user(
        email="test@example.com",
        name="Test User",
        provider="local",
        role="user"
    )


def test_get_user_with_user_id_fully_authenticated(adapter, test_user):
    """Test that _get_user_from_session works with user_id (normal authenticated state)."""
    # Create mock request with user_id in session
    request = Mock()
    request.session = {"user_id": test_user.id}
    
    # Should successfully get user
    user = _get_user_from_session(request, adapter)
    assert user is not None
    assert user.id == test_user.id
    assert user.email == test_user.email


def test_get_user_with_pending_2fa_user_id(adapter, test_user):
    """Test that _get_user_from_session does NOT return pending users (security fix).
    
    After the 2FA bypass fix, _get_user_from_session only returns FULLY authenticated 
    users (user_id set). Pending users (pending_2fa_user_id) must use 
    get_pending_or_authenticated_user() instead. This prevents the bypass vulnerability.
    """
    # Create mock request with only pending_2fa_user_id (no user_id)
    request = Mock()
    request.session = {"pending_2fa_user_id": test_user.id}
    # Intentionally NOT setting user_id - this is the pending state
    
    # Should return None (not fully authenticated)
    user = _get_user_from_session(request, adapter)
    assert user is None


def test_get_user_prefers_user_id_over_pending(adapter, test_user):
    """Test that user_id takes precedence when both are set."""
    # Create another user
    other_user = adapter.upsert_user(
        email="other@example.com",
        name="Other User",
        provider="local",
        role="user"
    )
    
    # Create mock request with both user_id and pending_2fa_user_id
    request = Mock()
    request.session = {
        "user_id": test_user.id,
        "pending_2fa_user_id": other_user.id
    }
    
    # Should return user identified by user_id
    user = _get_user_from_session(request, adapter)
    assert user is not None
    assert user.id == test_user.id


def test_get_user_returns_none_without_either_id(adapter):
    """Test that _get_user_from_session returns None when neither ID is present."""
    # Create mock request with empty session
    request = Mock()
    request.session = {}
    
    # Should return None
    user = _get_user_from_session(request, adapter)
    assert user is None


def test_get_user_returns_none_for_nonexistent_user(adapter):
    """Test that _get_user_from_session returns None for non-existent user ID."""
    # Create mock request with fake user ID
    request = Mock()
    request.session = {"pending_2fa_user_id": "nonexistent-user-id"}
    
    # Should return None
    user = _get_user_from_session(request, adapter)
    assert user is None


def test_mandatory_2fa_policy_check():
    """Test that check_2fa_required correctly identifies mandatory policy requirement."""
    from app.services.twofa import check_2fa_required
    import json
    
    adapter = get_adapter()
    adapter.init()
    
    # Create org with mandatory 2FA policy
    org = adapter.create_organization(name="Mandatory 2FA Org", slug="mandatory-2fa")
    org_settings = {"twofa_policy": "mandatory"}
    adapter.update_organization(org.id, settings=json.dumps(org_settings))
    
    # Create user in that org
    user = adapter.upsert_user(
        email="newuser@mandatory.com",
        name="New User",
        provider="local",
        role="user"
    )
    adapter.create_organization_member(org.id, user.id, "consultant")
    
    # User should require 2FA even though not enrolled
    assert check_2fa_required(user, adapter) is True
    assert user.twofa_enabled is False  # Not enrolled yet


def test_optional_2fa_policy_does_not_require():
    """Test that optional policy does not force 2FA requirement."""
    from app.services.twofa import check_2fa_required
    import json
    
    adapter = get_adapter()
    adapter.init()
    
    # Create org with optional 2FA policy
    org = adapter.create_organization(name="Optional 2FA Org", slug="optional-2fa")
    org_settings = {"twofa_policy": "optional"}
    adapter.update_organization(org.id, settings=json.dumps(org_settings))
    
    # Create user in that org
    user = adapter.upsert_user(
        email="user@optional.com",
        name="User",
        provider="local",
        role="user"
    )
    adapter.create_organization_member(org.id, user.id, "consultant")
    
    # User should NOT require 2FA
    assert check_2fa_required(user, adapter) is False


def test_disabled_2fa_policy_does_not_require():
    """Test that disabled policy does not require 2FA."""
    from app.services.twofa import check_2fa_required
    import json
    
    adapter = get_adapter()
    adapter.init()
    
    # Create org with disabled 2FA policy
    org = adapter.create_organization(name="Disabled 2FA Org", slug="disabled-2fa")
    org_settings = {"twofa_policy": "disabled"}
    adapter.update_organization(org.id, settings=json.dumps(org_settings))
    
    # Create user in that org
    user = adapter.upsert_user(
        email="user@disabled.com",
        name="User",
        provider="local",
        role="user"
    )
    adapter.create_organization_member(org.id, user.id, "consultant")
    
    # User should NOT require 2FA
    assert check_2fa_required(user, adapter) is False


def test_user_with_2fa_enabled_always_requires():
    """Test that users with 2FA already enabled always require it."""
    from app.services.twofa import check_2fa_required, generate_secret, encrypt_secret
    import json
    
    adapter = get_adapter()
    adapter.init()
    
    # Create org with disabled policy
    org = adapter.create_organization(name="Disabled Org", slug="disabled")
    org_settings = {"twofa_policy": "disabled"}
    adapter.update_organization(org.id, settings=json.dumps(org_settings))
    
    # Create user and enable 2FA
    user = adapter.upsert_user(
        email="user@enabled.com",
        name="User",
        provider="local",
        role="user"
    )
    adapter.create_organization_member(org.id, user.id, "consultant")
    
    # Enable 2FA for user
    secret = generate_secret()
    encrypted = encrypt_secret(secret)
    with adapter._session() as session:
        db_user = session.get(models.User, user.id)
        db_user.twofa_secret = encrypted
        db_user.twofa_enabled = True
        session.commit()
    
    # Refresh user
    user = adapter.get_user_by_id(user.id)
    
    # Should require 2FA even though org policy is disabled
    assert check_2fa_required(user, adapter) is True
