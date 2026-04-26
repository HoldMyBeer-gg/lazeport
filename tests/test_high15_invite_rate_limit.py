"""Tests for HIGH-15: No Rate Limit on Invite Accept.

Tests verify that invite acceptance has proper rate limiting to prevent
token brute-force attacks.
"""
import pytest
import secrets
from fastapi.testclient import TestClient
from app.main import app
from app.db import get_adapter
from app.services.auth import hash_password, hash_invite_token
from datetime import datetime, timedelta


@pytest.fixture
def org_with_invite():
    """Create an organization with a valid invite."""
    adapter = get_adapter()
    adapter.init()
    
    # Create organization
    org = adapter.create_organization(name="Test Org", slug="test-org-invite-rl")
    
    # Create admin to send invite
    admin = adapter.upsert_user(
        email="admin@test.com",
        name="Admin",
        provider="local",
        role="user"
    )
    adapter.set_user_password_hash(admin.id, hash_password("password123"))
    adapter.create_organization_member(org.id, admin.id, "org_admin")
    
    # Create invite with raw token
    raw_token = secrets.token_urlsafe(32)
    token_hash = hash_invite_token(raw_token)
    
    invite = adapter.create_org_invite(
        org.id,
        "invitee@test.com",
        "consultant",
        token_hash,
        datetime.utcnow() + timedelta(days=7),
        invited_by=admin.id
    )
    
    return {
        "org": org,
        "admin": admin,
        "invite": invite,
        "token": raw_token,  # Raw token for use in tests
    }


def test_invite_accept_with_valid_token_succeeds(org_with_invite):
    """Test that valid invite acceptance works."""
    setup = org_with_invite
    
    client = TestClient(app)
    response = client.post(
        "/auth/invite/accept",
        json={
            "token": setup["token"],
            "name": "New User",
            "password": "securepassword123"
        }
    )
    
    assert response.status_code == 200
    assert response.json()["status"] == "accepted"


def test_invite_accept_rate_limited_after_failures(org_with_invite):
    """Test that multiple failed invite attempts trigger rate limiting (HIGH-15 fix)."""
    setup = org_with_invite
    
    client = TestClient(app)
    
    # Make multiple attempts with invalid tokens
    # Default max_attempts is 5, so we need at least 6 attempts to see rate limiting
    for i in range(7):
        response = client.post(
            "/auth/invite/accept",
            json={
                "token": f"invalid-token-{i:04d}-" + "x" * 20,
                "name": "Attacker",
                "password": "password12345"
            }
        )
        
        # First 5 attempts fail with validation errors
        # 6th+ attempts should be rate limited (429)
        if i < 5:
            assert response.status_code in [400, 429], f"Attempt {i+1}: expected 400 or 429, got {response.status_code}"
        else:
            # After threshold, should definitely be rate limited
            assert response.status_code == 429
            error = response.json()
            assert "too many" in error["detail"]["message"].lower()
            assert "seconds_remaining" in error["detail"]


def test_rate_limit_cleared_after_successful_acceptance(org_with_invite):
    """Test that rate limit counter is cleared after successful invite acceptance."""
    setup = org_with_invite
    adapter = get_adapter()
    
    client = TestClient(app)
    
    # Make a few failed attempts
    for i in range(2):
        client.post(
            "/auth/invite/accept",
            json={
                "token": f"bad-token-{i}-" + "x" * 20,
                "name": "User",
                "password": "password12345"
            }
        )
    
    # Now use valid token
    response = client.post(
        "/auth/invite/accept",
        json={
            "token": setup["token"],
            "name": "Valid User",
            "password": "securepassword123"
        }
    )
    
    assert response.status_code == 200
    
    # Create another invite for same org
    raw_token2 = secrets.token_urlsafe(32)
    token_hash2 = hash_invite_token(raw_token2)
    
    adapter.create_org_invite(
        setup["org"].id,
        "another@test.com",
        "consultant",
        token_hash2,
        datetime.utcnow() + timedelta(days=7),
        invited_by=setup["admin"].id
    )
    
    # Should be able to accept another invite without being rate limited
    # (counter was cleared after successful acceptance)
    response2 = client.post(
        "/auth/invite/accept",
        json={
            "token": raw_token2,
            "name": "Another User",
            "password": "anotherpassword123"
        }
    )
    
    assert response2.status_code == 200


def test_used_invite_token_increments_rate_limit(org_with_invite):
    """Test that attempting to reuse an already-used invite counts against rate limit."""
    setup = org_with_invite
    
    client = TestClient(app)
    
    # Accept invite successfully
    response = client.post(
        "/auth/invite/accept",
        json={
            "token": setup["token"],
            "name": "First User",
            "password": "securepassword123"
        }
    )
    assert response.status_code == 200
    
    # Try to use same token again multiple times
    for i in range(7):
        response = client.post(
            "/auth/invite/accept",
            json={
                "token": setup["token"],
                "name": f"Attacker {i}",
                "password": "password12345"
            }
        )
        
        # First few attempts should return 400 (already used)
        # Eventually should be rate limited (429)
        if i < 5:
            assert response.status_code in [400, 429], f"Attempt {i+1}: expected 400 or 429"
        else:
            # After threshold, should definitely be rate limited
            assert response.status_code == 429


def test_expired_invite_token_increments_rate_limit(org_with_invite):
    """Test that attempting to use expired invite counts against rate limit."""
    setup = org_with_invite
    adapter = get_adapter()
    
    # Create expired invite
    expired_token = secrets.token_urlsafe(32)
    expired_token_hash = hash_invite_token(expired_token)
    
    adapter.create_org_invite(
        setup["org"].id,
        "expired@test.com",
        "consultant",
        expired_token_hash,
        datetime.utcnow() - timedelta(days=1),  # Already expired
        invited_by=setup["admin"].id
    )
    
    client = TestClient(app)
    
    # Try expired token multiple times
    for i in range(7):
        response = client.post(
            "/auth/invite/accept",
            json={
                "token": expired_token,
                "name": "Attacker",
                "password": "password12345"
            }
        )
        
        # First few attempts should return 400 (expired)
        # Eventually should be rate limited (429)
        if i < 5:
            assert response.status_code in [400, 429], f"Attempt {i+1}: expected 400 or 429"
        else:
            # After threshold, should definitely be rate limited
            assert response.status_code == 429
