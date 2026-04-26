"""Tests for name validation with special characters like apostrophes.

Ensures that names with common punctuation (O'Brien, Jean-Paul, etc.)
are accepted and properly stored in the database.
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
    org = adapter.create_organization(name="Test Org", slug="test-org-apostrophe")

    # Create admin to send invite
    admin = adapter.upsert_user(
        email="admin@apostrophe.com",
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
        "invitee@apostrophe.com",
        "consultant",
        token_hash,
        datetime.utcnow() + timedelta(days=7),
        invited_by=admin.id
    )

    return {
        "org": org,
        "admin": admin,
        "invite": invite,
        "token": raw_token,
    }


def test_invite_accept_with_apostrophe_in_name(org_with_invite):
    """Test that names with apostrophes (O'Brien, O'Connor) are accepted."""
    setup = org_with_invite

    client = TestClient(app)
    response = client.post(
        "/auth/invite/accept",
        json={
            "token": setup["token"],
            "name": "O'Brien",
            "password": "securepassword123"
        }
    )

    assert response.status_code == 200, f"Failed with: {response.text}"
    assert response.json()["status"] == "accepted"

    # Verify name was stored correctly
    adapter = get_adapter()
    user = adapter.get_user_by_email("invitee@apostrophe.com")
    assert user is not None
    assert user.name == "O'Brien"


def test_invite_accept_with_multiple_apostrophes(org_with_invite):
    """Test names with multiple apostrophes like Jean-Paul O'Connor."""
    setup = org_with_invite
    adapter = get_adapter()
    raw_token2 = secrets.token_urlsafe(32)
    token_hash2 = hash_invite_token(raw_token2)

    adapter.create_org_invite(
        setup["org"].id,
        "jeanpaul@apostrophe.com",
        "consultant",
        token_hash2,
        datetime.utcnow() + timedelta(days=7),
        invited_by=setup["admin"].id
    )

    client = TestClient(app)

    response = client.post(
        "/auth/invite/accept",
        json={
            "token": raw_token2,
            "name": "Jean-Paul O'Connor",
            "password": "securepassword123"
        }
    )

    assert response.status_code == 200, f"Failed with: {response.text}"

    # Verify name stored correctly
    user = adapter.get_user_by_email("jeanpaul@apostrophe.com")
    assert user is not None
    assert user.name == "Jean-Paul O'Connor"


def test_invite_accept_with_various_special_chars(org_with_invite):
    """Test that various legitimate name characters work."""
    setup = org_with_invite
    client = TestClient(app)

    test_names = [
        "O'Brien",           # apostrophe
        "Jean-Paul",         # hyphen
        "Mary Jane Smith",   # spaces
        "José García",       # accents
        "李明",              # Chinese characters
        "О'Brien",           # Cyrillic with apostrophe
    ]

    adapter = get_adapter()
    for i, name in enumerate(test_names):
        # Create a new invite for each test
        email = f"test{i}@apostrophe.com"
        raw_token = secrets.token_urlsafe(32)
        token_hash = hash_invite_token(raw_token)

        adapter.create_org_invite(
            setup["org"].id,
            email,
            "consultant",
            token_hash,
            datetime.utcnow() + timedelta(days=7),
            invited_by=setup["admin"].id
        )

        response = client.post(
            "/auth/invite/accept",
            json={
                "token": raw_token,
                "name": name,
                "password": "securepassword123"
            }
        )

        assert response.status_code == 200, f"Failed for name '{name}': {response.text}"

        # Verify stored correctly
        user = adapter.get_user_by_email(email)
        assert user is not None
        assert user.name == name, f"Name mismatch for '{name}': got '{user.name}'"
