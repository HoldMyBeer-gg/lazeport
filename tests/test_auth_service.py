from fastapi import HTTPException
from starlette.requests import Request
import pytest
from unittest.mock import MagicMock
from datetime import datetime, timedelta

from app.db import models
from app.services import auth
from app.config import settings


def _dummy_request():
    return Request({"type": "http", "headers": []})


def test_get_current_user_auth_disabled_returns_admin():
    user = auth.get_current_user(_dummy_request(), adapter=None)
    assert user.role == "admin"
    assert user.email == "test@local"


def test_require_admin_denies_non_admin():
    user = models.User(id="1", email="u@example.com", role="user", provider="local", name="User")
    with pytest.raises(HTTPException) as exc:
        auth.require_system_admin(user)
    assert "Admin access required" in str(exc.value)


class _Secret:
    def __init__(self, encrypted_password: str) -> None:
        self.encrypted_password = encrypted_password


class _Adapter:
    def __init__(self, secret: _Secret | None) -> None:
        self._secret = secret

    def get_bootstrap_secret(self):
        return self._secret

    def get_user_by_email(self, _email):
        return None

    def upsert_user(self, **_kwargs):
        return models.User(id="1", email="admin@local", role="admin", provider="local", name="admin")


def test_local_admin_login_invalid_username():
    with pytest.raises(HTTPException) as exc:
        auth.local_admin_login("not-admin", "pass", _Adapter(None))
    assert "Invalid credentials" in str(exc.value)


def test_local_admin_login_missing_secret():
    with pytest.raises(HTTPException) as exc:
        auth.local_admin_login("admin", "pass", _Adapter(None))
    assert "Admin not initialized" in str(exc.value)


def test_local_admin_login_invalid_password(monkeypatch):
    monkeypatch.setattr(auth, "decrypt_text", lambda _value: "correct")
    with pytest.raises(HTTPException) as exc:
        auth.local_admin_login("admin", "wrong", _Adapter(_Secret("enc")))
    assert "Invalid credentials" in str(exc.value)


# ── Session timeout and logout tests ───────────────────────────────────────────


def _mock_request(session_data: dict):
    """Create a mock request with session dict."""
    req = MagicMock()
    req.session = dict(session_data)
    return req


class _SessionAdapter:
    """Adapter stub for session tests."""
    def __init__(self, user: models.User | None = None):
        self.user = user
        self.session_version_incremented = False

    def get_user_by_id(self, user_id: str):
        if self.user and self.user.id == user_id:
            return self.user
        return None

    def get_user_organizations(self, user_id: str):
        # Return empty list (no orgs) for 2FA check
        return []

    def increment_user_session_version(self, user_id: str):
        self.session_version_incremented = True


def test_expired_session_is_rejected():
    """Session older than timeout should be rejected."""
    user = models.User(
        id="test-user",
        email="user@example.com",
        role="user",
        provider="local",
        name="Test User",
        session_version=0,
    )
    adapter = _SessionAdapter(user)

    # Create session with last_activity 31 minutes ago
    now = datetime.utcnow()
    old_time = (now - timedelta(minutes=31)).isoformat()
    req = _mock_request({
        "user_id": "test-user",
        "session_version": 0,
        "session_last_activity": old_time,
    })

    result = auth._get_user_from_session(req, adapter)

    assert result is None
    assert req.session == {}  # session should be cleared


def test_active_session_within_timeout():
    """Session within timeout should be accepted and refreshed."""
    user = models.User(
        id="test-user",
        email="user@example.com",
        role="user",
        provider="local",
        name="Test User",
        session_version=0,
    )
    adapter = _SessionAdapter(user)

    # Create session with last_activity 15 minutes ago
    now = datetime.utcnow()
    recent_time = (now - timedelta(minutes=15)).isoformat()
    req = _mock_request({
        "user_id": "test-user",
        "session_version": 0,
        "session_last_activity": recent_time,
    })

    result = auth._get_user_from_session(req, adapter)

    assert result is not None
    assert result.id == "test-user"
    # session_last_activity should be updated to now
    assert req.session.get("session_last_activity") is not None
    assert req.session.get("session_last_activity") != recent_time


def test_session_created_at_fallback():
    """Old sessions with session_created_at (no session_last_activity) should work."""
    user = models.User(
        id="test-user",
        email="user@example.com",
        role="user",
        provider="local",
        name="Test User",
        session_version=0,
    )
    adapter = _SessionAdapter(user)

    # Create session with only session_created_at (backward compat)
    now = datetime.utcnow()
    recent_time = (now - timedelta(minutes=15)).isoformat()
    req = _mock_request({
        "user_id": "test-user",
        "session_version": 0,
        "session_created_at": recent_time,  # old field name
    })

    result = auth._get_user_from_session(req, adapter)

    assert result is not None
    assert result.id == "test-user"
    # Should have created session_last_activity
    assert req.session.get("session_last_activity") is not None


def test_malformed_timestamp_is_rejected():
    """Session with malformed timestamp should be rejected."""
    user = models.User(
        id="test-user",
        email="user@example.com",
        role="user",
        provider="local",
        name="Test User",
        session_version=0,
    )
    adapter = _SessionAdapter(user)

    req = _mock_request({
        "user_id": "test-user",
        "session_version": 0,
        "session_last_activity": "not-a-valid-timestamp",
    })

    result = auth._get_user_from_session(req, adapter)

    assert result is None
    assert req.session == {}  # session should be cleared
