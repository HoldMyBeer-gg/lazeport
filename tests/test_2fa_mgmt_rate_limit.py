"""Regression: 2FA disable/regenerate must return 429 when rate-limited, not crash.

A function-local `from datetime import datetime` further down each handler made
`datetime` a local for the whole function, so the rate-limit branch above it
raised UnboundLocalError (500) instead of the intended 429.
"""
import json

import pytest
from fastapi.testclient import TestClient

from app.db import get_adapter, models
from app.main import app
from app.services import twofa
from app.services.auth import get_current_user, hash_password
from app.services.rate_limit import DEFAULT_MAX_ATTEMPTS


@pytest.fixture(autouse=True)
def _cleanup_overrides():
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def locked_user():
    adapter = get_adapter()
    user = adapter.upsert_user(email="locked@test.com", name="Locked", provider="local", role="user")
    adapter.set_user_password_hash(user.id, hash_password("correct horse battery staple"))
    with adapter._session() as session:
        db_user = session.get(models.User, user.id)
        db_user.twofa_secret = twofa.encrypt_secret(twofa.generate_secret())
        db_user.twofa_enabled = True
        db_user.twofa_backup_codes = json.dumps(["c1"])
        session.commit()
    user = adapter.get_user_by_id(user.id)
    for _ in range(DEFAULT_MAX_ATTEMPTS):
        adapter.create_login_attempt(identifier=f"2fa_mgmt_{user.id}", success=False)
    app.dependency_overrides[get_current_user] = lambda: user
    return user


@pytest.mark.parametrize("path", ["/auth/2fa/disable", "/auth/2fa/regenerate-backup-codes"])
def test_rate_limited_2fa_management_returns_429(locked_user, path):
    client = TestClient(app)
    r = client.post(path, json={"password": "correct horse battery staple"})
    assert r.status_code == 429, r.text
    assert "Too many attempts" in r.json()["detail"]
