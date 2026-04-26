"""Tests for app.services.rate_limit."""
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

from app.db import get_adapter
from app.services.rate_limit import (
    check_rate_limit,
    clear_login_attempts,
    get_org_rate_limit_settings,
    record_failed_login,
)


def test_check_rate_limit_allows_under_limit():
    """Under limit: login allowed."""
    adapter = get_adapter()
    adapter.init()
    identifier = "user@example.com"
    # No failed attempts
    allowed, locked_until = check_rate_limit(adapter, identifier, org_id=None)
    assert allowed is True
    assert locked_until is None


def test_check_rate_limit_blocks_over_limit():
    """Over limit: login blocked with locked_until."""
    adapter = get_adapter()
    adapter.init()
    identifier = "blocked@example.com"
    # Record 4 failed attempts (default max)
    for _ in range(4):
        record_failed_login(adapter, identifier)
    allowed, locked_until = check_rate_limit(adapter, identifier, org_id=None)
    assert allowed is False
    assert locked_until is not None
    assert isinstance(locked_until, datetime)


def test_clear_login_attempts_resets():
    """clear_login_attempts resets count; next check allows login."""
    adapter = get_adapter()
    adapter.init()
    identifier = "reset@example.com"
    for _ in range(4):
        record_failed_login(adapter, identifier)
    allowed_before, _ = check_rate_limit(adapter, identifier, org_id=None)
    assert allowed_before is False

    clear_login_attempts(adapter, identifier)
    allowed_after, locked_until = check_rate_limit(adapter, identifier, org_id=None)
    assert allowed_after is True
    assert locked_until is None


def test_get_org_rate_limit_settings_defaults():
    """Org with no settings returns defaults."""
    adapter = get_adapter()
    adapter.init()
    org_id = adapter.ensure_system_org()
    settings = get_org_rate_limit_settings(adapter, org_id)
    assert settings["max_attempts"] == 4
    assert settings["lockout_minutes"] == 15


def test_get_org_rate_limit_settings_custom():
    """Org with custom rate limit settings returns them."""
    import json

    adapter = get_adapter()
    adapter.init()
    org = adapter.create_organization(
        name="Custom Rate Org",
        slug="custom-rate-org",
        settings=json.dumps({
            "rate_limit_max_attempts": 6,
            "rate_limit_lockout_minutes": 30,
        }),
    )
    settings = get_org_rate_limit_settings(adapter, org.id)
    assert settings["max_attempts"] == 6
    assert settings["lockout_minutes"] == 30
