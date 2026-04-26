"""
Tests for OIDC/SSO authentication flow.

Covers email-check, login initiation, and callback handling.
"""
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db import get_adapter
from app.services.crypto import encrypt_text


def _get_csrf_headers(client: TestClient) -> dict:
    """Fetch CSRF token and return headers for state-changing requests."""
    r = client.get("/auth/csrf")
    assert r.status_code == 200
    token = r.json().get("token")
    assert token
    return {"X-CSRF-Token": token}


@pytest.fixture
def adapter():
    return get_adapter()


@pytest.fixture
def org_with_oidc(adapter):
    """Create org with domain and OIDC config."""
    org = adapter.create_organization(name="OIDC Test Org", slug="oidc-test-org")
    adapter.add_org_domain(org.id, "acme.com")
    adapter.upsert_org_oidc_config(
        org_id=org.id,
        provider_id="okta",
        provider_label="Okta SSO",
        issuer="https://dev-123.okta.com",
        client_id="test-client-id",
        client_secret_encrypted=encrypt_text("test-secret"),
    )
    return org


# ── Email check tests ──


def test_oidc_email_check_no_domain_returns_password_only(client):
    """Email without @ returns password_only."""
    headers = _get_csrf_headers(client)
    r = client.post(
        "/auth/oidc/email-check",
        json={"email": "x"},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json() == {"password_only": True}


def test_oidc_email_check_invalid_email_returns_password_only(client):
    """Email with no domain part returns password_only."""
    headers = _get_csrf_headers(client)
    r = client.post(
        "/auth/oidc/email-check",
        json={"email": "nobody"},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json() == {"password_only": True}


def test_oidc_email_check_unknown_domain_returns_password_only(client, adapter):
    """Domain not linked to any org returns password_only."""
    headers = _get_csrf_headers(client)
    r = client.post(
        "/auth/oidc/email-check",
        json={"email": "user@unknown.com"},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json() == {"password_only": True}


def test_oidc_email_check_org_no_domains_returns_password_only(client, adapter):
    """Org exists but has no domains linked returns password_only."""
    adapter.create_organization(name="No Domain Org", slug="no-domain-org")
    # No add_org_domain call
    headers = _get_csrf_headers(client)
    r = client.post(
        "/auth/oidc/email-check",
        json={"email": "user@example.com"},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json() == {"password_only": True}


def test_oidc_email_check_org_no_oidc_returns_password_only(client, adapter):
    """Org has domain but no OIDC config returns password_only."""
    org = adapter.create_organization(name="No OIDC Org", slug="no-oidc-org")
    adapter.add_org_domain(org.id, "example.com")
    headers = _get_csrf_headers(client)
    r = client.post(
        "/auth/oidc/email-check",
        json={"email": "user@example.com"},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json() == {"password_only": True}


def test_oidc_email_check_returns_oidc_offer(client, org_with_oidc):
    """Org with domain and OIDC config returns org_id, provider_id, provider_label."""
    headers = _get_csrf_headers(client)
    r = client.post(
        "/auth/oidc/email-check",
        json={"email": "alice@acme.com"},
        headers=headers,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["org_id"] == org_with_oidc.id
    assert data["provider_id"] == "okta"
    assert data["provider_label"] == "Okta SSO"


# ── Login initiation tests ──


def test_oidc_login_missing_org_id_returns_422(client):
    """Missing org_id returns 422."""
    r = client.get("/auth/oidc/login", params={"provider_id": "okta"})
    assert r.status_code == 422


def test_oidc_login_missing_provider_id_returns_422(client):
    """Missing provider_id returns 422."""
    r = client.get("/auth/oidc/login", params={"org_id": "00000000-0000-0000-0000-000000000001"})
    assert r.status_code == 422


@patch("app.api.auth.get_oidc_auth_url", new_callable=AsyncMock)
def test_oidc_login_valid_redirects_and_sets_session(mock_get_url, client, org_with_oidc):
    """Valid login redirects to IdP and sets session."""
    mock_get_url.return_value = ("https://idp.example.com/authorize?state=xyz", "xyz")
    r = client.get(
        "/auth/oidc/login",
        params={"org_id": org_with_oidc.id, "provider_id": "okta"},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert r.headers["location"].startswith("https://idp.example.com/")
    mock_get_url.assert_called_once()
    # Session should have oidc state (session cookie is set)
    assert "session" in r.cookies or "id" in str(r.cookies).lower()


@patch("app.api.auth.get_oidc_auth_url", new_callable=AsyncMock)
def test_oidc_login_invalid_config_redirects_to_failed(mock_get_url, client):
    """Invalid/unknown org or provider redirects to /login?error=oidc_failed."""
    mock_get_url.side_effect = ValueError("OIDC provider okta not configured for org")
    r = client.get(
        "/auth/oidc/login",
        params={"org_id": "00000000-0000-0000-0000-000000000001", "provider_id": "okta"},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "oidc_failed" in r.headers["location"]


# ── Callback tests ──


def test_oidc_callback_error_param_redirects_to_failed(client):
    """?error=... redirects to /login?error=oidc_failed."""
    r = client.get(
        "/auth/oidc/callback",
        params={"error": "access_denied"},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "/login?error=oidc_failed" in r.headers["location"]


def test_oidc_callback_missing_code_redirects_to_failed(client):
    """Missing code redirects to /login?error=oidc_failed."""
    r = client.get(
        "/auth/oidc/callback",
        params={"state": "some-state"},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "oidc_failed" in r.headers["location"]


def test_oidc_callback_missing_state_redirects_to_failed(client):
    """Missing state redirects to /login?error=oidc_failed."""
    r = client.get(
        "/auth/oidc/callback",
        params={"code": "auth-code"},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "oidc_failed" in r.headers["location"]


def test_oidc_callback_invalid_session_state_redirects_to_failed(client, org_with_oidc):
    """No/invalid session state redirects to /login?error=oidc_failed."""
    r = client.get(
        "/auth/oidc/callback",
        params={"code": "auth-code", "state": "random-state"},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "oidc_failed" in r.headers["location"]


@patch("app.api.auth.get_oidc_auth_url", new_callable=AsyncMock)
@patch("app.api.auth.exchange_code_for_userinfo", new_callable=AsyncMock)
def test_oidc_callback_user_not_found_redirects_to_no_account(
    mock_exchange, mock_get_url, client, org_with_oidc
):
    """User not in system (invite-only) redirects to /login?error=no_account."""
    mock_get_url.return_value = ("https://idp.example.com/auth", "state-123")
    mock_exchange.return_value = {"email": "newuser@acme.com", "sub": "oidc-sub"}

    # First establish session via login
    client.get(
        "/auth/oidc/login",
        params={"org_id": org_with_oidc.id, "provider_id": "okta"},
        follow_redirects=False,
    )

    r = client.get(
        "/auth/oidc/callback",
        params={"code": "auth-code", "state": "state-123"},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "no_account" in r.headers["location"]


@patch("app.api.auth.get_oidc_auth_url", new_callable=AsyncMock)
@patch("app.api.auth.exchange_code_for_userinfo", new_callable=AsyncMock)
def test_oidc_callback_success_redirects_to_dashboard(
    mock_exchange, mock_get_url, client, org_with_oidc, adapter, monkeypatch
):
    """Valid flow sets session and redirects to /dashboard."""
    monkeypatch.setenv("AUTH_DISABLED", "0")  # Ensure auth is checked for /api/me

    user = adapter.upsert_user(
        email="alice@acme.com", name="Alice", provider="local", role="user"
    )
    adapter.create_organization_member(org_with_oidc.id, user.id, "consultant")

    mock_get_url.return_value = ("https://idp.example.com/auth", "state-123")
    mock_exchange.return_value = {"email": "alice@acme.com", "sub": "oidc-sub"}

    client.get(
        "/auth/oidc/login",
        params={"org_id": org_with_oidc.id, "provider_id": "okta"},
        follow_redirects=False,
    )

    r = client.get(
        "/auth/oidc/callback",
        params={"code": "auth-code", "state": "state-123"},
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "/dashboard" in r.headers["location"]

    # Session should have user_id - verify by hitting /api/me
    me = client.get("/api/me")
    assert me.status_code == 200
    assert me.json()["email"] == "alice@acme.com"


@pytest.fixture
def client():
    return TestClient(app)
