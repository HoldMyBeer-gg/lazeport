"""
Tests that non-org-admin users are properly denied access to
organization-level settings endpoints (members, email, security, vision, audit).

Uses FastAPI dependency overrides to simulate users with different org roles.
"""
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db import get_adapter
from app.services.auth import get_current_user


# Helpers


def _setup_org_and_users(adapter):
    """Create an org, an admin user, and a consultant user with memberships."""
    org = adapter.create_organization(name="RBAC Test Org", slug="rbac-test-org")

    admin_user = adapter.upsert_user(
        email="orgadmin@test.com", name="Org Admin", provider="local", role="user"
    )
    adapter.create_organization_member(
        org_id=org.id, user_id=admin_user.id, role="org_admin"
    )

    consultant_user = adapter.upsert_user(
        email="consultant@test.com", name="Consultant", provider="local", role="user"
    )
    adapter.create_organization_member(
        org_id=org.id, user_id=consultant_user.id, role="consultant"
    )

    readonly_user = adapter.upsert_user(
        email="readonly@test.com", name="ReadOnly", provider="local", role="user"
    )
    adapter.create_organization_member(
        org_id=org.id, user_id=readonly_user.id, role="readonly"
    )

    return org, admin_user, consultant_user, readonly_user


def _make_client_as(user):
    """Return a TestClient that authenticates as the given user."""
    app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app)


# Fixtures


@pytest.fixture(autouse=True)
def cleanup_overrides():
    """Reset dependency overrides after each test."""
    yield
    app.dependency_overrides.clear()


@pytest.fixture()
def org_data():
    """Set up an org with admin, consultant, and readonly users."""
    adapter = get_adapter()
    return _setup_org_and_users(adapter)


# Gated endpoints that require org_admin or org_owner

ORG_ADMIN_GET_ENDPOINTS = [
    "/api/orgs/{org_id}/members",
    "/api/orgs/{org_id}/email-settings",
    "/api/orgs/{org_id}/rate-limit-settings",
    "/api/orgs/{org_id}/vision-settings",
    "/api/orgs/{org_id}/audit-logs",
    "/api/orgs/{org_id}/oidc-config",
    "/api/orgs/{org_id}/domains",
]

ORG_ADMIN_PUT_ENDPOINTS = [
    "/api/orgs/{org_id}/email-settings",
    "/api/orgs/{org_id}/rate-limit-settings",
    "/api/orgs/{org_id}/vision-settings",
    "/api/orgs/{org_id}/llm-settings",
]


# Tests: consultant cannot access org-admin endpoints


class TestConsultantDenied:
    """A consultant-role user should get 403 on all org-admin endpoints."""

    @pytest.mark.parametrize("endpoint", ORG_ADMIN_GET_ENDPOINTS)
    def test_get_endpoints_return_403(self, org_data, endpoint):
        org, _, consultant, _ = org_data
        client = _make_client_as(consultant)
        url = endpoint.format(org_id=org.id)
        resp = client.get(url)
        assert resp.status_code == 403, f"Expected 403 on GET {url}, got {resp.status_code}"

    @pytest.mark.parametrize("endpoint,payload", [
        ("/api/orgs/{org_id}/email-settings", {"host": "x", "port": 25, "username": "", "sender": ""}),
        ("/api/orgs/{org_id}/rate-limit-settings", {"max_attempts": 5, "lockout_minutes": 15}),
        ("/api/orgs/{org_id}/vision-settings", {"max_concurrent_tasks": 2}),
        ("/api/orgs/{org_id}/llm-settings", {"provider": "openai", "model": "gpt-4o-mini"}),
    ])
    def test_put_endpoints_return_403(self, org_data, endpoint, payload):
        org, _, consultant, _ = org_data
        client = _make_client_as(consultant)
        url = endpoint.format(org_id=org.id)
        resp = client.put(url, json=payload)
        assert resp.status_code == 403, f"Expected 403 on PUT {url}, got {resp.status_code}"

    def test_post_email_test_returns_403(self, org_data):
        org, _, consultant, _ = org_data
        client = _make_client_as(consultant)
        resp = client.post(
            f"/api/orgs/{org.id}/email-settings/test",
            json={"to_email": "x@x.com"},
        )
        assert resp.status_code == 403

    def test_post_members_returns_403(self, org_data):
        """Consultant cannot invite members (requires org_owner)."""
        org, _, consultant, _ = org_data
        client = _make_client_as(consultant)
        resp = client.post(
            f"/api/orgs/{org.id}/members",
            json={"user_email": "newuser@test.com", "role": "consultant"},
        )
        assert resp.status_code == 403

    def test_put_oidc_config_returns_403(self, org_data):
        """Consultant cannot update OIDC config."""
        org, _, consultant, _ = org_data
        client = _make_client_as(consultant)
        resp = client.put(
            f"/api/orgs/{org.id}/oidc-config",
            json={"issuer": "https://x.okta.com", "client_id": "x", "client_secret": ""},
        )
        assert resp.status_code == 403

    def test_post_domains_returns_403(self, org_data):
        """Consultant cannot add org domains."""
        org, _, consultant, _ = org_data
        client = _make_client_as(consultant)
        resp = client.post(
            f"/api/orgs/{org.id}/domains",
            json={"domain": "example.com"},
        )
        assert resp.status_code == 403

    def test_delete_oidc_config_returns_403(self, org_data):
        """Consultant cannot delete OIDC config."""
        org, _, consultant, _ = org_data
        client = _make_client_as(consultant)
        resp = client.delete(f"/api/orgs/{org.id}/oidc-config?provider_id=okta")
        assert resp.status_code == 403

    def test_delete_domain_returns_403(self, org_data):
        """Consultant cannot remove org domains."""
        org, _, consultant, _ = org_data
        client = _make_client_as(consultant)
        resp = client.delete(f"/api/orgs/{org.id}/domains?domain=example.com")
        assert resp.status_code == 403


# Tests: readonly cannot access org-admin endpoints


class TestReadonlyDenied:
    """A readonly-role user should get 403 on all org-admin endpoints."""

    @pytest.mark.parametrize("endpoint", ORG_ADMIN_GET_ENDPOINTS)
    def test_get_endpoints_return_403(self, org_data, endpoint):
        org, _, _, readonly = org_data
        client = _make_client_as(readonly)
        url = endpoint.format(org_id=org.id)
        resp = client.get(url)
        assert resp.status_code == 403, f"Expected 403 on GET {url}, got {resp.status_code}"

    @pytest.mark.parametrize("endpoint,payload", [
        ("/api/orgs/{org_id}/email-settings", {"host": "x", "port": 25, "username": "", "sender": ""}),
        ("/api/orgs/{org_id}/rate-limit-settings", {"max_attempts": 5, "lockout_minutes": 15}),
        ("/api/orgs/{org_id}/vision-settings", {"max_concurrent_tasks": 2}),
        ("/api/orgs/{org_id}/llm-settings", {"provider": "openai", "model": "gpt-4o-mini"}),
    ])
    def test_put_endpoints_return_403(self, org_data, endpoint, payload):
        org, _, _, readonly = org_data
        client = _make_client_as(readonly)
        url = endpoint.format(org_id=org.id)
        resp = client.put(url, json=payload)
        assert resp.status_code == 403, f"Expected 403 on PUT {url}, got {resp.status_code}"

    def test_put_oidc_config_returns_403(self, org_data):
        """Readonly cannot update OIDC config."""
        org, _, _, readonly = org_data
        client = _make_client_as(readonly)
        resp = client.put(
            f"/api/orgs/{org.id}/oidc-config",
            json={"issuer": "https://x.okta.com", "client_id": "x", "client_secret": ""},
        )
        assert resp.status_code == 403

    def test_post_domains_returns_403(self, org_data):
        """Readonly cannot add org domains."""
        org, _, _, readonly = org_data
        client = _make_client_as(readonly)
        resp = client.post(
            f"/api/orgs/{org.id}/domains",
            json={"domain": "example.com"},
        )
        assert resp.status_code == 403

    def test_delete_oidc_config_returns_403(self, org_data):
        """Readonly cannot delete OIDC config."""
        org, _, _, readonly = org_data
        client = _make_client_as(readonly)
        resp = client.delete(f"/api/orgs/{org.id}/oidc-config?provider_id=okta")
        assert resp.status_code == 403

    def test_delete_domain_returns_403(self, org_data):
        """Readonly cannot remove org domains."""
        org, _, _, readonly = org_data
        client = _make_client_as(readonly)
        resp = client.delete(f"/api/orgs/{org.id}/domains?domain=example.com")
        assert resp.status_code == 403


# Tests: org_admin CAN access org-admin endpoints


class TestOrgAdminAllowed:
    """An org_admin user should be allowed access to org-admin endpoints."""

    @pytest.mark.parametrize("endpoint", ORG_ADMIN_GET_ENDPOINTS)
    def test_get_endpoints_return_200(self, org_data, endpoint):
        org, admin, _, _ = org_data
        client = _make_client_as(admin)
        url = endpoint.format(org_id=org.id)
        resp = client.get(url)
        assert resp.status_code == 200, f"Expected 200 on GET {url}, got {resp.status_code}: {resp.text}"


# Tests: readonly CAN manage own trends filter presets


def test_readonly_can_save_and_delete_own_trends_presets(org_data):
    """Readonly users are allowed to create and delete their own trends filter presets."""
    org, _, _, readonly = org_data
    client = _make_client_as(readonly)
    r = client.get("/api/admin/trends-presets")
    assert r.status_code == 200
    assert r.json() == []
    r = client.post(
        "/api/admin/trends-presets",
        json={"name": "My filters", "filters": {"dateRange": "Last 7 days", "client": [], "app": [], "severity": [], "status": [], "tag": []}},
    )
    assert r.status_code == 200
    preset_id = r.json()["id"]
    r = client.get("/api/admin/trends-presets")
    assert r.status_code == 200
    assert len(r.json()) == 1
    r = client.delete(f"/api/admin/trends-presets/{preset_id}")
    assert r.status_code == 200
    r = client.get("/api/admin/trends-presets")
    assert r.json() == []


# Tests: non-member gets 403


class TestNonMemberDenied:
    """A user who is not a member of the org should get 403."""

    @pytest.mark.parametrize("endpoint", ORG_ADMIN_GET_ENDPOINTS)
    def test_non_member_gets_403(self, org_data, endpoint):
        org, _, _, _ = org_data
        adapter = get_adapter()
        outsider = adapter.upsert_user(
            email="outsider@test.com", name="Outsider", provider="local", role="user"
        )
        client = _make_client_as(outsider)
        url = endpoint.format(org_id=org.id)
        resp = client.get(url)
        assert resp.status_code == 403, f"Expected 403 on GET {url}, got {resp.status_code}"

    def test_non_member_cannot_read_llm_settings(self, org_data):
        """Non-member cannot GET llm-settings even though endpoint allows all org roles."""
        org, _, _, _ = org_data
        adapter = get_adapter()
        outsider = adapter.upsert_user(
            email="outsider-llm@test.com", name="LLM Outsider", provider="local", role="user"
        )
        client = _make_client_as(outsider)
        resp = client.get(f"/api/orgs/{org.id}/llm-settings")
        assert resp.status_code == 403

    def test_non_member_cannot_update_llm_settings(self, org_data):
        """Non-member cannot PUT llm-settings."""
        org, _, _, _ = org_data
        adapter = get_adapter()
        outsider = adapter.upsert_user(
            email="outsider-llm-put@test.com", name="LLM Outsider PUT", provider="local", role="user"
        )
        client = _make_client_as(outsider)
        resp = client.put(f"/api/orgs/{org.id}/llm-settings", json={"provider": "openai"})
        assert resp.status_code == 403

    def test_non_member_cannot_read_llm_settings_all(self, org_data):
        """Non-member cannot GET llm-settings/all."""
        org, _, _, _ = org_data
        adapter = get_adapter()
        outsider = adapter.upsert_user(
            email="outsider-llm-all@test.com", name="LLM Outsider All", provider="local", role="user"
        )
        client = _make_client_as(outsider)
        resp = client.get(f"/api/orgs/{org.id}/llm-settings/all")
        assert resp.status_code == 403

    def test_member_of_org_a_cannot_write_llm_settings_to_org_b(self):
        """Org admin of org A cannot PUT llm-settings for org B (cross-org write)."""
        adapter = get_adapter()
        org_a = adapter.create_organization(name="Cross RBAC Org A", slug="cross-rbac-org-a")
        org_b = adapter.create_organization(name="Cross RBAC Org B", slug="cross-rbac-org-b")
        user_a = adapter.upsert_user(
            email="cross-admin-a@test.com", name="Admin A", provider="local", role="user"
        )
        adapter.create_organization_member(org_id=org_a.id, user_id=user_a.id, role="org_admin")
        client = _make_client_as(user_a)
        resp = client.put(f"/api/orgs/{org_b.id}/llm-settings", json={"provider": "openai"})
        assert resp.status_code == 403, f"Expected 403 cross-org PUT, got {resp.status_code}"

    def test_member_of_org_a_cannot_read_llm_settings_of_org_b(self):
        """Org member of org A cannot GET llm-settings for org B (cross-org read)."""
        adapter = get_adapter()
        org_a = adapter.create_organization(name="Cross RBAC Read A", slug="cross-rbac-read-a")
        org_b = adapter.create_organization(name="Cross RBAC Read B", slug="cross-rbac-read-b")
        user_a = adapter.upsert_user(
            email="cross-reader-a@test.com", name="Reader A", provider="local", role="user"
        )
        adapter.create_organization_member(org_id=org_a.id, user_id=user_a.id, role="consultant")
        client = _make_client_as(user_a)
        resp = client.get(f"/api/orgs/{org_b.id}/llm-settings")
        assert resp.status_code == 403, f"Expected 403 cross-org GET, got {resp.status_code}"

    def test_sysadmin_llm_settings_are_org_scoped(self):
        """
        Regression: LLM settings saved for org A must not bleed into org B.

        The frontend bug (Settings.vue using orgs[0].id from /api/orgs instead
        of user.org_id from /api/me) caused a system admin's PUT to land on
        whichever org appeared first in the API list rather than their own org.
        The backend must store settings per-org; this test confirms isolation.

        System admins bypass org membership checks (get_user_role_in_org returns
        "admin" for any org), so the test uses a sysadmin who can freely read
        and write both orgs, making it easy to verify isolation without needing
        a non-existent org_id field on the User model.
        """
        adapter = get_adapter()
        org_a = adapter.create_organization(name="LLM Scope Org A", slug="llm-scope-org-a")
        org_b = adapter.create_organization(name="LLM Scope Org B", slug="llm-scope-org-b")
        sysadmin = adapter.upsert_user(
            email="sysadmin-scope@test.com", name="Sysadmin Scope", provider="local", role="admin"
        )
        client = _make_client_as(sysadmin)

        # Save "deepseek" to org_a only
        resp = client.put(
            f"/api/orgs/{org_a.id}/llm-settings",
            json={"provider": "deepseek", "model": "deepseek-chat"},
        )
        assert resp.status_code == 200, f"PUT to org_a failed: {resp.text}"
        assert resp.json()["provider"] == "deepseek"

        # org_b must remain unaffected
        resp_b = client.get(f"/api/orgs/{org_b.id}/llm-settings")
        assert resp_b.status_code == 200
        assert resp_b.json().get("provider") != "deepseek", (
            "LLM settings leaked into org_b — PUT to org_a wrote to the wrong org"
        )

        # org_a must have the updated setting
        resp_a = client.get(f"/api/orgs/{org_a.id}/llm-settings")
        assert resp_a.status_code == 200
        assert resp_a.json()["provider"] == "deepseek"
