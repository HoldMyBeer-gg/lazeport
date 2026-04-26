"""
Adversarial RBAC tests: cross-tenant isolation, privilege escalation,
readonly enforcement, and session invalidation (MED-6).
"""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock

from app.main import app
from app.db import get_adapter
from app.services.auth import get_current_user
from app.services.rbac import can_view_report, can_edit_report


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_client_as(user):
    app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app)


@pytest.fixture(autouse=True)
def cleanup_overrides():
    yield
    app.dependency_overrides.clear()


def _setup_two_orgs(adapter, suffix=""):
    """Create two isolated orgs each with an admin, consultant, and readonly user."""
    org_a = adapter.create_organization(name=f"Org A{suffix}", slug=f"org-a-adv{suffix}")
    org_b = adapter.create_organization(name=f"Org B{suffix}", slug=f"org-b-adv{suffix}")

    admin_a = adapter.upsert_user(
        email=f"admin_a{suffix}@adv.test", name="Admin A", provider="local", role="user"
    )
    adapter.create_organization_member(org_a.id, admin_a.id, "org_admin")

    admin_b = adapter.upsert_user(
        email=f"admin_b{suffix}@adv.test", name="Admin B", provider="local", role="user"
    )
    adapter.create_organization_member(org_b.id, admin_b.id, "org_admin")

    consultant_a = adapter.upsert_user(
        email=f"cons_a{suffix}@adv.test", name="Consultant A", provider="local", role="user"
    )
    adapter.create_organization_member(org_a.id, consultant_a.id, "consultant")

    readonly_a = adapter.upsert_user(
        email=f"readonly_a{suffix}@adv.test", name="Readonly A", provider="local", role="user"
    )
    adapter.create_organization_member(org_a.id, readonly_a.id, "readonly")

    return org_a, org_b, admin_a, admin_b, consultant_a, readonly_a


# ── Readonly report access ─────────────────────────────────────────────────────


class TestReadonlyReportAccess:
    """Readonly users can view reports shared with them but cannot edit anything."""

    @pytest.fixture()
    def setup(self):
        adapter = get_adapter()
        org_a, org_b, admin_a, admin_b, consultant_a, readonly_a = _setup_two_orgs(adapter, "-ro")
        client = adapter.create_client(name="Team RO", organization_id=org_a.id)
        app_obj = adapter.create_application(name="App RO", organization_id=org_a.id)
        report = adapter.create_report(
            "RO Report",
            organization_id=org_a.id,
            created_by=consultant_a.id,
            client_id=client.id,
            application_id=app_obj.id,
        )
        adapter.create_report_share(report.id, readonly_a.id, shared_by=consultant_a.id)
        return {
            "org_a": org_a,
            "report": report,
            "consultant_a": consultant_a,
            "readonly_a": readonly_a,
            "adapter": adapter,
        }

    def test_readonly_can_view_shared_report(self, setup):
        assert can_view_report(setup["readonly_a"], setup["report"], setup["adapter"]) is True

    def test_readonly_cannot_edit_shared_report(self, setup):
        assert can_edit_report(setup["readonly_a"], setup["report"], setup["adapter"]) is False

    def test_readonly_cannot_edit_report_they_created(self, setup):
        """Even if readonly user previously created a report they cannot edit it."""
        adapter = setup["adapter"]
        org_a = setup["org_a"]
        readonly_a = setup["readonly_a"]
        client = adapter.create_client(name="Team RO2", organization_id=org_a.id)
        app_obj = adapter.create_application(name="App RO2", organization_id=org_a.id)
        own_report = adapter.create_report(
            "RO Own Report",
            organization_id=org_a.id,
            created_by=readonly_a.id,
            client_id=client.id,
            application_id=app_obj.id,
        )
        assert can_view_report(readonly_a, own_report, adapter) is True
        assert can_edit_report(readonly_a, own_report, adapter) is False

    def test_readonly_cannot_view_unshared_report(self, setup):
        """Readonly cannot view a report that was not shared with them."""
        adapter = setup["adapter"]
        org_a = setup["org_a"]
        consultant_a = setup["consultant_a"]
        readonly_a = setup["readonly_a"]
        client = adapter.create_client(name="Team RO3", organization_id=org_a.id)
        app_obj = adapter.create_application(name="App RO3", organization_id=org_a.id)
        private_report = adapter.create_report(
            "Private Report",
            organization_id=org_a.id,
            created_by=consultant_a.id,
            client_id=client.id,
            application_id=app_obj.id,
        )
        assert can_view_report(readonly_a, private_report, adapter) is False

    def test_readonly_api_cannot_update_finding(self, setup):
        """Readonly user receives 403 when trying to edit a finding via the API."""
        adapter = setup["adapter"]
        report = setup["report"]
        readonly_a = setup["readonly_a"]
        finding = adapter.create_finding(
            report_id=report.id,
            title="Test Finding",
            content_json='{"Severity":"Low"}',
            notes="",
            template="",
        )
        client = _make_client_as(readonly_a)
        resp = client.put(
            f"/api/admin/findings/{finding.id}",
            json={"title": "Hacked", "content_json": '{"Severity":"Critical"}'},
        )
        assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.text}"


# ── Master template cross-org isolation ───────────────────────────────────────


class TestMasterTemplateCrossOrg:
    """Org A cannot read or delete Org B's master templates."""

    @pytest.fixture()
    def setup(self):
        adapter = get_adapter()
        org_a, org_b, admin_a, admin_b, _, _ = _setup_two_orgs(adapter, "-mt")
        adapter.create_master_template("secret-template-mt", b"DOCX content for org B", org_b.id)
        return {"org_a": org_a, "org_b": org_b, "admin_a": admin_a, "admin_b": admin_b}

    def test_org_a_cannot_download_org_b_template(self, setup):
        """Admin of Org A gets 404 (not 200) when requesting Org B's template by name."""
        client = _make_client_as(setup["admin_a"])
        resp = client.get("/api/admin/master-templates/secret-template-mt/download")
        assert resp.status_code == 404, f"Expected 404, got {resp.status_code}"

    def test_org_a_cannot_delete_org_b_template(self, setup):
        """Admin of Org A gets 404 when trying to delete Org B's template."""
        client = _make_client_as(setup["admin_a"])
        resp = client.delete("/api/admin/master-templates/secret-template-mt")
        assert resp.status_code == 404, f"Expected 404, got {resp.status_code}"

    def test_org_b_admin_can_access_own_template(self, setup):
        """Admin of Org B can download their own template."""
        client = _make_client_as(setup["admin_b"])
        resp = client.get("/api/admin/master-templates/secret-template-mt/download")
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"


# ── Audit log cross-org isolation ─────────────────────────────────────────────


class TestAuditLogCrossOrg:
    """An org admin cannot read another org's audit logs."""

    @pytest.fixture()
    def setup(self):
        adapter = get_adapter()
        org_a, org_b, admin_a, admin_b, _, _ = _setup_two_orgs(adapter, "-al")
        return {"org_a": org_a, "org_b": org_b, "admin_a": admin_a, "admin_b": admin_b}

    def test_org_a_admin_cannot_read_org_b_logs(self, setup):
        client = _make_client_as(setup["admin_a"])
        resp = client.get(f"/api/orgs/{setup['org_b'].id}/audit-logs")
        assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.text}"

    def test_org_b_admin_can_read_own_logs(self, setup):
        client = _make_client_as(setup["admin_b"])
        resp = client.get(f"/api/orgs/{setup['org_b'].id}/audit-logs")
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"

    def test_non_member_cannot_read_any_org_logs(self, setup):
        adapter = get_adapter()
        outsider = adapter.upsert_user(
            email="outsider_al@adv.test", name="Outsider AL", provider="local", role="user"
        )
        client = _make_client_as(outsider)
        resp = client.get(f"/api/orgs/{setup['org_a'].id}/audit-logs")
        assert resp.status_code == 403, f"Expected 403, got {resp.status_code}"


# ── Privilege escalation ───────────────────────────────────────────────────────


class TestPrivilegeEscalation:
    """Users cannot escalate their own or others' privileges."""

    @pytest.fixture()
    def setup(self):
        adapter = get_adapter()
        org_a, org_b, admin_a, admin_b, consultant_a, readonly_a = _setup_two_orgs(adapter, "-pe")
        return {
            "org_a": org_a,
            "admin_a": admin_a,
            "consultant_a": consultant_a,
            "readonly_a": readonly_a,
            "adapter": adapter,
        }

    def test_user_cannot_change_own_role(self, setup):
        """An org_owner cannot change their own role (self-role-change guard returns 400)."""
        org_a = setup["org_a"]
        adapter = setup["adapter"]
        owner = adapter.upsert_user(
            email="owner_pe@adv.test", name="Owner PE", provider="local", role="user"
        )
        adapter.create_organization_member(org_a.id, owner.id, "org_owner")
        client = _make_client_as(owner)
        resp = client.put(
            f"/api/orgs/{org_a.id}/members/{owner.id}/role",
            json={"role": "consultant"},
        )
        assert resp.status_code == 400, f"Expected 400, got {resp.status_code}: {resp.text}"

    def test_consultant_cannot_change_member_role(self, setup):
        """A consultant cannot change another member's role (requires org_owner)."""
        org_a = setup["org_a"]
        consultant_a = setup["consultant_a"]
        admin_a = setup["admin_a"]
        client = _make_client_as(consultant_a)
        resp = client.put(
            f"/api/orgs/{org_a.id}/members/{admin_a.id}/role",
            json={"role": "consultant"},
        )
        assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.text}"

    def test_readonly_cannot_change_member_role(self, setup):
        """A readonly user cannot promote anyone."""
        org_a = setup["org_a"]
        readonly_a = setup["readonly_a"]
        consultant_a = setup["consultant_a"]
        client = _make_client_as(readonly_a)
        resp = client.put(
            f"/api/orgs/{org_a.id}/members/{consultant_a.id}/role",
            json={"role": "org_admin"},
        )
        assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.text}"

    def test_org_admin_cannot_reset_2fa(self, setup):
        """An org_admin (not system admin) cannot reset another user's 2FA."""
        admin_a = setup["admin_a"]
        consultant_a = setup["consultant_a"]
        client = _make_client_as(admin_a)
        resp = client.post(f"/api/admin/users/{consultant_a.id}/2fa/reset")
        assert resp.status_code in (401, 403), f"Expected 401/403, got {resp.status_code}: {resp.text}"


# ── Session version invalidation (MED-6) ──────────────────────────────────────


class TestSessionVersionInvalidation:
    """session_version mismatch forces session clear; 2FA reset increments it."""

    def _mock_request(self, session_data: dict):
        req = MagicMock()
        req.session = dict(session_data)
        return req

    def test_correct_session_version_allows_access(self):
        from app.services.auth import _get_user_from_session
        adapter = get_adapter()
        user = adapter.upsert_user(
            email="sessv_ok@adv.test", name="SessV OK", provider="local", role="user"
        )
        req = self._mock_request({"user_id": user.id, "session_version": 0})
        result = _get_user_from_session(req, adapter)
        assert result is not None
        assert result.id == user.id

    def test_stale_session_version_clears_session(self):
        """After session_version is incremented (e.g. 2FA reset), old cookie is rejected."""
        from app.services.auth import _get_user_from_session
        adapter = get_adapter()
        user = adapter.upsert_user(
            email="sessv_stale@adv.test", name="SessV Stale", provider="local", role="user"
        )
        adapter.increment_user_session_version(user.id)  # DB now at version 1

        req = self._mock_request({"user_id": user.id, "session_version": 0})  # cookie still at 0
        result = _get_user_from_session(req, adapter)
        assert result is None, "Stale session should be rejected"
        assert "user_id" not in req.session, "Session should be cleared on mismatch"

    def test_missing_session_version_in_cookie_rejected_after_increment(self):
        """A cookie without session_version (legacy) is treated as version 0 and rejected if DB > 0."""
        from app.services.auth import _get_user_from_session
        adapter = get_adapter()
        user = adapter.upsert_user(
            email="sessv_legacy@adv.test", name="SessV Legacy", provider="local", role="user"
        )
        adapter.increment_user_session_version(user.id)

        req = self._mock_request({"user_id": user.id})  # no session_version key
        result = _get_user_from_session(req, adapter)
        assert result is None

    def test_increment_advances_version(self):
        adapter = get_adapter()
        user = adapter.upsert_user(
            email="sessv_inc@adv.test", name="SessV Inc", provider="local", role="user"
        )
        assert user.session_version == 0
        adapter.increment_user_session_version(user.id)
        assert adapter.get_user_by_id(user.id).session_version == 1
        adapter.increment_user_session_version(user.id)
        assert adapter.get_user_by_id(user.id).session_version == 2

    def test_2fa_reset_increments_session_version(self):
        """2FA reset via API must bump session_version so existing sessions are invalidated."""
        adapter = get_adapter()
        sys_admin = adapter.upsert_user(
            email="sysadmin_sv@adv.test", name="SysAdmin SV", provider="local", role="admin"
        )
        target = adapter.upsert_user(
            email="target_sv@adv.test", name="Target SV", provider="local", role="user"
        )
        adapter.update_user_2fa(target.id, twofa_secret="SECRET", twofa_enabled=True, twofa_backup_codes="[]")
        assert adapter.get_user_by_id(target.id).session_version == 0

        app.dependency_overrides[get_current_user] = lambda: sys_admin
        client = TestClient(app)
        resp = client.post(f"/api/admin/users/{target.id}/2fa/reset")
        app.dependency_overrides.clear()

        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
        refreshed = adapter.get_user_by_id(target.id)
        assert refreshed.twofa_enabled is False
        assert refreshed.session_version == 1, "session_version must be incremented after 2FA reset"
