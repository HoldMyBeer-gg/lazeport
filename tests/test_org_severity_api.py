"""
Unit tests for organization severity settings API endpoints (Phase 3).

Tests GET/PUT endpoints with RBAC, validation, and isolation.
"""
import json
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db import get_adapter
from app.db.models import SYSTEM_ORG_ID
from app.services.auth import get_current_user


def _make_client_as(user):
    """Return a TestClient that authenticates as the given user."""
    app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app)


class TestGetSeveritySettings:
    """Test GET /api/orgs/{org_id}/severity-settings endpoint."""

    @pytest.fixture(autouse=True)
    def cleanup_overrides(self):
        """Clear dependency overrides after each test."""
        yield
        app.dependency_overrides.clear()

    def test_org_admin_can_get_settings(self):
        """Test that org_admin can retrieve severity settings."""
        adapter = get_adapter()
        user = adapter.upsert_user(email="admin@test.com", name="Admin", provider="local", role="user")
        org = adapter.create_organization(name="Test Org", slug=f"test-get-{id(self)}")
        adapter.create_organization_member(org.id, user.id, role="org_admin")

        # Set up some criteria
        criteria = {
            "Critical": "Critical severity",
            "High": "High severity",
            "Medium": "Medium severity",
            "Low": "Low severity",
            "Informational": "Informational severity"
        }
        adapter.update_organization(org.id, severity_criteria=json.dumps(criteria))

        client = _make_client_as(user)
        response = client.get(f"/api/orgs/{org.id}/severity-settings")
        assert response.status_code == 200
        data = response.json()
        assert data["severity_criteria"] == criteria

    def test_org_owner_can_get_settings(self):
        """Test that org_owner can retrieve severity settings."""
        adapter = get_adapter()
        user = adapter.upsert_user(email="owner@test.com", name="Owner", provider="local", role="user")
        org = adapter.create_organization(name="Test Org", slug=f"test-owner-get-{id(self)}")
        adapter.create_organization_member(org.id, user.id, role="org_owner")

        client = _make_client_as(user)
        response = client.get(f"/api/orgs/{org.id}/severity-settings")
        assert response.status_code == 200
        assert "severity_criteria" in response.json()

    def test_consultant_denied_get(self):
        """Test that consultant role cannot get severity settings."""
        adapter = get_adapter()
        user = adapter.upsert_user(email="cons@test.com", name="Consultant", provider="local", role="user")
        org = adapter.create_organization(name="Test Org", slug=f"test-cons-get-{id(self)}")
        adapter.create_organization_member(org.id, user.id, role="consultant")

        client = _make_client_as(user)
        response = client.get(f"/api/orgs/{org.id}/severity-settings")
        assert response.status_code == 403

    def test_readonly_denied_get(self):
        """Test that readonly role cannot get severity settings."""
        adapter = get_adapter()
        user = adapter.upsert_user(email="ro@test.com", name="Readonly", provider="local", role="user")
        org = adapter.create_organization(name="Test Org", slug=f"test-ro-get-{id(self)}")
        adapter.create_organization_member(org.id, user.id, role="readonly")

        client = _make_client_as(user)
        response = client.get(f"/api/orgs/{org.id}/severity-settings")
        assert response.status_code == 403

    def test_non_member_denied_get(self):
        """Test that non-member cannot get severity settings."""
        adapter = get_adapter()
        user = adapter.upsert_user(email="nonmember@test.com", name="NonMember", provider="local", role="user")
        org = adapter.create_organization(name="Test Org", slug=f"test-nonmember-get-{id(self)}")

        client = _make_client_as(user)
        response = client.get(f"/api/orgs/{org.id}/severity-settings")
        assert response.status_code == 403

    def test_get_org_not_found(self):
        """Test that GET returns 403 for non-existent org (user not member)."""
        adapter = get_adapter()
        user = adapter.upsert_user(email="user@test.com", name="User", provider="local", role="user")

        client = _make_client_as(user)
        response = client.get("/api/orgs/00000000-0000-0000-0000-000000000099/severity-settings")
        # Returns 403 because user is not a member of the (non-existent) org
        assert response.status_code == 403


class TestPutSeveritySettings:
    """Test PUT /api/orgs/{org_id}/severity-settings endpoint."""

    @pytest.fixture(autouse=True)
    def cleanup_overrides(self):
        """Clear dependency overrides after each test."""
        yield
        app.dependency_overrides.clear()

    def test_org_admin_can_update_settings(self):
        """Test that org_admin can update severity settings."""
        adapter = get_adapter()
        user = adapter.upsert_user(email="admin@test.com", name="Admin", provider="local", role="user")
        org = adapter.create_organization(name="Test Org", slug=f"test-put-{id(self)}")
        adapter.create_organization_member(org.id, user.id, role="org_admin")

        new_criteria = {
            "Critical": "System down, no workaround",
            "High": "Major functionality impaired",
            "Medium": "Minor functionality impaired",
            "Low": "Cosmetic issue",
            "Informational": "Informational only"
        }

        client = _make_client_as(user)
        response = client.put(
            f"/api/orgs/{org.id}/severity-settings",
            json={"severity_criteria": new_criteria}
        )
        assert response.status_code == 200
        assert response.json()["severity_criteria"] == new_criteria

        # Verify it was persisted
        org_check = adapter.get_organization(org.id)
        stored = json.loads(org_check.severity_criteria)
        assert stored == new_criteria

    def test_org_owner_can_update_settings(self):
        """Test that org_owner can update severity settings."""
        adapter = get_adapter()
        user = adapter.upsert_user(email="owner@test.com", name="Owner", provider="local", role="user")
        org = adapter.create_organization(name="Test Org", slug=f"test-owner-put-{id(self)}")
        adapter.create_organization_member(org.id, user.id, role="org_owner")

        new_criteria = {
            "Critical": "Critical",
            "High": "High",
            "Medium": "Medium",
            "Low": "Low",
            "Informational": "Informational"
        }

        client = _make_client_as(user)
        response = client.put(
            f"/api/orgs/{org.id}/severity-settings",
            json={"severity_criteria": new_criteria}
        )
        assert response.status_code == 200

    def test_consultant_denied_put(self):
        """Test that consultant role cannot update severity settings."""
        adapter = get_adapter()
        user = adapter.upsert_user(email="cons@test.com", name="Consultant", provider="local", role="user")
        org = adapter.create_organization(name="Test Org", slug=f"test-cons-put-{id(self)}")
        adapter.create_organization_member(org.id, user.id, role="consultant")

        client = _make_client_as(user)
        response = client.put(
            f"/api/orgs/{org.id}/severity-settings",
            json={"severity_criteria": {"Critical": "C", "High": "H", "Medium": "M", "Low": "L", "Informational": "I"}}
        )
        assert response.status_code == 403

    def test_readonly_denied_put(self):
        """Test that readonly role cannot update severity settings."""
        adapter = get_adapter()
        user = adapter.upsert_user(email="ro@test.com", name="Readonly", provider="local", role="user")
        org = adapter.create_organization(name="Test Org", slug=f"test-ro-put-{id(self)}")
        adapter.create_organization_member(org.id, user.id, role="readonly")

        client = _make_client_as(user)
        response = client.put(
            f"/api/orgs/{org.id}/severity-settings",
            json={"severity_criteria": {"Critical": "C", "High": "H", "Medium": "M", "Low": "L", "Informational": "I"}}
        )
        assert response.status_code == 403

    def test_non_member_denied_put(self):
        """Test that non-member cannot update severity settings."""
        adapter = get_adapter()
        user = adapter.upsert_user(email="nonmember@test.com", name="NonMember", provider="local", role="user")
        org = adapter.create_organization(name="Test Org", slug=f"test-nonmember-put-{id(self)}")

        client = _make_client_as(user)
        response = client.put(
            f"/api/orgs/{org.id}/severity-settings",
            json={"severity_criteria": {"Critical": "C", "High": "H", "Medium": "M", "Low": "L", "Informational": "I"}}
        )
        assert response.status_code == 403

    def test_put_org_not_found(self):
        """Test that PUT returns 403 for non-existent org (user not member)."""
        adapter = get_adapter()
        user = adapter.upsert_user(email="user@test.com", name="User", provider="local", role="user")

        client = _make_client_as(user)
        response = client.put(
            "/api/orgs/00000000-0000-0000-0000-000000000099/severity-settings",
            json={"severity_criteria": {"Critical": "C", "High": "H", "Medium": "M", "Low": "L", "Informational": "I"}}
        )
        # Returns 403 because user is not a member of the (non-existent) org
        assert response.status_code == 403


class TestSeverityCriteriaValidation:
    """Test validation of severity criteria in PUT endpoint."""

    @pytest.fixture(autouse=True)
    def cleanup_overrides(self):
        """Clear dependency overrides after each test."""
        yield
        app.dependency_overrides.clear()

    @pytest.fixture
    def admin_org(self):
        """Create org with admin user."""
        adapter = get_adapter()
        user = adapter.upsert_user(email="admin@test.com", name="Admin", provider="local", role="user")
        org = adapter.create_organization(name="Test Org", slug=f"test-val-{id(self)}")
        adapter.create_organization_member(org.id, user.id, role="org_admin")
        app.dependency_overrides[get_current_user] = lambda: user
        return org.id

    def test_missing_level_critical(self, admin_org):
        """Test that missing Critical level is rejected."""
        adapter = get_adapter()
        admin_user = adapter.get_user_by_email("admin@test.com")
        client = _make_client_as(admin_user)
        response = client.put(
            f"/api/orgs/{admin_org}/severity-settings",
            json={"severity_criteria": {"High": "H", "Medium": "M", "Low": "L", "Informational": "I"}}
        )
        assert response.status_code == 422

    def test_missing_level_high(self, admin_org):
        """Test that missing High level is rejected."""
        adapter = get_adapter()
        admin_user = adapter.get_user_by_email("admin@test.com")
        client = _make_client_as(admin_user)
        response = client.put(
            f"/api/orgs/{admin_org}/severity-settings",
            json={"severity_criteria": {"Critical": "C", "Medium": "M", "Low": "L", "Informational": "I"}}
        )
        assert response.status_code == 422

    def test_extra_level(self, admin_org):
        """Test that extra levels are rejected."""
        adapter = get_adapter()
        admin_user = adapter.get_user_by_email("admin@test.com")
        client = _make_client_as(admin_user)
        response = client.put(
            f"/api/orgs/{admin_org}/severity-settings",
            json={
                "severity_criteria": {
                    "Critical": "C", "High": "H", "Medium": "M", "Low": "L", "Informational": "I",
                    "Ultra": "U"
                }
            }
        )
        assert response.status_code == 422

    def test_empty_definition(self, admin_org):
        """Test that empty definition is rejected."""
        adapter = get_adapter()
        admin_user = adapter.get_user_by_email("admin@test.com")
        client = _make_client_as(admin_user)
        response = client.put(
            f"/api/orgs/{admin_org}/severity-settings",
            json={"severity_criteria": {"Critical": "", "High": "H", "Medium": "M", "Low": "L", "Informational": "I"}}
        )
        assert response.status_code == 422

    def test_definition_too_long(self, admin_org):
        """Test that definition exceeding 2000 chars is rejected."""
        adapter = get_adapter()
        admin_user = adapter.get_user_by_email("admin@test.com")
        client = _make_client_as(admin_user)
        response = client.put(
            f"/api/orgs/{admin_org}/severity-settings",
            json={
                "severity_criteria": {
                    "Critical": "X" * 2001,
                    "High": "H", "Medium": "M", "Low": "L", "Informational": "I"
                }
            }
        )
        assert response.status_code == 422

    def test_definition_at_max_length(self, admin_org):
        """Test that definition at exactly 2000 chars is accepted."""
        adapter = get_adapter()
        admin_user = adapter.get_user_by_email("admin@test.com")
        client = _make_client_as(admin_user)
        response = client.put(
            f"/api/orgs/{admin_org}/severity-settings",
            json={
                "severity_criteria": {
                    "Critical": "X" * 2000,
                    "High": "H", "Medium": "M", "Low": "L", "Informational": "I"
                }
            }
        )
        assert response.status_code == 200

    def test_definition_with_html_script_tag(self, admin_org):
        """Test that HTML script tags are rejected."""
        adapter = get_adapter()
        admin_user = adapter.get_user_by_email("admin@test.com")
        client = _make_client_as(admin_user)
        response = client.put(
            f"/api/orgs/{admin_org}/severity-settings",
            json={
                "severity_criteria": {
                    "Critical": "Critical <script>alert('xss')</script>",
                    "High": "H", "Medium": "M", "Low": "L", "Informational": "I"
                }
            }
        )
        assert response.status_code == 422

    def test_definition_with_html_iframe_tag(self, admin_org):
        """Test that HTML iframe tags are rejected."""
        adapter = get_adapter()
        admin_user = adapter.get_user_by_email("admin@test.com")
        client = _make_client_as(admin_user)
        response = client.put(
            f"/api/orgs/{admin_org}/severity-settings",
            json={
                "severity_criteria": {
                    "Critical": "Critical <iframe src='evil.com'></iframe>",
                    "High": "H", "Medium": "M", "Low": "L", "Informational": "I"
                }
            }
        )
        assert response.status_code == 422

    def test_definition_with_safe_angle_brackets(self, admin_org):
        """Test that safe angle brackets (like in code samples) are allowed if no dangerous tags."""
        adapter = get_adapter()
        admin_user = adapter.get_user_by_email("admin@test.com")
        client = _make_client_as(admin_user)
        response = client.put(
            f"/api/orgs/{admin_org}/severity-settings",
            json={
                "severity_criteria": {
                    "Critical": "Critical vulnerability in <component>",
                    "High": "High", "Medium": "Medium", "Low": "Low", "Informational": "Informational"
                }
            }
        )
        assert response.status_code == 200

    def test_definition_not_string(self, admin_org):
        """Test that non-string definitions are rejected."""
        adapter = get_adapter()
        admin_user = adapter.get_user_by_email("admin@test.com")
        client = _make_client_as(admin_user)
        response = client.put(
            f"/api/orgs/{admin_org}/severity-settings",
            json={
                "severity_criteria": {
                    "Critical": 123,
                    "High": "H", "Medium": "M", "Low": "L", "Informational": "I"
                }
            }
        )
        assert response.status_code == 422

    def test_criteria_not_dict(self, admin_org):
        """Test that non-dict criteria are rejected."""
        adapter = get_adapter()
        admin_user = adapter.get_user_by_email("admin@test.com")
        client = _make_client_as(admin_user)
        response = client.put(
            f"/api/orgs/{admin_org}/severity-settings",
            json={"severity_criteria": ["Critical", "High", "Medium", "Low", "Informational"]}
        )
        assert response.status_code == 422


class TestSeveritySettingsOrgIsolation:
    """Test that org severity settings are properly isolated."""

    @pytest.fixture(autouse=True)
    def cleanup_overrides(self):
        """Clear dependency overrides after each test."""
        yield
        app.dependency_overrides.clear()

    def test_update_org_a_does_not_affect_org_b(self):
        """Test that updating OrgA's settings doesn't affect OrgB."""
        adapter = get_adapter()
        user_a = adapter.upsert_user(email="admin-a@test.com", name="Admin A", provider="local", role="user")
        user_b = adapter.upsert_user(email="admin-b@test.com", name="Admin B", provider="local", role="user")

        org_a = adapter.create_organization(name="Org A", slug=f"org-a-{id(self)}")
        org_b = adapter.create_organization(name="Org B", slug=f"org-b-{id(self)}")

        adapter.create_organization_member(org_a.id, user_a.id, role="org_admin")
        adapter.create_organization_member(org_b.id, user_b.id, role="org_admin")

        # Update OrgA's criteria with user_a
        criteria_a = {
            "Critical": "OrgA Critical",
            "High": "OrgA High",
            "Medium": "OrgA Medium",
            "Low": "OrgA Low",
            "Informational": "OrgA Informational"
        }

        client_a = _make_client_as(user_a)
        response = client_a.put(
            f"/api/orgs/{org_a.id}/severity-settings",
            json={"severity_criteria": criteria_a}
        )
        assert response.status_code == 200

        # Get OrgB's criteria with user_b (should be unchanged)
        client_b = _make_client_as(user_b)
        response_b = client_b.get(f"/api/orgs/{org_b.id}/severity-settings")
        assert response_b.status_code == 200
        criteria_b = response_b.json()["severity_criteria"]

        # OrgB should have different criteria than OrgA
        assert criteria_b != criteria_a
        # And OrgB's Critical should not be OrgA's Custom
        assert criteria_b.get("Critical") != "OrgA Critical"
