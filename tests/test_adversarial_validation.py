"""
Comprehensive adversarial validation tests for API endpoints.

Tests verify that Pydantic validators and route handlers reject null, missing,
empty, wrong-type, and out-of-range values gracefully with appropriate HTTP status codes:
- 422: Pydantic validation error (wrong type, failed validator, required field missing)
- 400: Business logic validation error (too-short password, empty name after strip, etc.)
- 401: Authentication error (wrong credentials)
- Status codes may be != 200 when type coercion makes exact code environment-dependent

See plan in /tests/test_adversarial_validation.py comments for edge case explanations.
"""
import json
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db import get_adapter
from app.db.models import SYSTEM_ORG_ID

DUMMY_UUID = "00000000-0000-0000-0000-000000000001"


# ── Fixtures ──

@pytest.fixture(autouse=True)
def cleanup_overrides():
    """Clear dependency overrides after each test."""
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def client():
    """FastAPI test client with AUTH_DISABLED=1 (set in conftest.py)."""
    return TestClient(app)


@pytest.fixture
def org_setup():
    """Create a test organization."""
    adapter = get_adapter()
    org = adapter.create_organization(name="Adversarial Org", slug="adv-test")
    return {"org_id": org.id, "adapter": adapter}


@pytest.fixture
def report_setup():
    """Create a test report for adversarial finding tests."""
    adapter = get_adapter()
    user = adapter.upsert_user(
        email="adv@test.com",
        name="Adv Tester",
        provider="local",
        role="admin"
    )
    report = adapter.create_report(
        name="Adv Report",
        organization_id=SYSTEM_ORG_ID,
        created_by=user.id
    )
    return {"report_id": report.id, "adapter": adapter}


# ══════════════════════════════════════════════════════════════════════════════
# Group 1: Auth Endpoints (no fixture needed; validators run regardless of auth)
# ══════════════════════════════════════════════════════════════════════════════

class TestAuthLoginAdversarial:
    """POST /auth/login adversarial tests."""

    def test_missing_email_field(self, client):
        """Missing required email field."""
        r = client.post("/auth/login", json={"password": "x"})
        assert r.status_code == 422

    def test_missing_password_field(self, client):
        """Missing required password field."""
        r = client.post("/auth/login", json={"email": "a@b.com"})
        assert r.status_code == 422

    def test_email_null(self, client):
        """Null email value."""
        r = client.post("/auth/login", json={"email": None, "password": "x"})
        assert r.status_code == 422

    def test_password_null(self, client):
        """Null password value."""
        r = client.post("/auth/login", json={"email": "a@b.com", "password": None})
        assert r.status_code == 422

    def test_empty_body(self, client):
        """Empty JSON body."""
        r = client.post("/auth/login", json={})
        assert r.status_code == 422

    def test_email_empty_string(self, client):
        """
        Empty email string.
        Edge case: validate_email only guards if v is None; empty string passes Pydantic,
        then the route handler at /auth/login line 216 raises 400 "email is required".
        """
        r = client.post("/auth/login", json={"email": "", "password": "x"})
        assert r.status_code == 400

    def test_email_too_long(self, client):
        """Email longer than 255 chars (validator max)."""
        long_email = "a" * 256 + "@b.com"
        r = client.post("/auth/login", json={"email": long_email, "password": "x"})
        assert r.status_code == 422

    def test_password_too_long(self, client):
        """Password longer than 255 chars (validator max)."""
        long_password = "x" * 256
        r = client.post("/auth/login", json={"email": "a@b.com", "password": long_password})
        assert r.status_code == 422


class TestAuthLoginLocalAdversarial:
    """POST /auth/login/local adversarial tests."""

    def test_missing_username(self, client):
        """Missing required username field."""
        r = client.post("/auth/login/local", json={"password": "x"})
        assert r.status_code == 422

    def test_missing_password(self, client):
        """Missing required password field."""
        r = client.post("/auth/login/local", json={"username": "admin"})
        assert r.status_code == 422

    def test_username_null(self, client):
        """Null username value."""
        r = client.post("/auth/login/local", json={"username": None, "password": "x"})
        assert r.status_code == 422

    def test_password_null(self, client):
        """Null password value."""
        r = client.post("/auth/login/local", json={"username": "admin", "password": None})
        assert r.status_code == 422

    def test_empty_body(self, client):
        """Empty JSON body."""
        r = client.post("/auth/login/local", json={})
        assert r.status_code == 422

    def test_username_too_long(self, client):
        """Username longer than 255 chars."""
        long_username = "a" * 256
        r = client.post("/auth/login/local", json={"username": long_username, "password": "x"})
        assert r.status_code == 422


class TestInviteAcceptAdversarial:
    """POST /auth/invite/accept adversarial tests."""

    def test_missing_token(self, client):
        """Missing required token field."""
        r = client.post("/auth/invite/accept", json={"password": "password123456"})
        assert r.status_code == 422

    def test_missing_password(self, client):
        """Missing required password field."""
        r = client.post("/auth/invite/accept", json={"token": "x" * 20})
        assert r.status_code == 422

    def test_token_null(self, client):
        """Null token value."""
        r = client.post("/auth/invite/accept", json={"token": None, "password": "password123456"})
        assert r.status_code == 422

    def test_password_null(self, client):
        """Null password value."""
        r = client.post("/auth/invite/accept", json={"token": "x" * 20, "password": None})
        assert r.status_code == 422

    def test_short_token(self, client):
        """Token shorter than required length (route checks len < 20)."""
        r = client.post("/auth/invite/accept", json={"token": "short", "password": "password123456"})
        assert r.status_code == 400

    def test_short_password(self, client):
        """Password shorter than required length (route checks len < 12)."""
        r = client.post("/auth/invite/accept", json={"token": "x" * 20, "password": "short"})
        assert r.status_code == 400

    def test_token_too_long(self, client):
        """Token longer than 1024 chars (validator max)."""
        long_token = "x" * 1025
        r = client.post("/auth/invite/accept", json={"token": long_token, "password": "password123456"})
        assert r.status_code == 422

    def test_password_too_long(self, client):
        """Password longer than 1024 chars."""
        long_password = "x" * 1025
        r = client.post("/auth/invite/accept", json={"token": "x" * 20, "password": long_password})
        assert r.status_code == 422


class TestTwoFAAdversarial:
    """POST /auth/2fa/verify adversarial tests.

    Note: These tests use a clean session (no pending_2fa_user_id), so all should get
    400 "No login in progress" from the route handler. The TwoFAVerifyRequest model
    has no validators, so we're mainly documenting that the model accepts any strings.
    """

    def test_empty_body(self, client):
        """Empty JSON body."""
        r = client.post("/auth/2fa/verify", json={})
        assert r.status_code == 400

    def test_explicit_empty_strings(self, client):
        """Both code and backup_code are empty strings."""
        r = client.post("/auth/2fa/verify", json={"code": "", "backup_code": ""})
        assert r.status_code == 400

    def test_very_long_code(self, client):
        """Code field with 10000 characters (model accepts it, route rejects)."""
        r = client.post("/auth/2fa/verify", json={"code": "A" * 10000, "backup_code": ""})
        assert r.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# Group 2: Finding CRUD (requires report_setup fixture)
# ══════════════════════════════════════════════════════════════════════════════

class TestFindingPayloadAdversarial:
    """POST /api/admin/findings adversarial tests."""

    def test_report_id_not_uuid(self, client, report_setup):
        """report_id with invalid UUID format."""
        r = client.post(
            "/api/admin/findings",
            json={"report_id": "not-a-uuid", "content": {}}
        )
        assert r.status_code == 422

    def test_report_id_empty_string(self, client, report_setup):
        """report_id as empty string."""
        r = client.post(
            "/api/admin/findings",
            json={"report_id": "", "content": {}}
        )
        assert r.status_code == 422

    def test_report_id_null(self, client, report_setup):
        """report_id as null."""
        r = client.post(
            "/api/admin/findings",
            json={"report_id": None, "content": {}}
        )
        assert r.status_code == 422

    def test_missing_report_id(self, client, report_setup):
        """Missing report_id field."""
        r = client.post(
            "/api/admin/findings",
            json={"content": {}}
        )
        assert r.status_code == 422

    def test_content_array(self, client, report_setup):
        """content as array instead of dict."""
        r = client.post(
            "/api/admin/findings",
            json={"report_id": DUMMY_UUID, "content": []}
        )
        assert r.status_code == 422

    def test_content_string(self, client, report_setup):
        """content as string instead of dict."""
        r = client.post(
            "/api/admin/findings",
            json={"report_id": DUMMY_UUID, "content": "string"}
        )
        assert r.status_code == 422

    def test_content_null(self, client, report_setup):
        """content as null."""
        r = client.post(
            "/api/admin/findings",
            json={"report_id": DUMMY_UUID, "content": None}
        )
        assert r.status_code == 422

    def test_missing_content(self, client, report_setup):
        """Missing content field."""
        r = client.post(
            "/api/admin/findings",
            json={"report_id": DUMMY_UUID}
        )
        assert r.status_code == 422

    def test_content_nested_dict(self, client, report_setup):
        """content with nested dict (should be flat)."""
        r = client.post(
            "/api/admin/findings",
            json={"report_id": DUMMY_UUID, "content": {"k": {"a": "b"}}}
        )
        assert r.status_code == 422

    def test_content_array_value(self, client, report_setup):
        """content with array value (should be string only)."""
        r = client.post(
            "/api/admin/findings",
            json={"report_id": DUMMY_UUID, "content": {"k": [1, 2]}}
        )
        assert r.status_code == 422

    def test_content_integer_value(self, client, report_setup):
        """content with integer value (should be string only)."""
        r = client.post(
            "/api/admin/findings",
            json={"report_id": DUMMY_UUID, "content": {"k": 123}}
        )
        assert r.status_code == 422


class TestFindingUpdateAdversarial:
    """PUT /api/admin/findings/{finding_id} adversarial tests."""

    def test_content_json_invalid_json(self, client, report_setup):
        """content_json with invalid JSON string."""
        r = client.put(
            f"/api/admin/findings/{DUMMY_UUID}",
            json={"content_json": "not valid json"}
        )
        assert r.status_code == 422

    def test_content_json_nested_object(self, client, report_setup):
        """content_json with nested object (should be flat)."""
        r = client.put(
            f"/api/admin/findings/{DUMMY_UUID}",
            json={"content_json": '{"a": {"b": "c"}}'}
        )
        assert r.status_code == 422

    def test_content_json_non_string_value(self, client, report_setup):
        """content_json with non-string value."""
        r = client.put(
            f"/api/admin/findings/{DUMMY_UUID}",
            json={"content_json": '{"key": 123}'}
        )
        assert r.status_code == 422

    def test_content_json_not_a_dict(self, client, report_setup):
        """content_json as JSON array instead of dict."""
        r = client.put(
            f"/api/admin/findings/{DUMMY_UUID}",
            json={"content_json": '["a","b"]'}
        )
        assert r.status_code == 422

    def test_title_too_long(self, client, report_setup):
        """title longer than 500 chars."""
        long_title = "T" * 501
        r = client.put(
            f"/api/admin/findings/{DUMMY_UUID}",
            json={"title": long_title}
        )
        assert r.status_code == 422


# ══════════════════════════════════════════════════════════════════════════════
# Group 3: Resource Names (Team, Report, Application)
# ══════════════════════════════════════════════════════════════════════════════

class TestTeamAdversarial:
    """POST /api/admin/clients adversarial tests."""

    def test_name_null(self, client):
        """name as null."""
        r = client.post("/api/admin/clients", json={"name": None})
        assert r.status_code == 422

    def test_missing_name(self, client):
        """Missing name field."""
        r = client.post("/api/admin/clients", json={})
        assert r.status_code == 422

    def test_name_empty_string(self, client):
        """
        name as empty string.
        Edge case: sanitize_string allows empty (length 0 < 255), but the route
        handler guards with `if not name`, raising 400.
        """
        r = client.post("/api/admin/clients", json={"name": ""})
        assert r.status_code == 400

    def test_name_whitespace_only(self, client):
        """name with only whitespace (stripped to empty)."""
        r = client.post("/api/admin/clients", json={"name": "   "})
        assert r.status_code == 400

    def test_name_too_long(self, client):
        """name longer than 255 chars."""
        long_name = "A" * 256
        r = client.post("/api/admin/clients", json={"name": long_name})
        assert r.status_code == 422


class TestReportPayloadAdversarial:
    """POST /api/admin/reports adversarial tests."""

    def test_name_null(self, client):
        """name as null."""
        r = client.post("/api/admin/reports", json={"name": None})
        assert r.status_code == 422

    def test_missing_name(self, client):
        """Missing name field."""
        r = client.post("/api/admin/reports", json={})
        assert r.status_code == 422

    def test_name_empty_string(self, client):
        """
        name as empty string.
        Edge case: sanitize_string allows empty, but route handler guards with `if not name`.
        """
        r = client.post("/api/admin/reports", json={"name": ""})
        assert r.status_code == 400

    def test_client_id_not_uuid(self, client):
        """client_id with invalid UUID format."""
        r = client.post(
            "/api/admin/reports",
            json={"name": "R", "client_id": "not-a-uuid"}
        )
        assert r.status_code == 422

    def test_client_id_empty_string(self, client):
        """client_id as empty string."""
        r = client.post(
            "/api/admin/reports",
            json={"name": "R", "client_id": ""}
        )
        assert r.status_code == 422

    def test_application_id_not_uuid(self, client):
        """application_id with invalid UUID format."""
        r = client.post(
            "/api/admin/reports",
            json={"name": "R", "application_id": "not-uuid"}
        )
        assert r.status_code == 422


class TestApplicationAdversarial:
    """POST /api/admin/applications adversarial tests."""

    def test_name_null(self, client):
        """name as null."""
        r = client.post("/api/admin/applications", json={"name": None})
        assert r.status_code == 422

    def test_missing_name(self, client):
        """Missing name field."""
        r = client.post("/api/admin/applications", json={})
        assert r.status_code == 422

    def test_type_invalid(self, client):
        """type with invalid value (not in allowed list)."""
        r = client.post(
            "/api/admin/applications",
            json={"name": "App", "type": "invalid-type"}
        )
        assert r.status_code == 422

    def test_type_null_is_valid(self, client):
        """
        type as null.
        Edge case: validator returns None for null, which is valid (optional field).
        """
        r = client.post(
            "/api/admin/applications",
            json={"name": "App", "type": None}
        )
        assert r.status_code == 200

    def test_type_empty_string_is_null(self, client):
        """
        type as empty string.
        Edge case: validator does `return v or None`, so empty string becomes None.
        """
        r = client.post(
            "/api/admin/applications",
            json={"name": "App", "type": ""}
        )
        assert r.status_code == 200

    def test_type_case_insensitive(self, client):
        """type value is case-insensitive (validator lowercases)."""
        r = client.post(
            "/api/admin/applications",
            json={"name": "App", "type": "WEB"}
        )
        assert r.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# Group 4: Generate Endpoints
# ══════════════════════════════════════════════════════════════════════════════

class TestGenerateEndpointsAdversarial:
    """POST /api/generate/structured adversarial tests."""

    def test_notes_null(self, client):
        """notes as null (required field)."""
        r = client.post(
            "/api/generate/structured",
            json={"notes": None, "template": "t"}
        )
        assert r.status_code == 422

    def test_template_missing(self, client):
        """Missing template field."""
        r = client.post(
            "/api/generate/structured",
            json={"notes": "n"}
        )
        assert r.status_code == 422

    def test_severity_override_invalid(self, client):
        """severity_override with invalid value."""
        r = client.post(
            "/api/generate/structured",
            json={"notes": "n", "template": "t", "severity_override": "super"}
        )
        assert r.status_code == 422

    def test_llm_provider_invalid(self, client):
        """llm_provider with invalid value."""
        r = client.post(
            "/api/generate/structured",
            json={"notes": "n", "template": "t", "llm_provider": "made-up"}
        )
        assert r.status_code == 422

    def test_llm_timeout_too_low(self, client):
        """llm_timeout below minimum (10 seconds)."""
        r = client.post(
            "/api/generate/structured",
            json={"notes": "n", "template": "t", "llm_timeout": 5}
        )
        assert r.status_code == 422

    def test_llm_timeout_too_high(self, client):
        """llm_timeout above maximum (600 seconds)."""
        r = client.post(
            "/api/generate/structured",
            json={"notes": "n", "template": "t", "llm_timeout": 700}
        )
        assert r.status_code == 422

    def test_llm_timeout_boundary_low(self, client):
        """
        llm_timeout at boundary (10 seconds, valid).
        Edge case: When valid timeout but no LLM configured, _require_llm_config raises 400.
        """
        r = client.post(
            "/api/generate/structured",
            json={"notes": "n", "template": "t", "llm_timeout": 10}
        )
        # Will be 400 from _require_llm_config, not from Pydantic
        assert r.status_code != 200

    def test_llm_timeout_boundary_high(self, client):
        """
        llm_timeout at boundary (600 seconds, valid).
        Edge case: When valid timeout but no LLM configured, _require_llm_config raises 400.
        """
        r = client.post(
            "/api/generate/structured",
            json={"notes": "n", "template": "t", "llm_timeout": 600}
        )
        # Will be 400 from _require_llm_config, not from Pydantic
        assert r.status_code != 200

    def test_self_check_rounds_zero(self, client):
        """self_check_rounds at 0 (below minimum of 1)."""
        r = client.post(
            "/api/generate/structured",
            json={"notes": "n", "template": "t", "self_check_rounds": 0}
        )
        assert r.status_code == 422

    def test_self_check_rounds_too_high(self, client):
        """self_check_rounds above maximum (5)."""
        r = client.post(
            "/api/generate/structured",
            json={"notes": "n", "template": "t", "self_check_rounds": 10}
        )
        assert r.status_code == 422

    def test_llm_base_url_ftp(self, client):
        """llm_base_url with invalid scheme (ftp://)."""
        r = client.post(
            "/api/generate/structured",
            json={"notes": "n", "template": "t", "llm_base_url": "ftp://x"}
        )
        assert r.status_code == 422

    def test_notes_too_long(self, client):
        """notes longer than 50000 chars."""
        long_notes = "A" * 50001
        r = client.post(
            "/api/generate/structured",
            json={"notes": long_notes, "template": "t"}
        )
        assert r.status_code == 422


# ══════════════════════════════════════════════════════════════════════════════
# Group 5: Organization Member Roles (requires org_setup fixture)
# ══════════════════════════════════════════════════════════════════════════════

class TestOrgMemberRoleAdversarial:
    """POST /api/orgs/{org_id}/members and PUT .../role adversarial tests."""

    @pytest.mark.parametrize("role,expected", [
        ("admin", 422),      # system role, not org role
        ("superuser", 422),  # system role, not org role
        ("user", 422),       # system role, not org role
        ("", 422),           # empty string
        (None, 422),         # null
    ])
    def test_add_member_invalid_role_parametrized(self, client, org_setup, role, expected):
        """Add member with invalid role (parametrized)."""
        r = client.post(
            f"/api/orgs/{org_setup['org_id']}/members",
            json={"user_email": "a@b.com", "role": role}
        )
        assert r.status_code == expected

    def test_add_member_missing_role(self, client, org_setup):
        """Add member without role field."""
        r = client.post(
            f"/api/orgs/{org_setup['org_id']}/members",
            json={"user_email": "a@b.com"}
        )
        assert r.status_code == 422

    def test_add_member_missing_email(self, client, org_setup):
        """Add member without email field."""
        r = client.post(
            f"/api/orgs/{org_setup['org_id']}/members",
            json={"role": "consultant"}
        )
        assert r.status_code == 422

    def test_add_member_invalid_email(self, client, org_setup):
        """Add member with invalid email format."""
        r = client.post(
            f"/api/orgs/{org_setup['org_id']}/members",
            json={"user_email": "not-an-email", "role": "consultant"}
        )
        assert r.status_code == 422

    @pytest.mark.parametrize("role,expected", [
        ("admin", 422),
        ("superuser", 422),
        ("user", 422),
        ("", 422),
        (None, 422),
    ])
    def test_update_role_invalid_parametrized(self, client, org_setup, role, expected):
        """Update member role with invalid role (parametrized)."""
        # Create a valid member first to get their user_id
        client.post(
            f"/api/orgs/{org_setup['org_id']}/members",
            json={"user_email": "valid@b.com", "role": "consultant"}
        )

        # Get the member list to find the user_id
        members = client.get(f"/api/orgs/{org_setup['org_id']}/members")
        assert members.status_code == 200
        members_list = members.json()
        valid_user_id = None
        for member in members_list:
            if member["email"] == "valid@b.com":
                valid_user_id = member["user_id"]
                break

        # Use the valid user_id for the role update test
        r = client.put(
            f"/api/orgs/{org_setup['org_id']}/members/{valid_user_id}/role",
            json={"role": role}
        )
        assert r.status_code == expected
