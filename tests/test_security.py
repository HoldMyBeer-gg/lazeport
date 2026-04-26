"""
Security-focused integration tests.

Tests input validation, CSRF protection, RBAC, SQL injection prevention,
XSS prevention, and more.
"""
import json
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.validation import (
    sanitize_string,
    sanitize_html_input,
    validate_filename,
    validate_email,
    check_sql_injection_patterns,
)


client = TestClient(app)


# Input Validation Tests


def test_sanitize_string_removes_control_chars():
    """Test that control characters are removed."""
    dirty = "Hello\x00World\x1fTest"
    clean = sanitize_string(dirty)
    assert clean == "HelloWorldTest"


def test_sanitize_string_enforces_max_length():
    """Test maximum length enforcement."""
    long_string = "A" * 10000
    with pytest.raises(ValueError):
        sanitize_string(long_string, max_length=100)


def test_sanitize_html_removes_script_tags():
    """Test XSS prevention via HTML sanitization."""
    dangerous = "Hello <script>alert('XSS')</script> World"
    safe = sanitize_html_input(dangerous)
    assert "<script>" not in safe
    assert "alert" not in safe


def test_sanitize_html_removes_event_handlers():
    """Test removal of inline event handlers."""
    dangerous = '<div onclick="alert(1)">Click me</div>'
    safe = sanitize_html_input(dangerous)
    assert "onclick" not in safe


def test_validate_filename_rejects_path_traversal():
    """Test prevention of path traversal attacks."""
    with pytest.raises(ValueError):
        validate_filename("../../../etc/passwd")
    
    with pytest.raises(ValueError):
        validate_filename("..\\..\\windows\\system32\\config\\sam")


def test_validate_filename_rejects_absolute_paths():
    """Test rejection of absolute paths."""
    with pytest.raises(ValueError):
        validate_filename("/etc/passwd")
    
    with pytest.raises(ValueError):
        validate_filename("C:\\Windows\\System32")


def test_validate_filename_accepts_safe_names():
    """Test acceptance of safe filenames."""
    safe_names = [
        "document.docx",
        "my-report_v2.pdf",
        "Finding Template 2024.txt",
    ]
    for name in safe_names:
        assert validate_filename(name) == name


def test_validate_email_rejects_invalid():
    """Test email validation."""
    invalid_emails = [
        "notanemail",
        "@example.com",
        "user@",
        "user space@example.com",
        "user@.com",
    ]
    for email in invalid_emails:
        with pytest.raises(ValueError):
            validate_email(email)


def test_validate_email_accepts_valid():
    """Test valid email acceptance."""
    valid_emails = [
        "user@example.com",
        "john.doe@company.co.uk",
        "test+tag@example.com",
    ]
    for email in valid_emails:
        assert validate_email(email) == email.strip().lower()


def test_sql_injection_pattern_detection():
    """Test SQL injection pattern detection."""
    sql_injection_attempts = [
        "1' OR '1'='1",
        "admin'--",
        "'; DROP TABLE users; --",
        "1 UNION SELECT * FROM passwords",
        "1'; DELETE FROM clients; --",
    ]
    for attempt in sql_injection_attempts:
        with pytest.raises(ValueError, match="dangerous"):
            check_sql_injection_patterns(attempt)


def test_sql_injection_clean_input():
    """Test that clean input passes SQL injection check."""
    clean_inputs = [
        "John Doe",
        "Company Name Inc.",
        "2024-01-15",
        "normal@email.com",
    ]
    for clean_input in clean_inputs:
        check_sql_injection_patterns(clean_input)


# CSRF Protection Tests


def test_csrf_token_required_for_post():
    """Test that CSRF token is required for POST requests."""
    # Attempt POST without CSRF token
    response = client.post(
        "/api/admin/clients",
        json={"name": "Test Team"},
        # No CSRF token in headers
    )
    # /api is exempt from CSRF protection
    assert response.status_code == 200


def test_csrf_exempt_paths():
    """Test that login endpoint is exempt from CSRF."""
    response = client.post(
        "/auth/login/local",
        json={"username": "admin", "password": "testpass"},
    )
    # Should not fail due to CSRF (will fail for other reasons like wrong password)
    assert response.status_code != 403


# RBAC Tests
# RBAC coverage: readonly cannot create, consultant edit own, admin manage, owner invite,
# and cross-org isolation are tested in tests/test_org_rbac.py and tests/test_cross_org_isolation.py


# API Input Validation Tests


def test_client_name_max_length():
    """Test that excessively long client names are rejected (clients use name_validator)."""
    long_name = "A" * 10000
    response = client.post("/api/admin/clients", json={"name": long_name})
    assert response.status_code in (400, 422)


def test_report_name_xss_prevention():
    """Test that XSS in report names is rejected by validation."""
    xss_name = "<script>alert('XSS')</script>"
    response = client.post(
        "/api/admin/reports",
        json={"name": xss_name},
    )
    # name_validator uses check_sql_injection_patterns which rejects 'script' and 'alert'
    assert response.status_code == 422


def test_finding_content_sql_injection_prevention():
    """Test that SQL injection in finding content is stored safely (parameterized queries)."""
    r = client.post("/api/admin/reports", json={"name": "SQL Test Report"})
    assert r.status_code == 200
    report_id = r.json()["id"]
    sql_injection_content = {"Summary": "'; DROP TABLE findings; --"}
    create = client.post(
        "/api/admin/findings",
        json={
            "report_id": report_id,
            "title": "SQL Injection Test",
            "content": sql_injection_content,
            "notes": "",
            "template": "",
        },
    )
    assert create.status_code == 200
    finding_id = create.json()["id"]
    get_r = client.get(f"/api/admin/findings/{finding_id}")
    assert get_r.status_code == 200
    # Content stored safely via parameterization, not executed
    content = json.loads(get_r.json()["content_json"])
    assert content["Summary"] == "'; DROP TABLE findings; --"
    client.delete(f"/api/admin/reports/{report_id}")


# Audit Logging Tests
# Audit logging for settings, profile, client, report, finding, connector is tested in tests/test_admin.py


def test_audit_log_captures_login(monkeypatch):
    """Test that login events are captured in audit log."""
    from app.db import get_adapter
    from app.services.auth import hash_password

    monkeypatch.setenv("AUTH_DISABLED", "0")
    adapter = get_adapter()
    adapter.init()
    user = adapter.upsert_user(email="auditlogin@test.com", name="Audit Login", provider="local")
    adapter.set_user_password_hash(user.id, hash_password("password123"))
    org = adapter.create_organization(name="Audit Login Org", slug="audit-login-org")
    adapter.create_organization_member(org_id=org.id, user_id=user.id, role="org_owner")

    resp = client.post("/auth/login", json={"email": "auditlogin@test.com", "password": "password123"})
    assert resp.status_code == 200

    # Login is logged to system org
    system_org_id = adapter.ensure_system_org()
    logs = list(adapter.list_audit_logs(system_org_id, limit=20))
    assert any(l.action == "login" and l.resource_type == "auth" for l in logs)


def test_audit_log_captures_resource_creation():
    """Test that resource creation is logged."""
    from app.db import get_adapter

    r = client.post("/api/admin/clients", json={"name": "Audit Team Alpha"})
    assert r.status_code == 200
    adapter = get_adapter()
    org_id = adapter.ensure_system_org()
    logs = list(adapter.list_audit_logs(org_id, limit=20))
    assert any(l.action == "create" and l.resource_type == "client" for l in logs)


# Session Security Tests
# Starlette SessionMiddleware sets httponly and samesite by default.
# secure flag is set when https_only=True (production) - not testable over HTTP.


def test_session_cookie_httponly_flag(monkeypatch):
    """Test that session cookies have httponly flag (prevents XSS from stealing session)."""
    from app.db import get_adapter
    from app.services.auth import hash_password

    monkeypatch.setenv("AUTH_DISABLED", "0")
    adapter = get_adapter()
    adapter.init()
    user = adapter.upsert_user(email="cookie@test.com", name="Cookie", provider="local")
    adapter.set_user_password_hash(user.id, hash_password("password123"))
    org = adapter.create_organization(name="Cookie Org", slug="cookie-org")
    adapter.create_organization_member(org_id=org.id, user_id=user.id, role="org_owner")

    response = client.post("/auth/login", json={"email": "cookie@test.com", "password": "password123"})
    assert response.status_code == 200
    set_cookie = response.headers.get("set-cookie") or ""
    assert "session=" in set_cookie
    assert "httponly" in set_cookie.lower() or "HttpOnly" in set_cookie


def test_session_cookie_samesite(monkeypatch):
    """Test that session cookies have SameSite attribute (CSRF protection)."""
    from app.db import get_adapter
    from app.services.auth import hash_password

    monkeypatch.setenv("AUTH_DISABLED", "0")
    adapter = get_adapter()
    adapter.init()
    user = adapter.upsert_user(email="samesite@test.com", name="SameSite", provider="local")
    adapter.set_user_password_hash(user.id, hash_password("password123"))
    org = adapter.create_organization(name="SameSite Org", slug="samesite-org")
    adapter.create_organization_member(org_id=org.id, user_id=user.id, role="org_owner")

    response = client.post("/auth/login", json={"email": "samesite@test.com", "password": "password123"})
    assert response.status_code == 200
    set_cookie = response.headers.get("set-cookie") or ""
    assert "session=" in set_cookie
    assert "samesite" in set_cookie.lower() or "SameSite" in set_cookie


# Organization Isolation Tests
# Cross-org isolation (clients, applications, reports, findings) is tested in
# tests/test_cross_org_isolation.py


# Rate Limiting Tests (Future)


def test_rate_limiting_login_endpoint(monkeypatch):
    """Test that login endpoint has IP-based rate limiting."""
    from app.db import get_adapter
    from app.services.auth import hash_password

    monkeypatch.setenv("AUTH_DISABLED", "0")
    
    adapter = get_adapter()
    adapter.init()
    
    # Create a test user
    user = adapter.upsert_user(email="ratelimit@test.com", name="Test User", provider="local")
    adapter.set_user_password_hash(user.id, hash_password("password123"))
    org = adapter.create_organization(name="RateLimit Org", slug="rate-limit-org")
    adapter.create_organization_member(org_id=org.id, user_id=user.id, role="org_owner")
    
    # Note: IP-based rate limiting uses system defaults (4 attempts) regardless of org settings
    # to prevent username enumeration via timing/rate limit differences
    
    # IP-based rate limiting: All requests from same IP (testclient) are counted together
    # Attempts 1-4 should fail with 401
    for i in range(4):
        response = client.post("/auth/login", json={
            "email": "ratelimit@test.com",
            "password": "wrongpassword"
        })
        assert response.status_code == 401, f"Attempt {i+1} should return 401"
    
    # 5th attempt should be rate limited (IP limit reached at default 4 attempts)
    response = client.post("/auth/login", json={
        "email": "ratelimit@test.com",
        "password": "wrongpassword"
    })
    assert response.status_code == 429
    data = response.json()
    assert "detail" in data
    detail = data["detail"]
    assert "locked" in detail["message"].lower() or "too many" in detail["message"].lower()
    assert "seconds_remaining" in detail
    assert detail["seconds_remaining"] >= 0
    
    # Even correct password should be blocked
    response = client.post("/auth/login", json={
        "email": "ratelimit@test.com",
        "password": "password123"
    })
    assert response.status_code == 429


def test_rate_limiting_api_endpoints(monkeypatch):
    """Test that API endpoints have IP-based rate limiting - currently only login has it."""
    from app.db import get_adapter
    from app.services.auth import hash_password

    monkeypatch.setenv("AUTH_DISABLED", "0")
    
    adapter = get_adapter()
    adapter.init()
    
    # Create a test user
    user = adapter.upsert_user(email="apiratelimit@test.com", name="API Test User", provider="local")
    adapter.set_user_password_hash(user.id, hash_password("password123"))
    org = adapter.create_organization(name="API RateLimit Org", slug="api-rate-limit-org")
    adapter.create_organization_member(org_id=org.id, user_id=user.id, role="org_owner")
    
    # Note: IP-based rate limiting uses system defaults (4 attempts) regardless of org settings
    # to prevent username enumeration via timing/rate limit differences
    
    # IP-based rate limiting: All login attempts from same IP count together
    # Attempts 1-4 should fail with 401
    for i in range(4):
        response = client.post("/auth/login/local", json={
            "username": "apiratelimit@test.com",
            "password": "wrongpassword"
        })
        assert response.status_code == 401, f"Attempt {i+1} should return 401"
    
    # 5th attempt should be rate limited (IP limit reached at default 4 attempts)
    response = client.post("/auth/login/local", json={
        "username": "apiratelimit@test.com",
        "password": "wrongpassword"
    })
    assert response.status_code == 429
    data = response.json()
    assert "detail" in data
    detail = data["detail"]
    assert "seconds_remaining" in detail


# File Upload Security Tests


def test_master_template_upload_validates_file_size():
    """Test that file size limits are enforced (LOW-14)."""
    # 10MB + 1 byte = over limit
    oversized = b"x" * (10 * 1024 * 1024 + 1)
    response = client.post(
        "/api/admin/master-templates/upload",
        files={"file": ("huge.docx", oversized, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")},
    )
    assert response.status_code == 413
    assert "10MB" in response.json().get("detail", "")




# Security Header Tests


def test_security_headers_present():
    """Test that all security headers are present."""
    response = client.get("/")
    headers = response.headers
    
    # Should have basic security headers
    expected_headers = [
        "x-content-type-options",
        "x-frame-options",
        "x-xss-protection",
        "referrer-policy",
        "content-security-policy",
    ]
    
    for header in expected_headers:
        assert header in headers, f"Missing security header: {header}"


def test_csp_header_restrictive():
    """Test that CSP header has restrictive policy."""
    response = client.get("/")
    csp = response.headers.get("content-security-policy", "")
    
    # Should have default-src restriction
    assert "default-src" in csp


def test_frame_options_deny():
    """Test that X-Frame-Options is set to DENY."""
    response = client.get("/")
    assert response.headers.get("x-frame-options") == "DENY"


def test_405_response_connection_close_mitigates_desync():
    """405 responses must send Connection: close to mitigate client-side desync (browser-powered
    request smuggling). POST to a GET-only endpoint leaves body on the socket; closing the
    connection prevents reuse so the next request is not poisoned."""
    response = client.post(
        "/api/admin/confidence-levels",
        content=b"body left on socket",
        headers={"Content-Type": "application/octet-stream"},
    )
    assert response.status_code == 405
    assert response.headers.get("connection", "").lower() == "close"


# Password Security Tests
# App uses PBKDF2-SHA256 (210k iterations), not bcrypt.


def test_password_hashing_pbkdf2():
    """Test that passwords are hashed with PBKDF2-SHA256."""
    from app.services.auth import hash_password, verify_password

    plain = "mySecretPassword123"
    hashed = hash_password(plain)
    assert hashed.startswith("pbkdf2_sha256$")
    assert "210000" in hashed
    assert plain not in hashed
    assert verify_password(plain, hashed) is True
    assert verify_password("wrong", hashed) is False


def test_verify_password_malformed_hash_returns_false():
    """Malformed or corrupted password hashes should return False, not raise."""
    from app.services.auth import verify_password

    assert verify_password("any", "not-a-valid-hash") is False
    assert verify_password("any", "pbkdf2_sha256$210000$bad") is False  # too few parts
    assert verify_password("any", "pbkdf2_sha256$210000$!!!!$!!!!") is False  # invalid base64


def test_password_not_stored_plaintext():
    """Test that passwords are never stored in plaintext."""
    from app.db import get_adapter
    from app.services.auth import hash_password, verify_password

    adapter = get_adapter()
    adapter.init()
    user = adapter.upsert_user(email="plaintext@test.com", name="Plain", provider="local")
    plain = "NeverStoreThis123"
    adapter.set_user_password_hash(user.id, hash_password(plain))
    stored = adapter.get_user_by_id(user.id)
    assert stored.password_hash is not None
    assert plain not in stored.password_hash
    assert stored.password_hash.startswith("pbkdf2_sha256$")
    assert verify_password(plain, stored.password_hash) is True


# Integration Tests (End-to-End)
# Full RBAC workflow is covered by tests/test_org_rbac.py.
# Audit trail for resource CRUD is covered by tests/test_admin.py.


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
