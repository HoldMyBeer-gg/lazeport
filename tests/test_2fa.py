"""
Tests for 2FA (Two-Factor Authentication) functionality.

Tests include:
- TOTP generation and verification
- Backup code generation, hashing, and consumption
- 2FA enrollment flow
- 2FA login verification
- Policy enforcement
- RBAC for 2FA endpoints
"""

import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db import get_adapter, models
from app.services import twofa
from app.services.auth import hash_password, get_current_user
from app.db.sql_adapter import SQLAdapter


def _make_client_as(user):
    """Return a TestClient that authenticates as the given user."""
    app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app)


@pytest.fixture(autouse=True)
def cleanup_overrides():
    """Reset dependency overrides after each test."""
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def adapter():
    """Get the default adapter."""
    return get_adapter()


@pytest.fixture
def system_admin(adapter):
    """Create a system admin user."""
    user = adapter.upsert_user(
        email="admin@local.domain",
        name="System Admin",
        provider="local",
        role="admin"
    )
    adapter.set_user_password_hash(user.id, hash_password("admin_password_123"))
    return user


@pytest.fixture
def org_with_users(adapter):
    """Create an organization with multiple users."""
    org = adapter.create_organization("Test Org", "test-org")
    
    admin_user = adapter.upsert_user(
        email="orgadmin@test.com",
        name="Org Admin",
        provider="local",
        role="user"
    )
    adapter.set_user_password_hash(admin_user.id, hash_password("password123"))
    adapter.create_organization_member(org.id, admin_user.id, "org_admin")
    
    regular_user = adapter.upsert_user(
        email="user@test.com",
        name="Regular User",
        provider="local",
        role="user"
    )
    adapter.set_user_password_hash(regular_user.id, hash_password("password123"))
    adapter.create_organization_member(org.id, regular_user.id, "consultant")
    
    return org, admin_user, regular_user


class TestTOTPFunctions:
    """Test TOTP (Time-based One-Time Password) functions."""
    
    def test_generate_secret(self):
        """Test secret generation."""
        secret = twofa.generate_secret()
        assert isinstance(secret, str)
        assert len(secret) >= 16
        
        secret2 = twofa.generate_secret()
        assert secret != secret2
    
    def test_get_provisioning_uri(self):
        """Test provisioning URI generation."""
        secret = twofa.generate_secret()
        uri = twofa.get_provisioning_uri(secret, "test@example.com")
        
        assert uri.startswith("otpauth://totp/")
        assert "test%40example.com" in uri or "test@example.com" in uri
        assert secret in uri
        assert "Laze" in uri and "Report" in uri
    
    def test_generate_qr_code(self):
        """Test QR code generation."""
        secret = twofa.generate_secret()
        uri = twofa.get_provisioning_uri(secret, "test@example.com")
        qr_code = twofa.generate_qr_code(uri)
        
        assert qr_code.startswith("data:image/png;base64,")
        assert len(qr_code) > 100
    
    def test_verify_token_valid(self):
        """Test TOTP token verification with valid token."""
        import pyotp
        
        secret = twofa.generate_secret()
        totp = pyotp.TOTP(secret)
        valid_token = totp.now()
        
        assert twofa.verify_token(secret, valid_token) is True
    
    def test_verify_token_invalid(self):
        """Test TOTP token verification with invalid token."""
        secret = twofa.generate_secret()
        
        assert twofa.verify_token(secret, "000000") is False
        assert twofa.verify_token(secret, "invalid") is False
        assert twofa.verify_token(secret, "") is False
    
    def test_verify_token_with_spaces(self):
        """Test TOTP token verification handles formatting."""
        import pyotp
        
        secret = twofa.generate_secret()
        totp = pyotp.TOTP(secret)
        valid_token = totp.now()
        
        assert twofa.verify_token(secret, f" {valid_token} ") is True
        assert twofa.verify_token(secret, f"{valid_token[:3]} {valid_token[3:]}") is True


class TestBackupCodes:
    """Test backup code functions."""
    
    def test_generate_backup_codes(self):
        """Test backup code generation."""
        codes = twofa.generate_backup_codes()
        
        assert len(codes) == 10
        for code in codes:
            assert isinstance(code, str)
            assert "-" in code
            assert len(code) == 9  # XXXX-XXXX
    
    def test_backup_codes_unique(self):
        """Test that generated codes are unique."""
        codes = twofa.generate_backup_codes()
        assert len(codes) == len(set(codes))
    
    def test_hash_backup_code(self):
        """Test backup code hashing."""
        code = "ABCD-1234"
        hashed = twofa.hash_backup_code(code)
        
        assert hashed.startswith("pbkdf2_sha256$")
        assert hashed != code
    
    def test_verify_backup_code_valid(self):
        """Test backup code verification with valid code."""
        codes = twofa.generate_backup_codes()
        hashed_codes = [twofa.hash_backup_code(c) for c in codes]
        hashed_json = json.dumps(hashed_codes)
        
        is_valid, updated_json = twofa.verify_backup_code(codes[0], hashed_json)
        
        assert is_valid is True
        updated_codes = json.loads(updated_json)
        assert len(updated_codes) == 9
    
    def test_verify_backup_code_invalid(self):
        """Test backup code verification with invalid code."""
        codes = twofa.generate_backup_codes()
        hashed_codes = [twofa.hash_backup_code(c) for c in codes]
        hashed_json = json.dumps(hashed_codes)
        
        is_valid, updated_json = twofa.verify_backup_code("INVALID-CODE", hashed_json)
        
        assert is_valid is False
        assert updated_json == hashed_json
    
    def test_verify_backup_code_single_use(self):
        """Test that backup codes are single-use."""
        codes = twofa.generate_backup_codes()
        hashed_codes = [twofa.hash_backup_code(c) for c in codes]
        hashed_json = json.dumps(hashed_codes)
        
        is_valid1, updated_json1 = twofa.verify_backup_code(codes[0], hashed_json)
        assert is_valid1 is True
        
        is_valid2, updated_json2 = twofa.verify_backup_code(codes[0], updated_json1)
        assert is_valid2 is False


class TestPolicyEnforcement:
    """Test 2FA policy enforcement."""
    
    def test_check_2fa_not_required_disabled_policy(self, adapter, org_with_users):
        """Test 2FA not required when policy is disabled."""
        org, _, user = org_with_users
        
        assert twofa.check_2fa_required(user, adapter) is False
    
    def test_check_2fa_not_required_optional_policy_not_enrolled(self, adapter, org_with_users):
        """Test 2FA not required for optional policy when not enrolled."""
        org, _, user = org_with_users
        
        org_settings = {"twofa_policy": "optional"}
        with adapter._session() as session:
            db_org = session.get(models.Organization, org.id)
            db_org.settings = json.dumps(org_settings)
            session.commit()
        
        assert twofa.check_2fa_required(user, adapter) is False
    
    def test_check_2fa_required_mandatory_policy(self, adapter, org_with_users):
        """Test 2FA required for mandatory policy."""
        org, _, user = org_with_users
        
        org_settings = {"twofa_policy": "mandatory"}
        with adapter._session() as session:
            db_org = session.get(models.Organization, org.id)
            db_org.settings = json.dumps(org_settings)
            session.commit()
        
        assert twofa.check_2fa_required(user, adapter) is True
    
    def test_check_2fa_required_when_enabled(self, adapter, org_with_users):
        """Test 2FA required when user has it enabled."""
        org, _, user = org_with_users
        
        with adapter._session() as session:
            db_user = session.get(models.User, user.id)
            db_user.twofa_enabled = True
            session.commit()
        
        user = adapter.get_user_by_id(user.id)
        assert twofa.check_2fa_required(user, adapter) is True


class TestEncryption:
    """Test secret encryption/decryption."""
    
    def test_encrypt_decrypt_secret(self):
        """Test that secrets can be encrypted and decrypted."""
        original_secret = twofa.generate_secret()
        
        encrypted = twofa.encrypt_secret(original_secret)
        assert encrypted != original_secret
        
        decrypted = twofa.decrypt_secret(encrypted)
        assert decrypted == original_secret
    
    def test_decrypt_empty_secret(self):
        """Test decrypting empty secret."""
        assert twofa.decrypt_secret("") == ""


class Test2FAWorkflow:
    """Test complete 2FA workflow using service functions."""
    
    def test_full_enrollment_workflow(self, adapter):
        """Test complete 2FA enrollment workflow."""
        user = adapter.upsert_user(email="test@test.com", name="Test", provider="local", role="user")
        
        secret = twofa.generate_secret()
        encrypted_secret = twofa.encrypt_secret(secret)
        
        backup_codes = twofa.generate_backup_codes()
        hashed_codes = [twofa.hash_backup_code(c) for c in backup_codes]
        
        with adapter._session() as session:
            db_user = session.get(models.User, user.id)
            db_user.twofa_secret = encrypted_secret
            db_user.twofa_enabled = True
            db_user.twofa_backup_codes = json.dumps(hashed_codes)
            session.commit()
        
        user = adapter.get_user_by_id(user.id)
        assert user.twofa_enabled is True
        
        decrypted = twofa.decrypt_secret(user.twofa_secret)
        assert decrypted == secret
    
    def test_disable_2fa_clears_all_data(self, adapter):
        """Test disabling 2FA clears all 2FA data."""
        user = adapter.upsert_user(email="test@test.com", name="Test", provider="local", role="user")
        
        secret = twofa.generate_secret()
        encrypted_secret = twofa.encrypt_secret(secret)
        
        with adapter._session() as session:
            db_user = session.get(models.User, user.id)
            db_user.twofa_secret = encrypted_secret
            db_user.twofa_enabled = True
            db_user.twofa_backup_codes = json.dumps(["code1", "code2"])
            session.commit()
        
        with adapter._session() as session:
            db_user = session.get(models.User, user.id)
            db_user.twofa_secret = ""
            db_user.twofa_enabled = False
            db_user.twofa_backup_codes = ""
            session.commit()
        
        user = adapter.get_user_by_id(user.id)
        assert user.twofa_enabled is False
        assert user.twofa_secret == ""
        assert user.twofa_backup_codes == ""


class TestRBAC:
    """Test RBAC for 2FA endpoints."""
    
    def test_admin_can_reset_user_2fa(self, adapter, system_admin):
        """Test that system admin can reset user 2FA."""
        # Create a regular user with 2FA enabled
        user = adapter.upsert_user(email="user@test.com", name="User", provider="local", role="user")
        adapter.set_user_password_hash(user.id, hash_password("password123"))
        
        secret = twofa.generate_secret()
        encrypted_secret = twofa.encrypt_secret(secret)
        
        with adapter._session() as session:
            db_user = session.get(models.User, user.id)
            db_user.twofa_secret = encrypted_secret
            db_user.twofa_enabled = True
            db_user.twofa_backup_codes = json.dumps(["code1", "code2"])
            session.commit()
        
        # Admin resets user 2FA
        client = _make_client_as(system_admin)
        response = client.post(f"/api/admin/users/{user.id}/2fa/reset")
        
        assert response.status_code == 200
        assert response.json()["success"] is True
        
        # Verify 2FA is disabled
        user = adapter.get_user_by_id(user.id)
        assert user.twofa_enabled is False
        assert user.twofa_secret == ""
        assert user.twofa_backup_codes == ""
    
    def test_non_admin_cannot_reset_user_2fa(self, adapter):
        """Test that non-admin cannot reset user 2FA."""
        # Create a regular user
        regular_user = adapter.upsert_user(email="user@test.com", name="User", provider="local", role="user")
        
        # Create a target user with 2FA enabled
        target_user = adapter.upsert_user(email="target@test.com", name="Target", provider="local", role="user")
        
        secret = twofa.generate_secret()
        encrypted_secret = twofa.encrypt_secret(secret)
        
        with adapter._session() as session:
            db_user = session.get(models.User, target_user.id)
            db_user.twofa_secret = encrypted_secret
            db_user.twofa_enabled = True
            session.commit()
        
        # Regular user tries to reset target user's 2FA
        client = _make_client_as(regular_user)
        response = client.post(f"/api/admin/users/{target_user.id}/2fa/reset")
        
        # Should be forbidden
        assert response.status_code == 403
        
        # Verify 2FA is still enabled
        target_user = adapter.get_user_by_id(target_user.id)
        assert target_user.twofa_enabled is True
    
    def test_admin_cannot_reset_nonexistent_user_2fa(self, adapter, system_admin):
        """Test that admin gets 404 when resetting 2FA for nonexistent user."""
        client = _make_client_as(system_admin)
        response = client.post("/api/admin/users/nonexistent-id/2fa/reset")
        
        assert response.status_code == 404
    
    def test_admin_cannot_reset_2fa_for_user_without_2fa(self, adapter, system_admin):
        """Test that admin gets 400 when resetting 2FA for user without 2FA."""
        user = adapter.upsert_user(email="user@test.com", name="User", provider="local", role="user")
        
        client = _make_client_as(system_admin)
        response = client.post(f"/api/admin/users/{user.id}/2fa/reset")
        
        assert response.status_code == 400
        assert "not have 2fa enabled" in response.json()["detail"].lower()
