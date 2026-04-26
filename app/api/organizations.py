"""
Organization and user management API endpoints.

Handles organization CRUD, member management, role assignment,
and audit log viewing.
"""
import json
import logging
import secrets
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, field_validator

log = logging.getLogger(__name__)

from app.db import get_adapter
from app.db.adapter import StorageAdapter
from app.db.models import SYSTEM_ORG_ID
from app.services.auth import get_current_user, require_system_admin
from app.services.rbac import require_owner, require_org_role
from app.services.audit import log_create, log_update, log_delete
from app.services.email import send_org_email
from app.validation import ValidatedString
from app.db import models
from app.services.crypto import encrypt_text
from app.services.auth import hash_invite_token
from app.config import settings

router = APIRouter()


# ── Pydantic Models ──

class OrganizationPayload(BaseModel):
    name: str
    slug: str

    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        return ValidatedString.name_validator(v)

    @field_validator('slug')
    @classmethod
    def validate_slug(cls, v):
        v = str(v).strip().lower()
        if not v or len(v) > 50:
            raise ValueError("Slug must be 1-50 characters")
        if not v.replace('-', '').replace('_', '').isalnum():
            raise ValueError("Slug must be alphanumeric with hyphens/underscores")
        return v


class OrganizationMemberPayload(BaseModel):
    user_email: str
    role: str

    @field_validator('user_email')
    @classmethod
    def validate_email(cls, v):
        return ValidatedString.email_validator(v)

    @field_validator('role')
    @classmethod
    def validate_role(cls, v):
        allowed = {'org_owner', 'org_admin', 'consultant', 'readonly'}
        v = str(v).strip().lower()
        if v not in allowed:
            raise ValueError(f"Role must be one of: {', '.join(allowed)}")
        return v


class RoleUpdatePayload(BaseModel):
    role: str

    @field_validator('role')
    @classmethod
    def validate_role(cls, v):
        allowed = {'org_owner', 'org_admin', 'consultant', 'readonly'}
        v = str(v).strip().lower()
        if v not in allowed:
            raise ValueError(f"Role must be one of: {', '.join(allowed)}")
        return v


class EmailSettingsPayload(BaseModel):
    host: str = ""
    port: int = 587
    username: str = ""
    password: str | None = None
    sender: str = ""
    use_tls: bool = True

    @field_validator('sender')
    @classmethod
    def validate_sender(cls, v):
        if not v:
            return ""
        return ValidatedString.email_validator(v)


class EmailTestPayload(BaseModel):
    to_email: str

    @field_validator('to_email')
    @classmethod
    def validate_email(cls, v):
        return ValidatedString.email_validator(v)


class OidcConfigPayload(BaseModel):
    provider_id: str = "okta"
    provider_label: str = "Okta"
    issuer: str = ""
    client_id: str = ""
    client_secret: str = ""

    @field_validator("provider_id", "provider_label", "issuer", "client_id")
    @classmethod
    def strip_str(cls, v):
        return str(v).strip() if v else ""

    @field_validator("issuer")
    @classmethod
    def validate_issuer(cls, v):
        v = str(v).strip()
        if not v:
            raise ValueError("Issuer URL is required")
        if len(v) > 512:
            raise ValueError("Issuer URL too long")
        return v

    @field_validator("client_id")
    @classmethod
    def validate_client_id(cls, v):
        v = str(v).strip()
        if not v:
            raise ValueError("Client ID is required")
        return v


class DomainPayload(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v):
        v = str(v).strip().lower()
        if not v:
            raise ValueError("Domain is required")
        if "@" in v:
            raise ValueError("Enter domain only (e.g. acme.com), not email")
        if len(v) > 253:
            raise ValueError("Domain too long")
        return v


def _load_org_settings(org: models.Organization) -> dict:
    if not org or not org.settings:
        return {}
    try:
        return json.loads(org.settings)
    except Exception:
        return {}


def _save_org_settings(adapter: StorageAdapter, org_id: str, settings_obj: dict) -> models.Organization | None:
    settings_json = json.dumps(settings_obj)
    return adapter.update_organization(org_id, settings=settings_json)


# ── Organizations ──

@router.get("/orgs")
def list_organizations(
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """List all organizations. System admins see all orgs, others see only their orgs."""
    if user.role == "admin":
        # System admins see all organizations
        orgs = adapter.list_organizations()
    else:
        # Regular users see only organizations they belong to
        orgs = adapter.get_user_organizations(user.id)
    
    # Strip sensitive settings field for all users (even admins in list view)
    return [
        {
            "id": org.id,
            "name": org.name,
            "slug": org.slug,
            "is_active": org.is_active,
            "created_at": org.created_at,
            "updated_at": org.updated_at,
            "max_users": org.max_users,
            "max_reports": org.max_reports,
        }
        for org in orgs
    ]


@router.get("/orgs/{org_id}")
@require_org_role("readonly", "consultant", "org_admin", "org_owner")
def get_organization(
    org_id: str,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Get organization details (without sensitive settings)."""
    org = adapter.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    # Parse settings to extract non-sensitive fields
    import json
    settings_data = {}
    try:
        if org.settings:
            parsed = json.loads(org.settings)
            # Include non-sensitive settings that UI needs
            if "twofa_policy" in parsed:
                settings_data["twofa_policy"] = parsed["twofa_policy"]
    except (json.JSONDecodeError, TypeError) as e:
        log.warning("Failed to parse org settings for org %s: %s", org.id, type(e).__name__)
    
    # Return org details with non-sensitive settings
    return {
        "id": org.id,
        "name": org.name,
        "slug": org.slug,
        "is_active": org.is_active,
        "settings": json.dumps(settings_data) if settings_data else None,
        "created_at": org.created_at,
        "updated_at": org.updated_at,
        "max_users": org.max_users,
        "max_reports": org.max_reports,
    }


@router.post("/orgs")
def create_organization(
    payload: OrganizationPayload,
    request: Request,
    user=Depends(require_system_admin),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Create a new organization (system admin only)."""
    # Check if slug already exists
    existing = adapter.get_organization_by_slug(payload.slug)
    if existing:
        raise HTTPException(status_code=400, detail="Organization slug already exists")

    org = adapter.create_organization(
        name=payload.name,
        slug=payload.slug,
        settings="{}"
    )

    # Populate severity criteria from default template
    from app.services.master_docx import parse_severity_criteria_markdown
    default_criteria = parse_severity_criteria_markdown()
    if default_criteria:
        adapter.update_organization(org.id, severity_criteria=json.dumps(default_criteria))

    # Provision factory default master template for the new org
    from app.main import _load_factory_master_template
    factory_content = _load_factory_master_template()
    if factory_content:
        adapter.create_master_template("master", factory_content, organization_id=org.id)

    # Log audit trail
    log_create(adapter, org.id, user.id, "organization", org.id, request, name=payload.name)

    return org


@router.put("/orgs/{org_id}")
@require_owner()
def update_organization(
    org_id: str,
    payload: OrganizationPayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Update organization (owner only)."""
    org = adapter.update_organization(
        org_id,
        name=payload.name,
        slug=payload.slug
    )
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    log_update(adapter, org_id, user.id, "organization", org_id, request)
    return org


@router.delete("/orgs/{org_id}")
@require_owner()
def delete_organization(
    org_id: str,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Delete organization (owner only). WARNING: Deletes all associated data!"""
    # Check if it's the system org
    if org_id == SYSTEM_ORG_ID:
        raise HTTPException(status_code=400, detail="Cannot delete System organization")

    if not adapter.delete_organization(org_id):
        raise HTTPException(status_code=404, detail="Organization not found")

    log_delete(adapter, org_id, user.id, "organization", org_id, request)
    return {"status": "deleted"}


# ── Organization Members ──

@router.get("/orgs/{org_id}/members")
def list_members(
    org_id: str,
    request: Request = None,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """List all members of an organization (system admin or org admin/owner)."""
    # Check permissions: system admin or org admin/owner
    if user.role != "admin":
        from app.services.rbac import get_user_role_in_org
        user_role = get_user_role_in_org(user.id, org_id, adapter)
        if user_role not in ("org_admin", "org_owner"):
            raise HTTPException(status_code=403, detail="Only organization admins/owners can view members")
    
    members = adapter.list_organization_members(org_id)

    user_ids = [m.user_id for m in members]
    users_by_id = adapter.get_users_by_ids(user_ids) if user_ids else {}

    result = []
    for member in members:
        user_obj = users_by_id.get(member.user_id)
        result.append({
            "user_id": member.user_id,
            "email": user_obj.email if user_obj else "",
            "name": user_obj.name if user_obj else "",
            "role": member.role,
            "joined_at": member.joined_at.isoformat() if member.joined_at else None,
        })

    return result


@router.post("/orgs/{org_id}/members")
def add_member(
    org_id: str,
    payload: OrganizationMemberPayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Add a user to the organization (system admin or org owner only)."""
    org = adapter.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    # Check permissions: system admin or org owner
    if user.role != "admin":
        from app.services.rbac import get_user_role_in_org
        user_role = get_user_role_in_org(user.id, org_id, adapter)
        if user_role != "org_owner":
            raise HTTPException(status_code=403, detail="Only organization owners can add members")

    email = payload.user_email.strip().lower()

    # Get or create user
    target_user = adapter.get_user_by_email(email)
    if not target_user:
        # Create new user
        target_user = adapter.upsert_user(
            email=email,
            name="",
            provider="local",
            role="user"
        )
        adapter.set_user_active(target_user.id, False)

    # Check if already a member
    existing = adapter.get_organization_member(org_id, target_user.id)
    if existing and target_user.is_active:
        raise HTTPException(status_code=400, detail="User is already a member")

    if not existing:
        existing = adapter.create_organization_member(
            org_id=org_id,
            user_id=target_user.id,
            role=payload.role,
            invited_by=user.id
        )

    log_create(
        adapter, org_id, user.id, "organization_member", existing.id,
        request, target_email=email, role=payload.role
    )

    token = secrets.token_urlsafe(32)
    token_hash = hash_invite_token(token)
    expires_at = datetime.utcnow() + timedelta(hours=48)
    invite = adapter.get_org_invite_by_email(org_id, email)
    if invite:
        invite = adapter.update_org_invite(
            invite.id,
            token_hash,
            expires_at,
            payload.role,
            invited_by=user.id,
            user_id=target_user.id,
        )
    else:
        invite = adapter.create_org_invite(
            org_id=org_id,
            email=email,
            role=payload.role,
            token_hash=token_hash,
            expires_at=expires_at,
            invited_by=user.id,
            user_id=target_user.id,
        )

    base_url = (settings.public_app_url or str(request.base_url)).rstrip("/")
    invite_url = f"{base_url}/invite?token={token}"
    org_name = org.name if org else "your organization"
    inviter = user.name or user.email
    subject = f"You were invited to {org_name}"
    body = (
        f"{inviter} added you to {org_name} in Lazeport.\n\n"
        f"Role: {payload.role}\n"
        f"Accept invite (valid for 48 hours):\n{invite_url}\n"
    )
    send_org_email(adapter, org_id, email, subject, body)

    return {"status": "invited", "invite_id": invite.id}


@router.put("/orgs/{org_id}/members/{user_id}/role")
@require_owner()
def update_member_role(
    org_id: str,
    user_id: str,
    payload: RoleUpdatePayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Update a member's role."""
    log.info(f"[ROLE_UPDATE] User {user.id} (role={user.role}) attempting to change user {user_id} role in org {org_id} to {payload.role}")
    
    # Prevent users from changing their own role (could lock themselves out)
    if user_id == user.id:
        raise HTTPException(status_code=400, detail="You cannot change your own role")
    
    member = adapter.update_organization_member_role(org_id, user_id, payload.role)
    if not member:
        raise HTTPException(status_code=404, detail="Member not found")

    log_update(
        adapter, org_id, user.id, "organization_member", member.id,
        request, new_role=payload.role
    )

    return member


@router.delete("/orgs/{org_id}/members/{user_id}")
def remove_member(
    org_id: str,
    user_id: str,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Remove a user from the organization (system admin or org owner only)."""
    # Check permissions: system admin or org owner
    if user.role != "admin":
        from app.services.rbac import get_user_role_in_org
        user_role = get_user_role_in_org(user.id, org_id, adapter)
        if user_role != "org_owner":
            raise HTTPException(status_code=403, detail="Only organization owners can remove members")
    
    # Prevent removing yourself
    if user_id == user.id:
        raise HTTPException(status_code=400, detail="Cannot remove yourself")

    if not adapter.delete_organization_member(org_id, user_id):
        raise HTTPException(status_code=404, detail="Member not found")

    log_delete(adapter, org_id, user.id, "organization_member", user_id, request)

    return {"status": "removed"}


# ── Email Settings ──

@router.get("/orgs/{org_id}/email-settings")
@require_org_role("org_admin", "org_owner")
def get_email_settings(
    org_id: str,
    request: Request = None,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    org = adapter.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    settings_obj = _load_org_settings(org)
    return {
        "host": settings_obj.get("smtp_host", ""),
        "port": settings_obj.get("smtp_port", 587),
        "username": settings_obj.get("smtp_username", ""),
        "sender": settings_obj.get("smtp_from", ""),
        "use_tls": settings_obj.get("smtp_use_tls", True),
        "has_password": bool(settings_obj.get("smtp_password")),
    }


@router.put("/orgs/{org_id}/email-settings")
@require_org_role("org_admin", "org_owner")
def update_email_settings(
    org_id: str,
    payload: EmailSettingsPayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    org = adapter.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    settings_obj = _load_org_settings(org)
    settings_obj["smtp_host"] = payload.host.strip()
    settings_obj["smtp_port"] = int(payload.port)
    settings_obj["smtp_username"] = payload.username.strip()
    settings_obj["smtp_from"] = payload.sender.strip()
    settings_obj["smtp_use_tls"] = bool(payload.use_tls)
    if payload.password:
        settings_obj["smtp_password"] = encrypt_text(payload.password)

    updated = _save_org_settings(adapter, org_id, settings_obj)
    if not updated:
        raise HTTPException(status_code=404, detail="Organization not found")

    log_update(adapter, org_id, user.id, "email_settings", org_id, request)
    return {"status": "updated"}


@router.post("/orgs/{org_id}/email-settings/test")
@require_org_role("org_admin", "org_owner")
def test_email_settings(
    org_id: str,
    payload: EmailTestPayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    subject = "Lazeport SMTP test"
    body = "Your organization SMTP settings are working."
    ok = send_org_email(adapter, org_id, payload.to_email, subject, body)
    if not ok:
        raise HTTPException(status_code=400, detail="Failed to send test email")
    log_create(adapter, org_id, user.id, "email_test", org_id, request, to_email=payload.to_email)
    return {"status": "sent"}


# ── OIDC / SSO ──

@router.get("/orgs/{org_id}/oidc-config")
@require_org_role("org_admin", "org_owner")
def get_oidc_config(
    org_id: str,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Get OIDC config for org (client secret not returned)."""
    org = adapter.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    configs = list(adapter.list_org_oidc_configs(org_id))
    if not configs:
        return {"configured": False}
    cfg = configs[0]
    return {
        "configured": True,
        "provider_id": cfg.provider_id,
        "provider_label": cfg.provider_label,
        "issuer": cfg.issuer,
        "client_id": cfg.client_id,
    }


@router.put("/orgs/{org_id}/oidc-config")
@require_org_role("org_admin", "org_owner")
def update_oidc_config(
    org_id: str,
    payload: OidcConfigPayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Save OIDC config for org."""
    org = adapter.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    existing = adapter.get_org_oidc_config(org_id, payload.provider_id or "okta")
    enc = encrypt_text(payload.client_secret) if payload.client_secret else (existing.client_secret_encrypted if existing else "")
    adapter.upsert_org_oidc_config(
        org_id=org_id,
        provider_id=payload.provider_id or "okta",
        provider_label=payload.provider_label or payload.provider_id or "Okta",
        issuer=payload.issuer,
        client_id=payload.client_id,
        client_secret_encrypted=enc,
    )
    log_update(adapter, org_id, user.id, "oidc_config", org_id, request)
    return {"status": "updated"}


@router.delete("/orgs/{org_id}/oidc-config")
@require_org_role("org_admin", "org_owner")
def delete_oidc_config(
    org_id: str,
    provider_id: str = "okta",
    request: Request = None,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Remove OIDC config for org."""
    org = adapter.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    ok = adapter.delete_org_oidc_config(org_id, provider_id)
    if not ok:
        raise HTTPException(status_code=404, detail="OIDC config not found")
    log_delete(adapter, org_id, user.id, "oidc_config", org_id, request)
    return {"status": "deleted"}


@router.get("/orgs/{org_id}/domains")
@require_org_role("org_admin", "org_owner")
def list_org_domains(
    org_id: str,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """List email domains for org (used for OIDC routing)."""
    org = adapter.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    domains = list(adapter.list_org_domains(org_id))
    return {"domains": [d.domain for d in domains]}


@router.post("/orgs/{org_id}/domains")
@require_org_role("org_admin", "org_owner")
def add_org_domain(
    org_id: str,
    payload: DomainPayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Add domain for org (used for OIDC routing)."""
    org = adapter.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    try:
        adapter.add_org_domain(org_id, payload.domain)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid or duplicate domain")
    log_create(adapter, org_id, user.id, "org_domain", org_id, request, domain=payload.domain)
    return {"status": "added", "domain": payload.domain}


@router.delete("/orgs/{org_id}/domains")
@require_org_role("org_admin", "org_owner")
def remove_org_domain(
    org_id: str,
    domain: str = Query(..., description="Domain to remove, e.g. acme.com"),
    request: Request = None,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Remove domain from org."""
    org = adapter.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    ok = adapter.remove_org_domain(org_id, domain)
    if not ok:
        raise HTTPException(status_code=404, detail="Domain not found")
    log_delete(adapter, org_id, user.id, "org_domain", org_id, request, domain=domain)
    return {"status": "deleted"}


# ── Audit Logs ──

@router.get("/orgs/{org_id}/audit-logs")
@require_org_role("org_admin", "org_owner")
def list_audit_logs(
    org_id: str,
    limit: int = 50,
    offset: int = 0,
    request: Request = None,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """
    List audit logs for an organization.

    Query params:
    - limit: Max number of records (default: 50, max: 500)
    - offset: Pagination offset (default: 0)
    """
    if limit > 500:
        limit = 500

    logs = adapter.list_audit_logs(org_id, limit, offset)

    user_ids = list({log.user_id for log in logs})
    users_by_id = adapter.get_users_by_ids(user_ids) if user_ids else {}

    result = []
    for log in logs:
        user_obj = users_by_id.get(log.user_id)
        result.append({
            "id": log.id,
            "action": log.action,
            "resource_type": log.resource_type,
            "resource_id": log.resource_id,
            "details": log.details,
            "user_email": user_obj.email if user_obj else "Unknown",
            "user_name": user_obj.name if user_obj else "",
            "ip_address": log.ip_address,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
        })

    return result


# ── Rate Limit Settings ──

class RateLimitSettingsPayload(BaseModel):
    max_attempts: int
    lockout_minutes: int

    @field_validator('max_attempts')
    @classmethod
    def validate_max_attempts(cls, v):
        if v < 1 or v > 100:
            raise ValueError('max_attempts must be between 1 and 100')
        return v

    @field_validator('lockout_minutes')
    @classmethod
    def validate_lockout_minutes(cls, v):
        if v < 1 or v > 1440:  # Max 24 hours
            raise ValueError('lockout_minutes must be between 1 and 1440 (24 hours)')
        return v


@router.get("/orgs/{org_id}/rate-limit-settings")
@require_org_role("org_admin", "org_owner")
def get_rate_limit_settings(
    org_id: str,
    request: Request = None,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Get rate limit settings for login attempts."""
    from app.services.rate_limit import get_org_rate_limit_settings
    return get_org_rate_limit_settings(adapter, org_id)


@router.put("/orgs/{org_id}/rate-limit-settings")
@require_org_role("org_admin", "org_owner")
def update_rate_limit_settings(
    org_id: str,
    payload: RateLimitSettingsPayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Update rate limit settings for login attempts (org admin/owner only)."""
    import json

    org = adapter.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Parse existing settings
    try:
        settings = json.loads(org.settings) if org.settings else {}
    except json.JSONDecodeError:
        settings = {}

    # Update rate limit settings
    settings["rate_limit_max_attempts"] = payload.max_attempts
    settings["rate_limit_lockout_minutes"] = payload.lockout_minutes

    # Save
    adapter.update_organization(org_id, settings=json.dumps(settings))

    # Audit log
    log_update(
        adapter, org_id, user.id, "organization_settings", org_id, request,
        details=f"Updated rate limit: {payload.max_attempts} attempts, {payload.lockout_minutes} min lockout"
    )

    return {
        "max_attempts": payload.max_attempts,
        "lockout_minutes": payload.lockout_minutes,
    }


# ── LLM Settings ──

class SamplingParams(BaseModel):
    """Provider-aware LLM sampling parameters. All optional; None = use app defaults."""
    temperature: float | None = None
    top_p: float | None = None
    frequency_penalty: float | None = None
    presence_penalty: float | None = None
    top_k: int | None = None
    min_p: float | None = None
    repeat_penalty: float | None = None

    @field_validator("temperature")
    @classmethod
    def validate_temperature(cls, v):
        if v is not None and (v < 0.0 or v > 2.0):
            raise ValueError("temperature must be between 0.0 and 2.0")
        return v

    @field_validator("top_p")
    @classmethod
    def validate_top_p(cls, v):
        if v is not None and (v < 0.0 or v > 1.0):
            raise ValueError("top_p must be between 0.0 and 1.0")
        return v

    @field_validator("frequency_penalty")
    @classmethod
    def validate_frequency_penalty(cls, v):
        if v is not None and (v < -2.0 or v > 2.0):
            raise ValueError("frequency_penalty must be between -2.0 and 2.0")
        return v

    @field_validator("presence_penalty")
    @classmethod
    def validate_presence_penalty(cls, v):
        if v is not None and (v < -2.0 or v > 2.0):
            raise ValueError("presence_penalty must be between -2.0 and 2.0")
        return v

    @field_validator("top_k")
    @classmethod
    def validate_top_k(cls, v):
        if v is not None and (v < 1 or v > 200):
            raise ValueError("top_k must be between 1 and 200")
        return v

    @field_validator("min_p")
    @classmethod
    def validate_min_p(cls, v):
        if v is not None and (v < 0.0 or v > 1.0):
            raise ValueError("min_p must be between 0.0 and 1.0")
        return v

    @field_validator("repeat_penalty")
    @classmethod
    def validate_repeat_penalty(cls, v):
        if v is not None and (v < 0.0 or v > 3.0):
            raise ValueError("repeat_penalty must be between 0.0 and 3.0")
        return v


class ProviderSettings(BaseModel):
    """Per-provider LLM configuration (model, URL, timeout, sampling)."""
    model: str | None = None
    base_url: str | None = None
    vision_model: str | None = None
    timeout: float | None = None
    sampling_params: SamplingParams | None = None

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, v):
        if v is None or not str(v).strip():
            return v
        return ValidatedString.url_validator(v)

    @field_validator("timeout")
    @classmethod
    def validate_timeout(cls, v):
        if v is not None and (v < 10 or v > 600):
            raise ValueError("Timeout must be between 10 and 600 seconds")
        return v


class OrgLlmSettings(BaseModel):
    """Full org-level LLM configuration with per-provider storage."""
    provider: str | None = None
    model: str | None = None
    base_url: str | None = None
    vision_model: str | None = None
    timeout: float | None = None
    extra_instructions: str | None = None
    sampling_params: SamplingParams | None = None
    providers: dict | None = None

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, v):
        if v is None:
            return v
        from app.services.llm import ALLOWED_PROVIDERS
        v_lower = str(v).strip().lower()
        if v_lower not in ALLOWED_PROVIDERS:
            raise ValueError(f"Provider must be one of: {', '.join(sorted(ALLOWED_PROVIDERS))}")
        return v_lower

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, v):
        if v is None or not str(v).strip():
            return v
        return ValidatedString.url_validator(v)

    @field_validator("timeout")
    @classmethod
    def validate_timeout(cls, v):
        if v is not None and (v < 10 or v > 600):
            raise ValueError("Timeout must be between 10 and 600 seconds")
        return v

    @field_validator("extra_instructions")
    @classmethod
    def validate_extra_instructions(cls, v):
        if v is not None and len(v) > 2000:
            raise ValueError("Extra instructions must be 2000 characters or fewer")
        return v


def _resolve_llm_settings(raw: dict) -> dict:
    """Resolve per-provider storage into flat active-provider settings."""
    from app.api.generate import DEFAULT_EXTRA_INSTRUCTIONS

    ei = raw.get("extra_instructions")
    resolved_ei = ei if ei is not None else DEFAULT_EXTRA_INSTRUCTIONS

    active = raw.get("provider")
    providers = raw.get("providers")
    if not providers or not active or active not in providers:
        result = dict(raw)
        result["extra_instructions"] = resolved_ei
        return result
    result = {
        "provider": active,
        "extra_instructions": resolved_ei,
    }
    result.update(providers[active])
    return {k: v for k, v in result.items() if v is not None}


@router.get("/orgs/{org_id}/llm-settings")
@require_org_role("readonly", "consultant", "org_admin", "org_owner")
def get_llm_settings(
    org_id: str,
    request: Request = None,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Get active org-level LLM configuration (flat). Any org member can read."""
    org = adapter.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    settings_obj = _load_org_settings(org)
    return _resolve_llm_settings(settings_obj.get("llm", {}))


@router.get("/orgs/{org_id}/llm-settings/all")
@require_org_role("readonly", "consultant", "org_admin", "org_owner")
def get_all_llm_settings(
    org_id: str,
    request: Request = None,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Get full org-level LLM configuration including per-provider storage.
    Applies default extra_instructions when missing so the UI can show it."""
    org = adapter.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    settings_obj = _load_org_settings(org)
    raw = settings_obj.get("llm", {})
    if not raw:
        return {}
    from app.api.generate import DEFAULT_EXTRA_INSTRUCTIONS
    result = dict(raw)
    if result.get("extra_instructions") is None or result.get("extra_instructions") == "":
        result["extra_instructions"] = DEFAULT_EXTRA_INSTRUCTIONS
    return result


@router.put("/orgs/{org_id}/llm-settings")
@require_org_role("org_admin", "org_owner")
def update_llm_settings(
    org_id: str,
    payload: OrgLlmSettings,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Update org-level LLM configuration. Org admin/owner only."""
    org = adapter.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    settings_obj = _load_org_settings(org)
    llm_data = payload.model_dump(exclude_none=True)
    if payload.sampling_params is not None:
        llm_data["sampling_params"] = payload.sampling_params.model_dump(exclude_none=True)
    if payload.providers is not None:
        llm_data["providers"] = payload.providers
    settings_obj["llm"] = llm_data

    updated = _save_org_settings(adapter, org_id, settings_obj)
    if not updated:
        raise HTTPException(status_code=404, detail="Organization not found")

    log_update(adapter, org_id, user.id, "llm_settings", org_id, request)
    return _resolve_llm_settings(settings_obj["llm"])


class VisionSettingsPayload(BaseModel):
    """Payload for updating vision processing settings."""
    max_concurrent_tasks: int = 2

    @field_validator('max_concurrent_tasks')
    @classmethod
    def validate_max_tasks(cls, v):
        if v < 1 or v > 10:
            raise ValueError("max_concurrent_tasks must be between 1 and 10")
        return v


@router.get("/orgs/{org_id}/vision-settings")
@require_org_role("org_admin", "org_owner")
def get_vision_settings(
    org_id: str,
    request: Request = None,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Get vision processing settings (max concurrent tasks for image extraction)."""
    import json

    org = adapter.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    try:
        settings = json.loads(org.settings) if org.settings else {}
    except json.JSONDecodeError:
        settings = {}

    return {
        "max_concurrent_tasks": settings.get("vision_max_concurrent_tasks", 2)
    }


@router.put("/orgs/{org_id}/vision-settings")
@require_org_role("org_admin", "org_owner")
def update_vision_settings(
    org_id: str,
    payload: VisionSettingsPayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Update vision processing settings (org admin/owner only)."""
    import json

    org = adapter.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Parse existing settings
    try:
        settings = json.loads(org.settings) if org.settings else {}
    except json.JSONDecodeError:
        settings = {}

    # Update vision settings
    settings["vision_max_concurrent_tasks"] = payload.max_concurrent_tasks

    # Save
    adapter.update_organization(org_id, settings=json.dumps(settings))

    # Audit log
    log_update(
        adapter, org_id, user.id, "organization_settings", org_id, request,
        details=f"Updated vision settings: max {payload.max_concurrent_tasks} concurrent tasks"
    )

    return {
        "max_concurrent_tasks": payload.max_concurrent_tasks,
    }


class SeveritySettingsPayload(BaseModel):
    """Payload for updating organization severity criteria."""
    severity_criteria: dict = {}  # Dict[str, str] of severity level -> definition

    @field_validator('severity_criteria')
    @classmethod
    def validate_severity_criteria(cls, v):
        """Validate severity criteria structure and content."""
        if not isinstance(v, dict):
            raise ValueError("severity_criteria must be a dictionary")

        # Must have exactly 5 required levels
        required_levels = {'Critical', 'High', 'Medium', 'Low', 'Informational'}
        if set(v.keys()) != required_levels:
            missing = required_levels - set(v.keys())
            extra = set(v.keys()) - required_levels
            msg = "severity_criteria must contain exactly 5 levels"
            if missing:
                msg += f" (missing: {', '.join(sorted(missing))})"
            if extra:
                msg += f" (extra: {', '.join(sorted(extra))})"
            raise ValueError(msg)

        # Each definition must be a non-empty string, max 2000 chars, no HTML tags
        for level, definition in v.items():
            if not isinstance(definition, str):
                raise ValueError(f"Definition for {level} must be a string")
            if len(definition) == 0:
                raise ValueError(f"Definition for {level} cannot be empty")
            if len(definition) > 2000:
                raise ValueError(f"Definition for {level} exceeds 2000 character limit")
            # Check for HTML tags (basic XSS prevention)
            if '<' in definition and any(tag in definition.lower() for tag in ['script', 'iframe', 'onclick', 'onerror']):
                raise ValueError(f"Definition for {level} contains disallowed HTML tags")

        return v


@router.get("/orgs/{org_id}/severity-settings")
@require_org_role("org_admin", "org_owner")
def get_severity_settings(
    org_id: str,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Get organization severity criteria (org admin/owner only)."""
    org = adapter.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Parse severity criteria JSON
    try:
        if org.severity_criteria:
            severity_criteria = json.loads(org.severity_criteria)
        else:
            severity_criteria = {}
    except json.JSONDecodeError:
        severity_criteria = {}

    return {
        "severity_criteria": severity_criteria,
    }


@router.put("/orgs/{org_id}/severity-settings")
@require_org_role("org_admin", "org_owner")
def put_severity_settings(
    org_id: str,
    payload: SeveritySettingsPayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Update organization severity criteria (org admin/owner only)."""
    org = adapter.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Save severity criteria as JSON
    adapter.update_organization(org_id, severity_criteria=json.dumps(payload.severity_criteria))

    # Audit log
    log_update(
        adapter, org_id, user.id, "organization_settings", org_id, request,
        details="Updated severity criteria"
    )

    return {
        "severity_criteria": payload.severity_criteria,
    }
