from __future__ import annotations

import io
import json
import logging
import re
import time
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Request
from pydantic import BaseModel, field_validator

from app.config import settings as app_settings
from app.db import get_adapter, models
from app.db.adapter import StorageAdapter
from app.db.models import SYSTEM_ORG_ID
from app.services.auth import get_current_user, require_system_admin
from app.services.audit import log_create, log_update, log_delete
from app.services.email import send_org_email
from app.services.rbac import (
    get_org_id_from_request,
    can_view_report,
    can_edit_report,
    can_manage_report_shares,
    get_user_role_in_org,
    has_permission,
    verify_resource_org_access,
    require_consultant,
    require_organization_admin,
    require_owner,
)
from app.validation import ValidatedString, MAX_CONTENT_LENGTH

ROOT = Path(__file__).resolve().parent.parent.parent
TEMPLATES_DIR = Path(app_settings.templates_dir) if Path(app_settings.templates_dir).is_absolute() else ROOT / app_settings.templates_dir


router = APIRouter()

log = logging.getLogger(__name__)

STALE_GENERATING_MS = 5 * 60 * 1000  # 5 minutes (3 self-check rounds × 60s + margin)


def _safe_filename(name: str) -> str:
    """Sanitise a string for use in a Content-Disposition filename header.

    HTTP headers are encoded as Latin-1, so any character outside that range
    (e.g. em-dashes, smart quotes, CJK, emoji) must be stripped or replaced.
    """
    safe = "".join(c if c.isascii() and (c.isalnum() or c in " -_.,()") else "_" for c in name)
    return safe.strip() or "download"


def _mark_stale_generating_as_failed(tasks: list) -> tuple[list, bool]:
    """Mark tasks stuck in 'generating' for > STALE_GENERATING_MS as 'failed'.

    Only fires when generating_since is present and the threshold has elapsed.
    Tasks without a timestamp are left alone — they could be mid-flight from a
    fast-path Celery task that hasn't written its completion yet.
    """
    now_ms = int(time.time() * 1000)
    updated = []
    changed = False
    for t in tasks:
        if t.get("status") == "generating":
            since = t.get("generating_since")
            if since and (now_ms - since) >= STALE_GENERATING_MS:
                updated.append({**t, "status": "failed"})
                changed = True
            else:
                updated.append(t)
        else:
            updated.append(t)
    return updated, changed


def _ensure_system_org_id(adapter: StorageAdapter) -> str:
    return adapter.ensure_system_org()


def _strip_internal_content_keys(content_dict: dict) -> dict:
    """Remove internal keys (e.g. _severity_flags, rubric_source) so they are not shown or persisted in findings."""
    if not content_dict or not isinstance(content_dict, dict):
        return content_dict
    return {k: v for k, v in content_dict.items() if not (isinstance(k, str) and k.startswith("_"))}


def _parse_finding_content_safe(content_json: str | None, finding_id: str = "") -> dict:
    """LOW-19: Parse finding content_json. On failure, log and return placeholder."""
    raw = content_json or "{}"
    try:
        parsed = json.loads(raw)
        return _strip_internal_content_keys(parsed) if isinstance(parsed, dict) else parsed
    except Exception as e:
        log.warning("Failed to parse finding content_json (finding_id=%s): %s", finding_id, e)
        return {
            "Vulnerability Summary": "[Content unavailable - encoding or JSON error]",
            "Severity": "Unknown",
        }


def _get_report_or_404(report_id: str, adapter: StorageAdapter):
    report = adapter.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


def _require_report_view(report_id: str, user, adapter: StorageAdapter):
    report = _get_report_or_404(report_id, adapter)
    if not can_view_report(user, report, adapter):
        raise HTTPException(status_code=403, detail="Insufficient permissions to view this report")
    return report


def _require_report_edit(report_id: str, user, adapter: StorageAdapter):
    report = _get_report_or_404(report_id, adapter)
    if not can_edit_report(user, report, adapter):
        raise HTTPException(status_code=403, detail="Insufficient permissions to modify this report")
    return report


def _get_client_or_404(client_id: str, user, adapter: StorageAdapter):
    """Get client and verify user has org access."""
    client = adapter.get_client(client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Team not found")
    # Verify user belongs to same org as client
    verify_resource_org_access(user, client.organization_id, adapter, "client")
    return client


def _get_application_or_404(app_id: str, user, adapter: StorageAdapter):
    """Get application and verify user has org access."""
    app = adapter.get_application(app_id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    # Verify user belongs to same org as application
    verify_resource_org_access(user, app.organization_id, adapter, "application")
    return app


def _get_finding_or_404(finding_id: str, user, adapter: StorageAdapter):
    """Get finding and verify user has org access."""
    finding = adapter.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    # Verify user belongs to same org as finding
    verify_resource_org_access(user, finding.organization_id, adapter, "finding")
    return finding


class SettingsPayload(BaseModel):
    org_name: Optional[str] = None
    author_name: Optional[str] = None
    voice_style: Optional[str] = None

    @field_validator('org_name', 'author_name')
    @classmethod
    def validate_names(cls, v):
        if v is None:
            return v
        return ValidatedString.name_validator(v)
    
    @field_validator('voice_style')
    @classmethod
    def validate_voice_style(cls, v):
        if v is None:
            return v
        return ValidatedString.notes_validator(v)


class TeamPayload(BaseModel):
    name: str

    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        return ValidatedString.name_validator(v)


class ApplicationPayload(BaseModel):
    name: str
    type: Optional[str] = None
    description: Optional[str] = ""

    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        return ValidatedString.name_validator(v)

    @field_validator('type')
    @classmethod
    def validate_type(cls, v):
        if v is None:
            return v
        allowed = {'web', 'api', 'ios', 'android', 'hardware'}
        v = str(v).strip().lower()
        if v and v not in allowed:
            raise ValueError(f"Application type must be one of: {', '.join(allowed)}")
        return v or None

    @field_validator('description')
    @classmethod
    def validate_description(cls, v):
        if not v:
            return ""
        return ValidatedString.notes_validator(v)


class ReportPayload(BaseModel):
    name: str
    client_id: Optional[str] = None
    application_id: Optional[str] = None

    @field_validator('client_id', 'application_id')
    @classmethod
    def validate_ids(cls, v):
        if v is None:
            return v
        return ValidatedString.uuid_validator(v)

    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        return ValidatedString.name_validator(v)


class ReportUpdatePayload(BaseModel):
    name: str
    client_id: Optional[str] = None
    application_id: Optional[str] = None

    @field_validator('client_id', 'application_id')
    @classmethod
    def validate_ids(cls, v):
        if v is None:
            return v
        return ValidatedString.uuid_validator(v)

    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        return ValidatedString.name_validator(v)


class ReportSharePayload(BaseModel):
    user_id: str | None = None
    email: str | None = None

    @field_validator('user_id')
    @classmethod
    def validate_user_id(cls, v):
        if v is None:
            return v
        return ValidatedString.uuid_validator(v)

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        if v is None:
            return v
        return ValidatedString.email_validator(v)


class ReportSummariesPayload(BaseModel):
    summary_executive: str | None = None
    summary_technical: str | None = None
    summary_recommendations: str | None = None

    @field_validator('summary_executive', 'summary_technical', 'summary_recommendations')
    @classmethod
    def validate_summaries(cls, v):
        if v is None:
            return v
        return ValidatedString.content_validator(v)


class FindingPayload(BaseModel):
    report_id: str
    title: Optional[str] = ""
    content: dict
    notes: Optional[str] = ""
    template: Optional[str] = ""

    @field_validator('report_id')
    @classmethod
    def validate_report_id(cls, v):
        return ValidatedString.uuid_validator(v)
    
    @field_validator('title')
    @classmethod
    def validate_title(cls, v):
        if not v:
            return ""
        return ValidatedString.title_validator(v)
    
    @field_validator('notes', 'template')
    @classmethod
    def validate_text_fields(cls, v):
        if not v:
            return ""
        return ValidatedString.notes_validator(v)
    
    @field_validator('content')
    @classmethod
    def validate_content_structure(cls, v):
        """
        MED-16: Validate content is a flat dict with string values only.
        
        Findings expect content_json to be a simple key-value structure like:
        {"Title": "XSS", "Description": "...", "Severity": "High"}
        
        Reject nested objects, arrays, or non-string values.
        """
        if not isinstance(v, dict):
            raise ValueError("content must be a dictionary")
        
        for key, value in v.items():
            if not isinstance(key, str):
                raise ValueError(f"All keys must be strings, got {type(key).__name__}")
            
            # Allow string values only (no nested objects, arrays, numbers, etc.)
            if value is not None and not isinstance(value, str):
                raise ValueError(
                    f"Field '{key}' has non-string value (type: {type(value).__name__}). "
                    "All content values must be strings."
                )
            
            # Check string length
            if isinstance(value, str) and len(value) > MAX_CONTENT_LENGTH:
                raise ValueError(f"Field '{key}' exceeds maximum length of {MAX_CONTENT_LENGTH} characters")
        
        return v


class RolePayload(BaseModel):
    role: str

    @field_validator('role')
    @classmethod
    def validate_role(cls, v):
        allowed_roles = {'admin', 'user', 'org_owner', 'org_admin', 'consultant', 'readonly'}
        v = str(v).strip().lower()
        if v not in allowed_roles:
            raise ValueError(f"Role must be one of: {', '.join(allowed_roles)}")
        return v


class MasterDocxPayload(BaseModel):
    report_id: str
    template_name: str
    locale: str | None = None

    @field_validator('report_id')
    @classmethod
    def validate_report_id(cls, v):
        return ValidatedString.uuid_validator(v)
    
    @field_validator('template_name')
    @classmethod
    def validate_template_name(cls, v):
        return ValidatedString.filename_validator(v)


class FindingTemplatePayload(BaseModel):
    name: str
    content: str

    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        return ValidatedString.name_validator(v)
    
    @field_validator('content')
    @classmethod
    def validate_content(cls, v):
        return ValidatedString.content_validator(v)


class ProfilePayload(BaseModel):
    name: str | None = None
    email: str | None = None
    phone: str | None = None
    title: str | None = None
    company_name: str | None = None
    department_name: str | None = None
    theme: str | None = None
    default_master_template: str | None = None
    default_finding_template: str | None = None
    openai_api_key: str | None = None  # Optional: set to store, set to "" to clear
    ai_key_provider: str | None = None  # Which provider the key belongs to

    @field_validator('name', 'company_name', 'department_name')
    @classmethod
    def validate_names(cls, v):
        if v is None:
            return v
        return ValidatedString.name_validator(v)
    
    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        return ValidatedString.email_validator(v)
    
    @field_validator('phone', 'title')
    @classmethod
    def validate_text(cls, v):
        if v is None:
            return v
        return ValidatedString.name_validator(v)
    
    @field_validator('theme', 'default_master_template', 'default_finding_template')
    @classmethod
    def validate_settings(cls, v):
        if v is None:
            return v
        return ValidatedString.name_validator(v)


class ConnectorPayload(BaseModel):
    type: str
    name: str
    config: dict
    enabled: bool = True

    @field_validator('type')
    @classmethod
    def validate_type(cls, v):
        allowed_types = {'jira', 'github', 'slack', 'servicenow'}
        v = str(v).strip().lower()
        if v not in allowed_types:
            raise ValueError(f"Connector type must be one of: {', '.join(allowed_types)}")
        return v
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        return ValidatedString.name_validator(v)
    
    @field_validator('config')
    @classmethod
    def validate_config(cls, v):
        if not isinstance(v, dict):
            raise ValueError("Config must be a dictionary")
        # Validate specific keys for Jira
        if 'url' in v:
            ValidatedString.url_validator(v['url'])
        if 'email' in v:
            ValidatedString.email_validator(v['email'])
        return v


class JiraIssuePayload(BaseModel):
    finding_id: str
    project_key: str
    issue_type: str = "Bug"

    @field_validator('finding_id')
    @classmethod
    def validate_finding_id(cls, v):
        return ValidatedString.uuid_validator(v)
    
    @field_validator('project_key')
    @classmethod
    def validate_project_key(cls, v):
        v = str(v).strip().upper()
        if not v or len(v) > 10:
            raise ValueError("Project key must be 1-10 characters")
        if not v.replace('_', '').isalnum():
            raise ValueError("Project key must be alphanumeric")
        return v
    
    @field_validator('issue_type')
    @classmethod
    def validate_issue_type(cls, v):
        return ValidatedString.name_validator(v)


@router.get("/settings")
@require_organization_admin()
def get_settings(
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    return adapter.get_settings()


@router.put("/settings")
@require_organization_admin()
def update_settings(
    payload: SettingsPayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    data = payload.model_dump()
    updated = adapter.upsert_settings(data)
    changed_keys = [k for k, v in data.items() if v is not None]
    org_id = _ensure_system_org_id(adapter)
    log_update(adapter, org_id, user.id, "settings", "settings", request, keys=changed_keys)
    return updated


@router.get("/profile")
def get_profile(
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    selected_provider = (getattr(user, "ai_key_provider", "") or "openai").strip().lower()
    
    # Get list of all configured providers
    configured_providers = []
    if getattr(adapter, "get_user_provider_api_key", None):
        # Check all known providers
        for prov in ["openai", "anthropic", "gemini", "openrouter", "deepseek"]:
            if adapter.get_user_provider_api_key(user.id, prov):
                configured_providers.append(prov)
        openai_configured = selected_provider in configured_providers
    else:
        openai_configured = bool(
            getattr(user, "openai_api_key_encrypted", None)
            and user.openai_api_key_encrypted
        )
    
    return {
        "name": user.name,
        "email": user.contact_email or "",
        "phone": user.phone or "",
        "title": user.title or "",
        "company_name": user.company_name or "",
        "department_name": user.department_name or "",
        "theme": user.theme or "accessibility",
        "default_master_template": user.default_master_template or "master",
        "default_finding_template": user.default_finding_template or "",
        "openai_api_key_configured": openai_configured,
        "ai_key_provider": getattr(user, "ai_key_provider", "") or "",
        "configured_providers": configured_providers,
    }


@router.put("/profile")
def update_profile(
    payload: ProfilePayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    changed_fields = []
    if payload.name is not None:
        changed_fields.append("name")
        adapter.set_user_name(user.id, payload.name.strip())
    if payload.company_name is not None:
        changed_fields.append("company_name")
    if payload.department_name is not None:
        changed_fields.append("department_name")
    if payload.email is not None:
        changed_fields.append("email")
    if payload.phone is not None:
        changed_fields.append("phone")
    if payload.title is not None:
        changed_fields.append("title")
    if payload.theme is not None:
        valid_themes = ("system", "terminal", "light", "dark", "ghost", "solarized-light", "solarized-dark", "accessibility")
        if payload.theme in valid_themes:
            changed_fields.append("theme")
    if payload.default_master_template is not None:
        changed_fields.append("default_master_template")
    if payload.default_finding_template is not None:
        changed_fields.append("default_finding_template")
    if payload.openai_api_key is not None:
        changed_fields.append("openai_api_key")
        provider_for_key = (
            (payload.ai_key_provider or getattr(user, "ai_key_provider", "") or "openai")
            .strip()
            .lower()
        )
        if getattr(adapter, "set_user_provider_api_key", None):
            adapter.set_user_provider_api_key(
                user.id,
                provider_for_key,
                payload.openai_api_key if payload.openai_api_key.strip() else None,
            )
        else:
            adapter.set_user_openai_api_key(
                user.id,
                payload.openai_api_key if payload.openai_api_key.strip() else None,
            )
    if payload.ai_key_provider is not None:
        changed_fields.append("ai_key_provider")

    adapter.update_user_profile(
        user.id,
        contact_email=payload.email.strip() if payload.email is not None else None,
        phone=payload.phone.strip() if payload.phone is not None else None,
        title=payload.title.strip() if payload.title is not None else None,
        theme=payload.theme if payload.theme in ("system", "terminal", "light", "dark", "ghost", "solarized-light", "solarized-dark", "accessibility") else None,
        company_name=payload.company_name.strip() if payload.company_name is not None else None,
        department_name=payload.department_name.strip() if payload.department_name is not None else None,
        default_master_template=payload.default_master_template.strip() if payload.default_master_template is not None else None,
        default_finding_template=payload.default_finding_template.strip() if payload.default_finding_template is not None else None,
        ai_key_provider=payload.ai_key_provider.strip() if payload.ai_key_provider is not None else None,
    )
    org_id = _ensure_system_org_id(adapter)
    log_update(adapter, org_id, user.id, "profile", user.id, request, fields=changed_fields)
    return {"ok": True}


class LlmInstructionsPayload(BaseModel):
    instructions: str = ""


@router.get("/me/llm-instructions")
def get_llm_instructions(
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Get the current user's LLM extra instructions (writing style, etc.). Stored in DB for long prompts."""
    u = adapter.get_user_by_id(user.id)
    instructions = getattr(u, "llm_extra_instructions", None) or "" if u else ""
    return {"instructions": instructions}


@router.put("/me/llm-instructions")
def update_llm_instructions(
    payload: LlmInstructionsPayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Update the current user's LLM extra instructions. Appended to every AI request."""
    adapter.update_user_profile(user.id, llm_extra_instructions=payload.instructions or "")
    org_id = _ensure_system_org_id(adapter)
    log_update(adapter, org_id, user.id, "llm_instructions", user.id, request)
    return {"ok": True, "instructions": payload.instructions or ""}


@router.get("/users")
@require_organization_admin()
def list_users(
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """List users in the current user's organization.
    
    Returns only users who are members of the requesting user's organization,
    preventing cross-org information disclosure (HIGH-1 fix).
    """
    from app.services.rbac import get_org_id_from_request
    
    # Get the user's organization ID
    org_id = get_org_id_from_request(request, user, adapter)
    
    if not org_id:
        # User not in any organization
        return []
    
    # Get organization members
    members = adapter.list_organization_members(org_id)
    
    # Fetch full user details for each member
    users = []
    for member in members:
        user_obj = adapter.get_user_by_id(member.user_id)
        if user_obj:
            users.append(user_obj)
    
    return users


@router.patch("/users/{user_id}")
def update_user_role(
    user_id: str,
    payload: RolePayload,
    request: Request,
    user=Depends(require_system_admin),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """
    Update system-level user role (system admin only).
    
    This endpoint changes the global 'role' field (admin/user) in the User table.
    For organization-specific roles, use PUT /orgs/{org_id}/members/{user_id}/role.
    
    MED-12 fix: Restricted to system admins to prevent privilege escalation.
    """
    if payload.role not in ("admin", "user"):
        raise HTTPException(status_code=400, detail="Invalid role")
    existing = adapter.get_user_by_id(user_id)
    old_role = existing.role if existing else None
    updated_user = adapter.set_user_role(user_id, payload.role)
    if not updated_user:
        raise HTTPException(status_code=404, detail="User not found")
    org_id = _ensure_system_org_id(adapter)
    log_update(adapter, org_id, user.id, "user", user_id, request, old_role=old_role, new_role=payload.role)
    return updated_user


@router.post("/users/{user_id}/2fa/reset")
def admin_reset_user_2fa(
    user_id: str,
    request: Request,
    admin_user=Depends(require_system_admin),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """
    Reset 2FA for a user (system admin only).
    
    Clears all 2FA configuration for the specified user and sends them a notification.
    """
    from app.services.audit import log_auth
    
    target_user = adapter.get_user_by_id(user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not target_user.twofa_enabled:
        raise HTTPException(status_code=400, detail="User does not have 2FA enabled")
    
    # Clear 2FA configuration
    # MED-6: Session invalidation handled by incrementing session_version below.
    with adapter._session() as session:
        db_user = session.get(models.User, user_id)
        if db_user:
            db_user.twofa_secret = ""
            db_user.twofa_enabled = False
            db_user.twofa_backup_codes = ""
            db_user.twofa_configured_at = None
            session.commit()

    # MED-6: Invalidate all existing sessions by incrementing session_version
    adapter.increment_user_session_version(user_id)
    
    # Get user's organization for logging and email
    org_id = SYSTEM_ORG_ID
    try:
        orgs = list(adapter.get_user_organizations(target_user.id))
        if orgs:
            org_id = orgs[0].id
    except Exception as e:
        log.warning("Could not resolve org for user during 2FA reset: %s", type(e).__name__)
    
    log_auth(adapter, org_id, target_user.id, "2fa_reset_by_admin", request, details={
        "admin_id": admin_user.id,
        "admin_email": admin_user.email
    })
    
    # Send email notification to the user
    from datetime import datetime
    try:
        send_org_email(
            adapter,
            org_id,
            target_user.email,
            "Two-Factor Authentication Reset by Administrator",
            f"Hello {target_user.name or target_user.email},\n\n"
            f"Two-factor authentication has been reset for your account by a system administrator.\n\n"
            f"Administrator: {admin_user.email}\n"
            f"Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n"
            f"IMPORTANT: Please log out and log back in immediately for this change to take full effect.\n\n"
            f"You will need to set up 2FA again if your organization requires it.\n\n"
            f"If you did not request this change, please contact your administrator immediately.\n\n"
            f"Best regards,\n"
            f"Lazeport Security Team"
        )
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"Failed to send 2FA reset email to {target_user.email}: {e}")
    
    return {
        "success": True,
        "message": f"2FA has been reset for user {target_user.email}"
    }


# ── Teams (formerly Clients) ─────────────────────────────────────────────────

@router.get("/clients")
def list_clients(
    request: Request,
    query: Optional[str] = None,
    include_inactive: bool = False,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """List all clients in the user's organization (or all clients for system admins)."""
    from collections import Counter

    if user.role == "admin":
        clients = list(adapter.list_clients(query=query, include_inactive=include_inactive))
        reports = list(adapter.list_reports())
    else:
        org_id = get_org_id_from_request(request, user, adapter)
        if not org_id:
            raise HTTPException(status_code=403, detail="You are not a member of any organization")
        clients = list(adapter.list_clients(query=query, organization_id=org_id, include_inactive=include_inactive))
        reports = list(adapter.list_reports(organization_id=org_id))

    counts = Counter(r.client_id for r in reports if r.client_id)
    return [{**c.model_dump(), "report_count": counts.get(c.id, 0)} for c in clients]


@router.post("/clients")
@require_organization_admin()
def create_client(
    payload: TeamPayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Create a new client (org_admin or org_owner only)."""
    from app.services.rbac import get_org_id_from_request
    
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Team name required")
    
    # HIGH-3 fix: Get user's organization and pass it to create_client
    org_id = get_org_id_from_request(request, user, adapter)
    if not org_id:
        raise HTTPException(status_code=403, detail="You are not a member of any organization")

    client = adapter.create_client(name=name, organization_id=org_id)

    # Audit log
    log_create(adapter, org_id, user.id, "client", client.id, request, name=name)

    return client


@router.put("/clients/{client_id}")
def update_client(
    client_id: str,
    payload: TeamPayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Team name required")
    existing = _get_client_or_404(client_id, user, adapter)
    org_id = existing.organization_id or _ensure_system_org_id(adapter)
    
    # Check permissions: only org_admin, org_owner, or system admin can update clients
    if user.role != "admin":
        user_role = get_user_role_in_org(user.id, org_id, adapter)
        if user_role not in ("org_admin", "org_owner"):
            raise HTTPException(status_code=403, detail="Only organization admins can update clients")
    
    client = adapter.update_client(client_id, name)
    if not client:
        raise HTTPException(status_code=404, detail="Team not found")
    log_update(
        adapter,
        org_id,
        user.id,
        "client",
        client_id,
        request,
        old_name=existing.name,
        new_name=name,
    )
    return client


@router.delete("/clients/{client_id}")
def delete_client(
    client_id: str,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Delete a client (org_admin or org_owner only)."""
    client = _get_client_or_404(client_id, user, adapter)
    org_id = client.organization_id or _ensure_system_org_id(adapter)
    
    # Check permissions: only org_admin, org_owner, or system admin can delete clients
    if user.role != "admin":
        from app.services.rbac import get_user_role_in_org
        user_role = get_user_role_in_org(user.id, org_id, adapter)
        if user_role not in ("org_admin", "org_owner"):
            raise HTTPException(status_code=403, detail="Only organization admins can delete clients")

    ok = adapter.delete_client(client_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Team not found")

    # Audit log
    log_delete(adapter, org_id, user.id, "client", client_id, request, name=client.name)

    return {"ok": True}


# ── Applications ─────────────────────────────────────────────────────────────

@router.get("/applications")
def list_applications(
    request: Request,
    query: Optional[str] = None,
    enriched: bool = False,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """List all applications in the user's organization.

    Pass ``?enriched=true`` to include report counts and client usage.
    """
    org_id = get_org_id_from_request(request, user, adapter)
    if not org_id:
        raise HTTPException(status_code=403, detail="You are not a member of any organization")
    apps = list(adapter.list_applications(query=query, organization_id=org_id))
    if not enriched:
        return apps

    # Build enriched response with report/client data per application
    reports = list(adapter.list_reports(organization_id=org_id))
    
    # Filter reports by creator for consultants and readonly users
    user_role = None
    if user.role != "admin":
        user_role = get_user_role_in_org(user.id, org_id, adapter)
        if user_role in ("consultant", "readonly"):
            reports = [r for r in reports if r.created_by == user.id]
    
    clients = {t.id: (t.name if t.is_active else f"{t.name} (inactive)") for t in adapter.list_clients(organization_id=org_id, include_inactive=True)}

    # Pre-compute finding counts per report to avoid N+1 queries
    finding_counts: dict[str, int] = {}
    for r in reports:
        finding_counts[r.id] = len(list(adapter.list_findings(r.id)))

    result = []
    for app in apps:
        app_reports = [r for r in reports if r.application_id == app.id]
        client_ids = set(r.client_id for r in app_reports)
        client_names = sorted(clients.get(tid, "Unknown") for tid in client_ids)
        total_findings = sum(finding_counts.get(r.id, 0) for r in app_reports)
        # Find the most recent report by created_at
        latest = max(app_reports, key=lambda r: r.created_at, default=None)
        result.append({
            **app.model_dump(),
            "report_count": len(app_reports),
            "finding_count": total_findings,
            "clients": client_names,
            "last_report": latest.created_at.isoformat() if latest else None,
            "last_report_id": latest.id if latest else None,
        })
    return result


@router.post("/applications")
@require_organization_admin()
def create_application(
    payload: ApplicationPayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Create a new application (org_admin or org_owner only)."""
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Application name required")

    org_id = get_org_id_from_request(request, user, adapter)
    if not org_id:
        raise HTTPException(status_code=403, detail="You are not a member of any organization")

    application = adapter.create_application(
        name=name,
        type=payload.type,
        description=payload.description or "",
        organization_id=org_id,
    )

    log_create(adapter, org_id, user.id, "application", application.id, request, name=name)

    return application


@router.put("/applications/{app_id}")
def update_application(
    app_id: str,
    payload: ApplicationPayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Application name required")
    existing = _get_application_or_404(app_id, user, adapter)
    org_id = existing.organization_id or _ensure_system_org_id(adapter)
    
    # Check permissions: only org_admin, org_owner, or system admin can update applications
    if user.role != "admin":
        user_role = get_user_role_in_org(user.id, org_id, adapter)
        if user_role not in ("org_admin", "org_owner"):
            raise HTTPException(status_code=403, detail="Only organization admins can update applications")
    
    application = adapter.update_application(
        app_id, name, type=payload.type, description=payload.description or "",
    )
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")
    log_update(
        adapter,
        org_id,
        user.id,
        "application",
        app_id,
        request,
        old_name=existing.name,
        new_name=name,
    )
    return application


@router.delete("/applications/{app_id}")
def delete_application(
    app_id: str,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Delete an application (org_admin or org_owner only)."""
    application = _get_application_or_404(app_id, user, adapter)
    org_id = application.organization_id or _ensure_system_org_id(adapter)
    
    # Check permissions: only org_admin, org_owner, or system admin can delete applications
    if user.role != "admin":
        user_role = get_user_role_in_org(user.id, org_id, adapter)
        if user_role not in ("org_admin", "org_owner"):
            raise HTTPException(status_code=403, detail="Only organization admins can delete applications")

    ok = adapter.delete_application(app_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Application not found")

    log_delete(adapter, org_id, user.id, "application", app_id, request, name=application.name)

    return {"ok": True}


# ── Reports ──────────────────────────────────────────────────────────────────

@router.get("/reports")
def list_reports(
    request: Request,
    client_id: Optional[str] = None,
    application_id: Optional[str] = None,
    query: Optional[str] = None,
    tag: Optional[str] = None,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """List reports, optionally filtered by client, application, and/or tag name."""
    org_id = get_org_id_from_request(request, user, adapter)
    if not org_id:
        raise HTTPException(status_code=403, detail="You are not a member of any organization")
    user_role = get_user_role_in_org(user.id, org_id, adapter)
    if not user_role and user.role != "admin":
        raise HTTPException(status_code=403, detail="You are not a member of this organization")

    reports = list(adapter.list_reports(
        client_id=client_id,
        application_id=application_id,
        organization_id=org_id,
        query=query,
        tag_name=_validate_tag_query(tag),
    ))
    
    # Filter by view permission
    if user_role not in ("org_admin", "org_owner", "admin") and user.role != "admin":
        reports = [r for r in reports if can_view_report(user, r, adapter)]

    # Bulk-load findings to compute per-report counts and severity breakdown
    from collections import defaultdict
    report_ids = [r.id for r in reports]
    findings_bulk = list(adapter.list_findings_bulk(report_ids)) if report_ids else []
    finding_counts: dict[str, int] = defaultdict(int)
    sev_breakdowns: dict[str, dict] = defaultdict(lambda: defaultdict(int))
    for f in findings_bulk:
        finding_counts[f.report_id] += 1
        content = _parse_finding_content_safe(f.content_json, f.id)
        sev = (content.get("Severity") or "").strip()
        if sev:
            sev_breakdowns[f.report_id][sev] += 1

    # Add permission flags and finding stats for frontend
    result = []
    for r in reports:
        report_dict = r.model_dump() if hasattr(r, 'model_dump') else (r.dict() if hasattr(r, 'dict') else r.__dict__)
        report_dict['can_edit'] = can_edit_report(user, r, adapter)
        report_dict['can_manage_shares'] = can_manage_report_shares(user, r, adapter)
        report_dict['finding_count'] = finding_counts[r.id]
        report_dict['severity_breakdown'] = dict(sev_breakdowns[r.id])
        result.append(report_dict)

    return result


@router.get("/reports/{report_id}")
def get_report(
    report_id: str,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    report = _require_report_view(report_id, user, adapter)
    report_dict = report.model_dump() if hasattr(report, "model_dump") else (report.dict() if hasattr(report, "dict") else report.__dict__.copy())
    report_dict["can_edit"] = can_edit_report(user, report, adapter)
    report_dict["can_manage_shares"] = can_manage_report_shares(user, report, adapter)
    return report_dict


@router.post("/reports")
def create_report(
    payload: ReportPayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Create a new report. Team and application are optional (report-first flow)."""
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Report name required")

    org_id = _ensure_system_org_id(adapter)
    if payload.client_id:
        client = adapter.get_client(payload.client_id)
        if not client:
            raise HTTPException(status_code=404, detail="Team not found")
        org_id = client.organization_id or org_id
    if payload.application_id:
        application = adapter.get_application(payload.application_id)
        if not application:
            raise HTTPException(status_code=404, detail="Application not found")
        app_org = application.organization_id or _ensure_system_org_id(adapter)
        if payload.client_id:
            client_org = adapter.get_client(payload.client_id).organization_id or org_id
            if client_org != app_org:
                raise HTTPException(
                    status_code=400,
                    detail="Team and application must belong to the same organization"
                )
        org_id = app_org

    # Use user's first org when both client and app are unset
    if not payload.client_id and not payload.application_id:
        orgs = list(adapter.get_user_organizations(user.id))
        org_id = orgs[0].id if orgs else org_id

    user_role = get_user_role_in_org(user.id, org_id, adapter)
    if not user_role and user.role != "admin":
        raise HTTPException(status_code=403, detail="You are not a member of this organization")
    if user_role and not has_permission(user_role, ["consultant"]):
        raise HTTPException(status_code=403, detail="Insufficient permissions to create reports")

    report = adapter.create_report(
        name=name,
        organization_id=org_id,
        created_by=user.id,
        client_id=payload.client_id,
        application_id=payload.application_id,
    )

    log_create(adapter, org_id, user.id, "report", report.id, request, name=name, client_id=payload.client_id, application_id=payload.application_id)

    return report


@router.put("/reports/{report_id}")
def update_report(
    report_id: str,
    payload: ReportUpdatePayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Report name required")
    existing = _require_report_edit(report_id, user, adapter)
    report_org = existing.organization_id or _ensure_system_org_id(adapter)
    updates = payload.model_dump(exclude_unset=True)
    client_id = updates.get("client_id")
    application_id = updates.get("application_id")
    if client_id:
        client = adapter.get_client(client_id)
        if not client:
            raise HTTPException(status_code=404, detail="Team not found")
        client_org = client.organization_id or _ensure_system_org_id(adapter)
        if client_org != report_org:
            raise HTTPException(status_code=403, detail="Team does not belong to this organization")
    if application_id:
        app = adapter.get_application(application_id)
        if not app:
            raise HTTPException(status_code=404, detail="Application not found")
        app_org = app.organization_id or _ensure_system_org_id(adapter)
        if app_org != report_org:
            raise HTTPException(status_code=403, detail="Application does not belong to this organization")
    report = adapter.update_report(report_id, **updates)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    org_id = report.organization_id or _ensure_system_org_id(adapter)
    log_update(
        adapter,
        org_id,
        user.id,
        "report",
        report_id,
        request,
        old_name=existing.name,
        new_name=name,
    )
    return report


@router.patch("/reports/{report_id}/summaries")
def update_report_summaries(
    report_id: str,
    payload: ReportSummariesPayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    _require_report_edit(report_id, user, adapter)
    report = adapter.update_report_summaries(
        report_id,
        summary_executive=payload.summary_executive,
        summary_technical=payload.summary_technical,
        summary_recommendations=payload.summary_recommendations,
    )
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    updated_sections = [
        name
        for name, value in (
            ("summary_executive", payload.summary_executive),
            ("summary_technical", payload.summary_technical),
            ("summary_recommendations", payload.summary_recommendations),
        )
        if value is not None
    ]
    org_id = report.organization_id or _ensure_system_org_id(adapter)
    log_update(
        adapter,
        org_id,
        user.id,
        "report_summaries",
        report_id,
        request,
        sections=updated_sections,
    )
    return report


@router.delete("/reports/{report_id}")
def delete_report(
    report_id: str,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Delete a report and all associated findings."""
    # Get report first for audit log
    report = _require_report_edit(report_id, user, adapter)
    
    org_id = report.organization_id or SYSTEM_ORG_ID
    
    ok = adapter.delete_report(report_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Audit log
    log_delete(adapter, org_id, user.id, "report", report_id, request, name=report.name)
    
    return {"ok": True}


@router.get("/reports/{report_id}/shares")
def list_report_shares(
    report_id: str,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    report = _get_report_or_404(report_id, adapter)
    if not can_manage_report_shares(user, report, adapter):
        raise HTTPException(status_code=403, detail="Insufficient permissions to manage shares")

    org_id = report.organization_id or _ensure_system_org_id(adapter)
    shares = adapter.list_report_shares(report_id)
    result = []
    for share in shares:
        user_obj = adapter.get_user_by_id(share.user_id)
        shared_by_user = adapter.get_user_by_id(share.shared_by)
        user_role = get_user_role_in_org(share.user_id, org_id, adapter)
        result.append({
            "user_id": share.user_id,
            "email": user_obj.email if user_obj else "",
            "name": user_obj.name if user_obj else "",
            "role": user_role,
            "shared_by": share.shared_by,
            "shared_by_email": shared_by_user.email if shared_by_user else "",
            "shared_by_name": shared_by_user.name if shared_by_user else "",
            "shared_at": share.created_at.isoformat() if share.created_at else None,
        })
    return result


@router.get("/reports/{report_id}/share-candidates")
def list_report_share_candidates(
    report_id: str,
    query: str = "",
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    report = _get_report_or_404(report_id, adapter)
    if not can_manage_report_shares(user, report, adapter):
        raise HTTPException(status_code=403, detail="Insufficient permissions to manage shares")

    org_id = report.organization_id or _ensure_system_org_id(adapter)
    members = adapter.list_organization_members(org_id)
    shares = adapter.list_report_shares(report_id)
    shared_ids = {share.user_id for share in shares}
    query_lower = query.strip().lower()

    candidates = []
    for member in members:
        if member.user_id in shared_ids:
            continue
        if report.created_by and member.user_id == report.created_by:
            continue
        user_obj = adapter.get_user_by_id(member.user_id)
        if not user_obj or not user_obj.email:
            continue
        hay = f"{user_obj.name} {user_obj.email}".lower()
        if query_lower and query_lower not in hay:
            continue
        candidates.append({
            "user_id": user_obj.id,
            "email": user_obj.email,
            "name": user_obj.name,
            "role": member.role,
        })

    return candidates


@router.post("/reports/{report_id}/shares")
def create_report_share(
    report_id: str,
    payload: ReportSharePayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    report = _get_report_or_404(report_id, adapter)
    if not can_manage_report_shares(user, report, adapter):
        raise HTTPException(status_code=403, detail="Insufficient permissions to manage shares")

    if not payload.user_id and not payload.email:
        raise HTTPException(status_code=400, detail="Provide user_id or email")

    target_user = None
    if payload.user_id:
        target_user = adapter.get_user_by_id(payload.user_id)
    elif payload.email:
        target_user = adapter.get_user_by_email(payload.email)

    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    if not target_user.email:
        raise HTTPException(status_code=400, detail="Target user must have an email set")

    org_id = report.organization_id or _ensure_system_org_id(adapter)
    target_role = get_user_role_in_org(target_user.id, org_id, adapter)
    if not target_role:
        raise HTTPException(status_code=400, detail="User is not a member of this organization")

    existing = adapter.get_report_share(report.id, target_user.id)
    if existing:
        return {"status": "exists"}

    share = adapter.create_report_share(report.id, target_user.id, user.id)
    log_create(
        adapter,
        org_id,
        user.id,
        "report_share",
        share.id,
        request,
        report_id=report.id,
        target_email=target_user.email,
        target_user_id=target_user.id,
    )

    subject = f"Report shared: {report.name}"
    body = (
        f"{user.name or user.email} shared a report with you.\n\n"
        f"Report: {report.name}\n"
    )
    send_org_email(adapter, org_id, target_user.email, subject, body)

    return {"status": "shared"}


@router.delete("/reports/{report_id}/shares/{user_id}")
def delete_report_share(
    report_id: str,
    user_id: str,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    report = _get_report_or_404(report_id, adapter)
    if not can_manage_report_shares(user, report, adapter):
        raise HTTPException(status_code=403, detail="Insufficient permissions to manage shares")

    ok = adapter.delete_report_share(report_id, user_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Share not found")

    org_id = report.organization_id or _ensure_system_org_id(adapter)
    log_delete(
        adapter,
        org_id,
        user.id,
        "report_share",
        user_id,
        request,
        report_id=report.id,
    )
    return {"ok": True}


@router.get("/reports/{report_id}/import-queue")
def get_import_queue(
    report_id: str,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """List Burp import sessions for this report with their tasks (for resume support)."""
    _require_report_view(report_id, user, adapter)
    sessions = list(adapter.list_burp_sessions_for_report(report_id))
    result = []
    for s in sessions:
        tasks = json.loads(s.tasks_json) if s.tasks_json else []
        tasks, changed = _mark_stale_generating_as_failed(tasks)
        if changed:
            adapter.update_burp_session_tasks(s.id, json.dumps(tasks))
        result.append({
            "session_id": s.id,
            "file_name": s.file_name,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "tasks": tasks,
        })
    return {"sessions": result}


@router.get("/import-queue/pending")
def get_pending_imports(
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """List all Burp import sessions with pending/generating tasks for the user's org."""
    org_id = get_org_id_from_request(request, user, adapter)
    if not org_id:
        raise HTTPException(status_code=403, detail="You are not a member of any organization")
    sessions = adapter.list_burp_sessions_with_pending(org_id)
    result = []
    for s in sessions:
        report = adapter.get_report(s.report_id)
        if not report or not can_view_report(user, report, adapter):
            continue
        tasks = json.loads(s.tasks_json) if s.tasks_json else []
        tasks, changed = _mark_stale_generating_as_failed(tasks)
        if changed:
            adapter.update_burp_session_tasks(s.id, json.dumps(tasks))
        result.append({
            "session_id": s.id,
            "report_id": s.report_id,
            "file_name": s.file_name,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "tasks": tasks,
        })
    return {"sessions": result}


class ImportTaskStatusPayload(BaseModel):
    status: str  # pending | generating | completed | skipped | failed


class BurpImportEnqueuePayload(BaseModel):
    session_id: str
    task_indices: list[int]
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    llm_base_url: Optional[str] = None
    llm_timeout: Optional[float] = None
    sampling_params: Optional[dict] = None


class ResetAndEnqueuePayload(BaseModel):
    task_indices: list[int]
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    llm_base_url: Optional[str] = None
    llm_timeout: Optional[float] = None
    sampling_params: Optional[dict] = None


@router.post("/import-sessions/{session_id}/reset-and-enqueue")
def reset_and_enqueue_burp_import_tasks(
    session_id: str,
    payload: ResetAndEnqueuePayload,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """LOW-3: Atomically set tasks to pending and enqueue them (no reset-then-enqueue race)."""
    sess = adapter.get_burp_import_session(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Import session not found")
    _require_report_edit(sess.report_id, user, adapter)

    tasks = json.loads(sess.tasks_json) if sess.tasks_json else []
    # 1) Atomically set requested tasks to pending
    pending_updates = {}
    for idx in payload.task_indices:
        if 0 <= idx < len(tasks):
            pending_updates[idx] = {"status": "pending", "generating_since": None}
    if not pending_updates:
        return {"enqueued": 0}

    updated_sess = adapter.update_burp_session_tasks_atomic(session_id, pending_updates)
    if not updated_sess:
        return {"enqueued": 0}
    tasks = json.loads(updated_sess.tasks_json) if updated_sess.tasks_json else []

    # 2) Enqueue (same logic as enqueue_burp_import_tasks)
    from app.tasks.burp_import import generate_burp_finding_task

    selected_provider = str(payload.llm_provider or "openai").strip().lower()
    if getattr(adapter, "get_user_provider_api_key", None):
        llm_api_key = adapter.get_user_provider_api_key(user.id, selected_provider)
    else:
        user_key = adapter.get_user_openai_api_key(user.id) if getattr(adapter, "get_user_openai_api_key", None) else None
        llm_api_key = user_key if selected_provider == "openai" else None

    task_updates = {}
    indices_to_dispatch = []
    for idx in payload.task_indices:
        if idx < 0 or idx >= len(tasks):
            continue
        t = tasks[idx]
        if t.get("status") not in ("pending", "failed"):
            continue
        task_updates[idx] = {"status": "generating", "generating_since": int(time.time() * 1000)}
        indices_to_dispatch.append(idx)

    # Commit generating status BEFORE dispatching so Celery never races the DB write.
    if task_updates:
        adapter.update_burp_session_tasks_atomic(session_id, task_updates)

    from app.tasks.llm_generation import TOTAL_STEPS
    _report = adapter.get_report(sess.report_id)
    user_org_id = (_report.organization_id if _report else None) or "default"

    for idx in indices_to_dispatch:
        t = tasks[idx]
        finding_name = (t.get("finding", {}).get("name") or f"Finding {idx + 1}")[:80]
        gt = adapter.create_generation_task(
            user_id=user.id,
            organization_id=user_org_id,
            report_id=sess.report_id,
            task_type="import_finding",
            title=f"Importing: {finding_name}",
            total_steps=TOTAL_STEPS["import_finding"],
        )
        generate_burp_finding_task.delay(
            session_id,
            idx,
            llm_provider=payload.llm_provider,
            llm_model=payload.llm_model,
            llm_base_url=payload.llm_base_url,
            llm_api_key=llm_api_key,
            llm_timeout=payload.llm_timeout,
            sampling_params=payload.sampling_params,
            generation_task_id=gt.id,
        )

    return {"enqueued": len(indices_to_dispatch)}


@router.post("/burp-import/enqueue")
def enqueue_burp_import_tasks(
    payload: BurpImportEnqueuePayload,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Enqueue Burp import tasks for server-side processing. Survives page refresh."""
    sess = adapter.get_burp_import_session(payload.session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Import session not found")
    _require_report_edit(sess.report_id, user, adapter)
    
    # Read tasks to determine what to enqueue
    tasks = json.loads(sess.tasks_json) if sess.tasks_json else []
    from app.tasks.burp_import import generate_burp_finding_task

    # Use DB-stored user key only when it matches selected provider.
    selected_provider = str(payload.llm_provider or "openai").strip().lower()
    if getattr(adapter, "get_user_provider_api_key", None):
        llm_api_key = adapter.get_user_provider_api_key(user.id, selected_provider)
    else:
        user_key = adapter.get_user_openai_api_key(user.id) if getattr(adapter, "get_user_openai_api_key", None) else None
        llm_api_key = user_key if selected_provider == "openai" else None

    # Prepare atomic updates for all tasks being enqueued
    task_updates = {}
    indices_to_dispatch = []

    for idx in payload.task_indices:
        if idx < 0 or idx >= len(tasks):
            continue
        t = tasks[idx]
        if t.get("status") not in ("pending", "failed"):
            continue
        task_updates[idx] = {"status": "generating", "generating_since": int(time.time() * 1000)}
        indices_to_dispatch.append(idx)

    # Commit generating status BEFORE dispatching so Celery never races the DB write.
    if task_updates:
        adapter.update_burp_session_tasks_atomic(payload.session_id, task_updates)

    from app.tasks.llm_generation import TOTAL_STEPS
    _report = adapter.get_report(sess.report_id)
    user_org_id = (_report.organization_id if _report else None) or "default"

    for idx in indices_to_dispatch:
        # Create a GenerationTask so the TaskBar shows import progress
        t = tasks[idx]
        finding_name = (t.get("finding", {}).get("name") or f"Finding {idx + 1}")[:80]
        gt = adapter.create_generation_task(
            user_id=user.id,
            organization_id=user_org_id,
            report_id=sess.report_id,
            task_type="import_finding",
            title=f"Importing: {finding_name}",
            total_steps=TOTAL_STEPS["import_finding"],
        )
        generate_burp_finding_task.delay(
            payload.session_id,
            idx,
            llm_provider=payload.llm_provider,
            llm_model=payload.llm_model,
            llm_base_url=payload.llm_base_url,
            llm_api_key=llm_api_key,
            llm_timeout=payload.llm_timeout,
            sampling_params=payload.sampling_params,
            generation_task_id=gt.id,
        )

    return {"enqueued": len(indices_to_dispatch)}


@router.patch("/import-sessions/{session_id}/tasks/{task_index}")
def update_import_task_status(
    session_id: str,
    task_index: int,
    payload: ImportTaskStatusPayload,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Update a task's status in a Burp import session."""
    # MED-1 fix: Use atomic single-task update method instead of read-modify-write
    sess = adapter.get_burp_import_session(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Import session not found")
    _require_report_edit(sess.report_id, user, adapter)
    status_val = payload.status.strip().lower()
    if status_val not in ("pending", "generating", "completed", "skipped", "failed"):
        raise HTTPException(status_code=400, detail="Invalid status")
    
    # Use atomic update method that handles locking internally
    updated_sess = adapter.update_burp_session_task_status(session_id, task_index, status_val)
    if not updated_sess:
        raise HTTPException(status_code=404, detail="Task not found")
    
    tasks = json.loads(updated_sess.tasks_json) if updated_sess.tasks_json else []
    return {"ok": True, "tasks": tasks}


@router.post("/import-sessions/{session_id}/cancel-pending")
def cancel_pending_import_tasks(
    session_id: str,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Cancel remaining import work by skipping pending/failed tasks only."""
    sess = adapter.get_burp_import_session(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Import session not found")
    _require_report_edit(sess.report_id, user, adapter)

    tasks = json.loads(sess.tasks_json) if sess.tasks_json else []
    task_updates: dict[int, dict] = {}
    cancelled = 0
    left_generating = 0
    left_completed = 0

    for idx, task in enumerate(tasks):
        status = str(task.get("status", "")).strip().lower()
        if status in ("pending", "failed"):
            task_updates[idx] = {"status": "skipped", "generating_since": None}
            cancelled += 1
        elif status == "generating":
            left_generating += 1
        elif status == "completed":
            left_completed += 1

    if task_updates:
        updated = adapter.update_burp_session_tasks_atomic(session_id, task_updates)
        tasks = json.loads(updated.tasks_json) if (updated and updated.tasks_json) else tasks

    return {
        "ok": True,
        "cancelled": cancelled,
        "left_generating": left_generating,
        "left_completed": left_completed,
        "tasks": tasks,
    }


@router.post("/findings")
def create_finding(
    payload: FindingPayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Create a new finding in a report."""
    report = _require_report_edit(payload.report_id, user, adapter)
    content_dict = _strip_internal_content_keys(payload.content or {})
    content_json = json.dumps(content_dict)
    
    # Build evidence_payload from notes if present (manual findings)
    evidence_payload_str = ""
    if payload.notes and payload.notes.strip():
        from app.services.evidence_schema import build_payload_from_notes
        evidence_payload = build_payload_from_notes(payload.notes)
        evidence_payload_str = evidence_payload.to_json()
    
    finding = adapter.create_finding(
        report_id=payload.report_id,
        title=payload.title or "",
        content_json=content_json,
        notes=payload.notes or "",
        template=payload.template or "",
        evidence_payload=evidence_payload_str,
    )
    
    # Audit log
    org_id = report.organization_id or SYSTEM_ORG_ID
    log_create(adapter, org_id, user.id, "finding", finding.id, request, title=payload.title, report_id=payload.report_id)
    
    return finding


@router.get("/findings")
def list_findings(
    report_id: str,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    _require_report_view(report_id, user, adapter)
    return list(adapter.list_findings(report_id))


@router.get("/findings/{finding_id}")
def get_finding(
    finding_id: str,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    finding = adapter.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    _require_report_view(finding.report_id, user, adapter)
    return finding


class FindingUpdatePayload(BaseModel):
    title: str | None = None
    content_json: str | None = None
    notes: str | None = None
    template: str | None = None
    validation_guidance: str | None = None

    @field_validator('title')
    @classmethod
    def validate_title(cls, v):
        if v is None:
            return v
        from app.validation import sanitize_string, MAX_TITLE_LENGTH
        # Use sanitize_string directly (not title_validator) because finding titles
        # naturally contain security keywords like "SQL Injection", "Script", etc.
        return sanitize_string(v, MAX_TITLE_LENGTH)

    @field_validator('content_json')
    @classmethod
    def validate_content_json(cls, v):
        """
        MED-16: Validate content_json is valid JSON with flat string values.
        
        content_json should be a JSON-encoded dict with string values only.
        """
        if v is None:
            return v
        
        # Check length and printable chars first
        v = ValidatedString.content_validator(v)
        
        # Parse and validate JSON structure
        import json as _json
        try:
            parsed = _json.loads(v)
        except _json.JSONDecodeError as e:
            raise ValueError(f"content_json must be valid JSON: {e}")
        
        if not isinstance(parsed, dict):
            raise ValueError("content_json must be a JSON object (dict)")
        
        # Validate it's a flat dict with string values
        for key, value in parsed.items():
            if not isinstance(key, str):
                raise ValueError(f"All keys must be strings, got {type(key).__name__}")
            
            if value is not None and not isinstance(value, str):
                raise ValueError(
                    f"Field '{key}' has non-string value (type: {type(value).__name__}). "
                    "All content values must be strings."
                )
        
        return v

    @field_validator('notes')
    @classmethod
    def validate_notes(cls, v):
        if v is None:
            return v
        return ValidatedString.notes_validator(v)

    @field_validator('validation_guidance')
    @classmethod
    def validate_validation_guidance(cls, v):
        if v is None:
            return v
        return ValidatedString.notes_validator(v)


@router.put("/findings/{finding_id}")
def update_finding(
    finding_id: str,
    payload: FindingUpdatePayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    import json as _json
    from app.services.evidence_structurer import SYSTEM_OWNED_FIELDS
    
    existing = adapter.get_finding(finding_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Finding not found")
    _require_report_edit(existing.report_id, user, adapter)
    
    # HIGH-9 fix: Preserve existing values when fields are omitted (None)
    updated_content_json = payload.content_json if payload.content_json is not None else existing.content_json
    
    # HIGH-10 fix: Protect system-owned fields from user modification
    if existing.evidence_payload and updated_content_json:
        try:
            from app.services.evidence_schema import EvidencePayload

            # Parse evidence to get system-managed values (LOW-9: validation raises clear error)
            evidence_payload = EvidencePayload.from_json(existing.evidence_payload)

            # Extract affected files from evidence
            affected_files = []
            for loc in evidence_payload.locations:
                if loc.file:
                    if loc.line:
                        affected_files.append(f"{loc.file}:{loc.line}")
                    else:
                        affected_files.append(loc.file)

            # Deduplicate while preserving order
            seen = set()
            unique_files = []
            for f in affected_files:
                if f not in seen:
                    seen.add(f)
                    unique_files.append(f)

            # Parse user's content_json and enforce system fields
            content_dict = _json.loads(updated_content_json)
            content_dict = _strip_internal_content_keys(content_dict)

            # Force-set system-owned fields from evidence
            for field in SYSTEM_OWNED_FIELDS:
                if field == "Affected Files":
                    content_dict[field] = "\n".join(unique_files)

            # Re-serialize
            updated_content_json = _json.dumps(content_dict)
        except ValueError as e:
            # LOW-9: Surface validation errors to user
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            log.warning("Could not enforce system fields: %s", e)
            raise HTTPException(
                status_code=400,
                detail="Evidence payload could not be parsed. Please regenerate the finding from source.",
            )
    else:
        # Strip internal keys from content before save when not in evidence-enforce path
        if updated_content_json:
            try:
                content_dict = _json.loads(updated_content_json)
                content_dict = _strip_internal_content_keys(content_dict)
                updated_content_json = _json.dumps(content_dict)
            except Exception as e:
                log.warning("Failed to strip internal keys from finding content (finding_id=%s): %s", finding_id, type(e).__name__)
    
    finding = adapter.update_finding(
        finding_id=finding_id,
        title=payload.title if payload.title is not None else existing.title,
        content_json=updated_content_json,
        notes=payload.notes if payload.notes is not None else existing.notes,
        template=payload.template if payload.template is not None else existing.template,
        validation_guidance=payload.validation_guidance if payload.validation_guidance is not None else existing.validation_guidance,
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    org_id = finding.organization_id or _ensure_system_org_id(adapter)
    log_update(
        adapter,
        org_id,
        user.id,
        "finding",
        finding_id,
        request,
        old_title=existing.title,
        new_title=finding.title,
    )
    return finding


@router.delete("/findings/{finding_id}")
def delete_finding(
    finding_id: str,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Delete a finding."""
    # Get finding first for audit log
    finding = adapter.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    _require_report_edit(finding.report_id, user, adapter)
    
    org_id = finding.organization_id or SYSTEM_ORG_ID
    
    ok = adapter.delete_finding(finding_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    # Audit log
    log_delete(adapter, org_id, user.id, "finding", finding_id, request, title=finding.title)
    
    return {"ok": True}


def _user_api_key_for_provider(
    user,
    adapter: StorageAdapter,
    provider_override: str | None,
) -> str | None:
    """
    Return the stored user API key only when it matches the selected provider.
    Prevents cross-provider key use (e.g. DeepSeek key sent to OpenAI).
    """
    effective_provider = str(provider_override or "openai").strip().lower()
    if getattr(adapter, "get_user_provider_api_key", None):
        return adapter.get_user_provider_api_key(user.id, effective_provider)
    # Fallback for older adapters without multi-provider support
    key = (
        adapter.get_user_openai_api_key(user.id)
        if getattr(adapter, "get_user_openai_api_key", None)
        else None
    )
    return key if effective_provider == "openai" else None


class ValidationGuidancePayload(BaseModel):
    """Request payload for generating validation guidance."""
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    base_url: Optional[str] = None
    
    @field_validator('llm_model', 'base_url')
    @classmethod
    def empty_string_to_none(cls, v):
        """Convert empty strings to None."""
        if v is None:
            return None
        if isinstance(v, str) and not v.strip():
            return None
        return v


@router.get("/findings/{finding_id}/validation-guidance")
def get_validation_guidance(
    finding_id: str,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Get cached validation guidance for a finding if it exists."""
    finding = adapter.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    report = adapter.get_report(finding.report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # RBAC check
    if not can_view_report(user, report, adapter):
        raise HTTPException(status_code=403, detail="Access denied")
    
    return {
        "guidance": finding.validation_guidance or None,
        "finding_id": finding_id,
        "finding_title": finding.title or "Untitled Vulnerability"
    }


@router.post("/findings/{finding_id}/validation-guidance")
def generate_validation_guidance(
    finding_id: str,
    payload: ValidationGuidancePayload,
    regenerate: bool = False,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """
    Generate validation guidance/PoC for a finding using LLM.
    
    This endpoint is designed for authorized security testing and provides
    guidance on how to validate findings discovered during penetration tests.
    
    If guidance already exists and regenerate=False, returns cached guidance.
    Set regenerate=True to force re-generation.
    """
    from app.services.llm import chat_completion
    import json as _json
    import logging
    
    log = logging.getLogger(__name__)
    log.info(f"Validation guidance request - finding_id: {finding_id}, regenerate: {regenerate}, payload_provider: {payload.llm_provider}, model: {payload.llm_model}, base_url: {payload.base_url}")
    
    finding = adapter.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    report = adapter.get_report(finding.report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # RBAC check
    if not can_view_report(user, report, adapter):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Return cached guidance if it exists and not forcing regeneration
    if finding.validation_guidance and not regenerate:
        log.info(f"Returning cached validation guidance for finding {finding_id}")
        return {
            "guidance": finding.validation_guidance,
            "finding_id": finding_id,
            "finding_title": finding.title or "Untitled Vulnerability",
            "cached": True
        }
    
    # Use user's saved provider preference if not explicitly provided
    effective_provider = payload.llm_provider or getattr(user, "ai_key_provider", None) or "openai"
    effective_provider = effective_provider.strip().lower()
    log.info(f"Using provider: {effective_provider} (from: {'request' if payload.llm_provider else 'user_profile' if getattr(user, 'ai_key_provider', None) else 'default'})")
    
    # Get user's API key for the provider
    user_api_key = _user_api_key_for_provider(user, adapter, effective_provider)
    
    # Parse finding content (LOW-19: log on parse failure)
    content = _parse_finding_content_safe(finding.content_json, finding.id)
    
    # Extract relevant information from finding
    title = finding.title or "Untitled Vulnerability"
    severity = content.get("Severity", "Unknown")
    summary = content.get("Vulnerability Summary", "")
    impact = content.get("Impact", "")
    affected_resources = content.get("Affected Resources", "")
    
    # Extract evidence if available
    evidence_text = ""
    if finding.evidence_payload:
        try:
            from app.services.evidence_schema import EvidencePayload
            payload_obj = EvidencePayload.from_json(finding.evidence_payload)
            evidence_text = payload_obj.verbatim_text or ""
        except Exception as e:
            log.warning("Failed to parse evidence payload for finding %s: %s", finding_id, type(e).__name__)
    
    # Craft an ethically-framed prompt
    system_prompt = """You are a security testing assistant helping authorized penetration testers validate vulnerabilities.

IMPORTANT CONTEXT:
- The user is an authorized security professional
- They have written permission and rules of engagement
- They are working within legal and ethical boundaries
- This is part of authorized security testing with appropriate insurance coverage
- Your role is to help them validate findings, NOT to facilitate unauthorized access

Your task is to provide VALIDATION GUIDANCE only - clear, actionable steps to verify if the reported vulnerability actually exists. This helps ensure findings are accurate and not false positives."""

    user_prompt = f"""Finding to Validate:
Title: {title}
Severity: {severity}

Summary:
{summary}

Impact:
{impact}

Affected Resources:
{affected_resources}

Evidence:
{evidence_text[:500] if evidence_text else 'No evidence provided'}

Please provide the SIMPLEST way to validate this vulnerability. Use markdown formatting throughout:
- Use `## Section Title` for each section heading
- Use bullet points (`-`) for all steps and lists — do NOT use numbered prose like "Step 1:", "Step 2:"
- Use backticks for commands, payloads, and tool names

Cover:
- **Validation steps**: bullet-point procedure to verify the vulnerability exists
- **Expected result**: what you should observe if it's real
- **Tools / commands**: specific commands or tools (if applicable)
- **Safe testing notes**: any precautions

Focus on validation, not exploitation. Keep it concise and practical."""

    try:
        response_text = chat_completion(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            provider_override=effective_provider,
            model_override=payload.llm_model,
            base_url_override=payload.base_url,
            api_key_override=user_api_key,
            sampling_params={"max_tokens": 600},
        )
        
        # Save the guidance to the finding
        adapter.update_finding(finding_id, validation_guidance=response_text)
        log.info(f"Saved validation guidance for finding {finding_id}")
        
        return {
            "guidance": response_text,
            "finding_id": finding_id,
            "finding_title": title,
            "cached": False
        }
    
    except ValueError as e:
        # LLM configuration or API key issues
        raise HTTPException(status_code=400, detail="LLM configuration error. Please check your provider settings.")
    except Exception as e:
        log.exception("Failed to generate validation guidance for finding %s", finding_id)
        raise HTTPException(status_code=500, detail="Failed to generate guidance. Please try again.")


@router.get("/finding-templates")
def list_finding_templates(
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """List all finding templates (org-specific + global)."""
    org_id = get_org_id_from_request(request, user, adapter)
    if not org_id:
        raise HTTPException(status_code=403, detail="You are not a member of any organization")
    return list(adapter.list_finding_templates(organization_id=org_id))


@router.post("/finding-templates")
def create_finding_template(
    payload: FindingTemplatePayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Create a finding template. Available to all users (consultants can create templates)."""
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Template name required")

    org_id = get_org_id_from_request(request, user, adapter)
    if not org_id:
        raise HTTPException(status_code=403, detail="You are not a member of any organization")

    template = adapter.create_finding_template(name=name, content=payload.content or "", organization_id=org_id)
    log_create(adapter, org_id, user.id, "finding_template", template.id, request, name=name)
    return template


@router.put("/finding-templates/{template_id}")
def update_finding_template(
    template_id: str,
    payload: FindingTemplatePayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    existing = adapter.get_finding_template(template_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Template not found")
    
    org_id = existing.organization_id or _ensure_system_org_id(adapter)
    
    # Check permissions: user must be template creator, org_admin, org_owner, or system admin
    if user.role != "admin":
        verify_resource_org_access(user, org_id, adapter, "finding template")
        user_role = get_user_role_in_org(user.id, org_id, adapter)
        is_creator = existing.created_by == user.id
        if not is_creator and user_role not in ("org_admin", "org_owner"):
            raise HTTPException(status_code=403, detail="You can only edit templates you created or be an organization admin")
    
    t = adapter.update_finding_template(template_id, payload.name.strip(), payload.content or "")
    if not t:
        raise HTTPException(status_code=404, detail="Template not found")
    org_id = t.organization_id or _ensure_system_org_id(adapter)
    log_update(
        adapter,
        org_id,
        user.id,
        "finding_template",
        template_id,
        request,
        old_name=existing.name,
        new_name=payload.name.strip(),
    )
    return t


@router.delete("/finding-templates/{template_id}")
def delete_finding_template(
    template_id: str,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    existing = adapter.get_finding_template(template_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Template not found")
    
    org_id = existing.organization_id or _ensure_system_org_id(adapter)
    
    # Check permissions: user must be template creator, org_admin, org_owner, or system admin
    if user.role != "admin":
        verify_resource_org_access(user, org_id, adapter, "finding template")
        user_role = get_user_role_in_org(user.id, org_id, adapter)
        is_creator = existing.created_by == user.id
        if not is_creator and user_role not in ("org_admin", "org_owner"):
            raise HTTPException(status_code=403, detail="You can only delete templates you created or be an organization admin")
    
    ok = adapter.delete_finding_template(template_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Template not found")
    
    log_delete(adapter, org_id, user.id, "finding_template", template_id, request, name=existing.name)
    return {"ok": True}


@router.post("/master-docx")
def build_master_docx_endpoint(
    payload: MasterDocxPayload,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    from fastapi.responses import StreamingResponse
    from app.services.master_docx import build_master_docx
    import io
    import json as _json

    report = _require_report_view(payload.report_id, user, adapter)
    client = adapter.get_client(report.client_id)
    application = adapter.get_application(report.application_id)
    settings_row = adapter.get_settings()

    findings_raw = adapter.list_findings(payload.report_id)
    findings: list[dict] = []
    for f in findings_raw:
        content = _parse_finding_content_safe(f.content_json, f.id)
        validation_guidance = (f.validation_guidance or "").strip()
        if validation_guidance:
            content["Validation Guidance"] = validation_guidance
        
        # Exclude False Positive findings from reports
        confidence = content.get("Confidence", "").strip()
        if confidence == "False Positive":
            continue
        
        # Attach the DB title so the builder can use it
        findings.append({"_title": f.title or "", "_content": content})
    
    # Get user's organization
    orgs = list(adapter.get_user_organizations(user.id))
    org_id = orgs[0].id if orgs else adapter.ensure_system_org()

    template = adapter.get_master_template(payload.template_name, org_id)
    if not template:
        raise HTTPException(status_code=404, detail="Master template not found")

    try:
        docx_bytes = build_master_docx(
            template_bytes=template.content,
            report_name=report.name,
            client_name=(application.name if application else settings_row.org_name),
            team_name=(client.name if client else ""),
            company_name=user.company_name or "",
            department_name=user.department_name or "",
            author_name=user.name or "",
            author_email=user.contact_email or user.email or "",
            author_phone=user.phone or "",
            author_title=user.title or "",
            findings=findings,
            summaries={
                "SUMMARY_EXECUTIVE": report.summary_executive or "",
                "SUMMARY_TECHNICAL": report.summary_technical or "",
                "SUMMARY_RECOMMENDATIONS": report.summary_recommendations or "",
            },
            locale=payload.locale,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    filename = _safe_filename(f"{report.name}_master.docx")
    return StreamingResponse(
        io.BytesIO(docx_bytes),
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/master-templates/upload")
@require_organization_admin()
async def upload_master_template(
    request: Request,
    file: UploadFile = File(...),
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """
    Upload a master DOCX template.
    
    Security checks:
    - File extension must be .docx
    - Filename must be safe (no path traversal)
    - File size must be under 10MB
    - File must be valid DOCX format (ZIP with specific structure)
    """
    from docx import Document
    
    # Validate filename
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")
    
    if not file.filename.lower().endswith(".docx"):
        raise HTTPException(status_code=400, detail="Only .docx files are accepted")
    
    # Sanitize filename
    try:
        name = ValidatedString.filename_validator(Path(file.filename).stem)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    # Read content with size limit (10MB)
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    content = b""
    bytes_read = 0
    
    while chunk := await file.read(8192):
        bytes_read += len(chunk)
        if bytes_read > MAX_FILE_SIZE:
            raise HTTPException(status_code=413, detail="File size exceeds 10MB limit")
        content += chunk
    
    if not content:
        raise HTTPException(status_code=400, detail="File is empty")
    
    # Validate DOCX structure
    try:
        doc = Document(io.BytesIO(content))
        # Basic validation: ensure it has at least one paragraph or table
        if not doc.paragraphs and not doc.tables:
            raise HTTPException(status_code=400, detail="Invalid DOCX: document is empty")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid DOCX file. Please upload a valid .docx document.")
    
    # Get user's organization (LOW-12: use get_org_id_from_request for consistency)
    user_org_id = get_org_id_from_request(request, user, adapter)
    if not user_org_id:
        raise HTTPException(status_code=403, detail="You are not a member of any organization")
    
    # Check if template exists and update, otherwise create
    existing = adapter.get_master_template(name, user_org_id)
    if existing:
        adapter.update_master_template(name, content, user_org_id)
        org_id = existing.organization_id or _ensure_system_org_id(adapter)
        log_update(adapter, org_id, user.id, "master_template", name, request, name=name)
    else:
        created = adapter.create_master_template(name, content, user_org_id)
        org_id = created.organization_id or _ensure_system_org_id(adapter)
        log_create(adapter, org_id, user.id, "master_template", created.id, request, name=name)
    return {"ok": True, "name": name}


@router.delete("/master-templates/{name}")
@require_organization_admin()
def delete_master_template(
    name: str,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    if ".." in name or "/" in name or "\\" in name:
        raise HTTPException(status_code=400, detail="Invalid template name")
    
    # Get user's organization (LOW-12: use get_org_id_from_request for consistency)
    user_org_id = get_org_id_from_request(request, user, adapter)
    if not user_org_id:
        raise HTTPException(status_code=403, detail="You are not a member of any organization")
    
    existing = adapter.get_master_template(name, user_org_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Master template not found")
    ok = adapter.delete_master_template(name, user_org_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Master template not found")
    org_id = existing.organization_id or _ensure_system_org_id(adapter)
    log_delete(adapter, org_id, user.id, "master_template", name, request, name=name)
    return {"ok": True}


@router.get("/master-templates/{name}/download")
def download_master_template(
    name: str,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Download a master template from the database."""
    from fastapi.responses import StreamingResponse
    if ".." in name or "/" in name or "\\" in name:
        raise HTTPException(status_code=400, detail="Invalid template name")
    
    # Get user's organization
    orgs = list(adapter.get_user_organizations(user.id))
    user_org_id = orgs[0].id if orgs else adapter.ensure_system_org()
    
    template = adapter.get_master_template(name, user_org_id)
    if not template:
        raise HTTPException(status_code=404, detail="Master template not found")
    return StreamingResponse(
        io.BytesIO(template.content),
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{_safe_filename(name)}.docx"'},
    )


@router.get("/master-templates/{name}/tokens")
def get_master_template_tokens(
    name: str,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    if ".." in name or "/" in name or "\\" in name:
        raise HTTPException(status_code=400, detail="Invalid template name")
    
    # Get user's organization
    orgs = list(adapter.get_user_organizations(user.id))
    user_org_id = orgs[0].id if orgs else adapter.ensure_system_org()
    
    template = adapter.get_master_template(name, user_org_id)
    if not template:
        raise HTTPException(status_code=404, detail="Master template not found")
    
    # MED-18: Use Jinja2 parser to extract all template variables
    # Handles dotted paths (report.date), filters (var | upper), etc.
    from docx import Document
    from jinja2 import Environment, meta
    
    doc = Document(io.BytesIO(template.content))
    tokens = set()
    
    # Collect all text from document
    all_text = []
    for para in doc.paragraphs:
        all_text.append(para.text)
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                all_text.append(cell.text)
    for section in doc.sections:
        for hf in (section.header, section.footer, section.first_page_header,
                    section.first_page_footer, section.even_page_header, section.even_page_footer):
            if hf:
                for para in hf.paragraphs:
                    all_text.append(para.text)
                for table in hf.tables:
                    for row in table.rows:
                        for cell in row.cells:
                            all_text.append(cell.text)
    
    # Parse all text with Jinja2 to extract variable references
    env = Environment(autoescape=True)
    combined_text = "\n".join(all_text)
    try:
        ast = env.parse(combined_text)
        tokens = meta.find_undeclared_variables(ast)
    except Exception as e:
        # Fallback to simple regex if Jinja2 parsing fails
        log.warning(f"Jinja2 parsing failed, falling back to regex: {e}")
        pat = r"\{\{\s*([A-Za-z0-9_.]+)\s*\}\}"  # At least allow dots
        for text in all_text:
            tokens.update(re.findall(pat, text))
    
    return {"tokens": sorted(tokens)}


# ── Tags ─────────────────────────────────────────────────────────────────────

TAG_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9 .]+$')
TAG_NAME_MAX_LEN = 50
VALID_ENTITY_TYPES = {"finding", "report", "client", "application"}


def _validate_tag_query(tag: Optional[str]) -> Optional[str]:
    """Accept only tag-shaped query param (same rules as tag names); prevents odd input."""
    if not tag:
        return None
    v = str(tag).strip()
    if not v or len(v) > TAG_NAME_MAX_LEN or not TAG_NAME_PATTERN.match(v):
        return None
    return v


class TagPayload(BaseModel):
    name: str

    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        v = str(v).strip()
        if not v or len(v) > 50:
            raise ValueError("Tag name must be 1-50 characters")
        if not TAG_NAME_PATTERN.match(v):
            raise ValueError("Tag name may only contain letters, numbers, spaces, and periods")
        return v


class TagAssignPayload(BaseModel):
    tag_name: str
    entity_type: str
    entity_id: str

    @field_validator('tag_name')
    @classmethod
    def validate_tag_name(cls, v):
        v = str(v).strip()
        if not v or len(v) > 50:
            raise ValueError("Tag name must be 1-50 characters")
        if not TAG_NAME_PATTERN.match(v):
            raise ValueError("Tag name may only contain letters, numbers, spaces, and periods")
        return v

    @field_validator('entity_type')
    @classmethod
    def validate_entity_type(cls, v):
        v = str(v).strip().lower()
        if v not in VALID_ENTITY_TYPES:
            raise ValueError(f"entity_type must be one of: {', '.join(sorted(VALID_ENTITY_TYPES))}")
        return v

    @field_validator('entity_id')
    @classmethod
    def validate_entity_id(cls, v):
        return ValidatedString.uuid_validator(v)


class TagRemovePayload(BaseModel):
    tag_id: str
    entity_type: str
    entity_id: str

    @field_validator('tag_id', 'entity_id')
    @classmethod
    def validate_ids(cls, v):
        return ValidatedString.uuid_validator(v)

    @field_validator('entity_type')
    @classmethod
    def validate_entity_type(cls, v):
        v = str(v).strip().lower()
        if v not in VALID_ENTITY_TYPES:
            raise ValueError(f"entity_type must be one of: {', '.join(sorted(VALID_ENTITY_TYPES))}")
        return v


@router.get("/tags")
def list_tags(
    request: Request,
    query: Optional[str] = None,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """List tags for the organization, with optional prefix search for auto-suggest."""
    org_id = get_org_id_from_request(request, user, adapter)
    if not org_id:
        raise HTTPException(status_code=403, detail="You are not a member of any organization")
    return list(adapter.list_tags(org_id, query=query))


@router.post("/tags")
def create_tag(
    payload: TagPayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Create a new tag (or return existing if name matches)."""
    org_id = get_org_id_from_request(request, user, adapter)
    if not org_id:
        raise HTTPException(status_code=403, detail="You are not a member of any organization")
    tag = adapter.create_tag(org_id, payload.name, created_by=user.id)
    return tag


# NOTE: /tags/assign and /tags/entity routes MUST be defined BEFORE /tags/{tag_id}
# otherwise FastAPI matches "assign" / "entity" as a tag_id.

@router.post("/tags/assign")
def assign_tag(
    payload: TagAssignPayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Create-or-find a tag by name and assign it to an entity. Single round-trip for the UI."""
    org_id = get_org_id_from_request(request, user, adapter)
    if not org_id:
        raise HTTPException(status_code=403, detail="You are not a member of any organization")
    
    # Verify user has permission to modify this entity
    entity_type = payload.entity_type.strip().lower()
    if entity_type == "client":
        # HIGH-6 fix: Verify client exists and belongs to user's org
        client = adapter.get_client(payload.entity_id)
        if not client:
            raise HTTPException(status_code=404, detail="Team not found")
        client_org_id = client.organization_id or SYSTEM_ORG_ID
        
        if user.role != "admin" and client_org_id != org_id:
            raise HTTPException(
                status_code=403,
                detail="You do not have permission to tag this client"
            )
        
        # Only org_admin/org_owner can tag clients
        if user.role != "admin":
            user_role = get_user_role_in_org(user.id, org_id, adapter)
            if user_role not in ("org_admin", "org_owner"):
                raise HTTPException(status_code=403, detail="Only organization admins can tag clients")
    elif entity_type == "application":
        # HIGH-6 fix: Verify application exists and belongs to user's org
        application = adapter.get_application(payload.entity_id)
        if not application:
            raise HTTPException(status_code=404, detail="Application not found")
        app_org_id = application.organization_id or SYSTEM_ORG_ID
        
        if user.role != "admin" and app_org_id != org_id:
            raise HTTPException(
                status_code=403,
                detail="You do not have permission to tag this application"
            )
        
        # Only org_admin/org_owner can tag applications
        if user.role != "admin":
            user_role = get_user_role_in_org(user.id, org_id, adapter)
            if user_role not in ("org_admin", "org_owner"):
                raise HTTPException(status_code=403, detail="Only organization admins can tag applications")
    elif entity_type == "report":
        report = adapter.get_report(payload.entity_id)
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        if not can_edit_report(user, report, adapter):
            raise HTTPException(status_code=403, detail="You don't have permission to tag this report")
    elif entity_type == "finding":
        finding = adapter.get_finding(payload.entity_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        report = adapter.get_report(finding.report_id)
        if not report or not can_edit_report(user, report, adapter):
            raise HTTPException(status_code=403, detail="You don't have permission to tag this finding")
    
    # Create or find the tag
    tag = adapter.create_tag(org_id, payload.tag_name, created_by=user.id)
    # Assign
    adapter.add_entity_tag(tag.id, payload.entity_type, payload.entity_id, created_by=user.id)
    return {"tag_id": tag.id, "tag_name": tag.name}


@router.delete("/tags/assign")
def unassign_tag(
    payload: TagRemovePayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Remove a tag from an entity."""
    org_id = get_org_id_from_request(request, user, adapter)
    if not org_id:
        raise HTTPException(status_code=403, detail="You are not a member of any organization")
    
    # Verify user has permission to modify this entity
    entity_type = payload.entity_type.strip().lower()
    if entity_type == "client":
        # HIGH-6 fix: Verify client exists and belongs to user's org
        client = adapter.get_client(payload.entity_id)
        if not client:
            raise HTTPException(status_code=404, detail="Team not found")
        client_org_id = client.organization_id or SYSTEM_ORG_ID
        
        if user.role != "admin" and client_org_id != org_id:
            raise HTTPException(
                status_code=403,
                detail="You do not have permission to untag this client"
            )
        
        # Only org_admin/org_owner can untag clients
        if user.role != "admin":
            user_role = get_user_role_in_org(user.id, org_id, adapter)
            if user_role not in ("org_admin", "org_owner"):
                raise HTTPException(status_code=403, detail="Only organization admins can untag clients")
    elif entity_type == "application":
        # HIGH-6 fix: Verify application exists and belongs to user's org
        application = adapter.get_application(payload.entity_id)
        if not application:
            raise HTTPException(status_code=404, detail="Application not found")
        app_org_id = application.organization_id or SYSTEM_ORG_ID
        
        if user.role != "admin" and app_org_id != org_id:
            raise HTTPException(
                status_code=403,
                detail="You do not have permission to untag this application"
            )
        
        # Only org_admin/org_owner can untag applications
        if user.role != "admin":
            user_role = get_user_role_in_org(user.id, org_id, adapter)
            if user_role not in ("org_admin", "org_owner"):
                raise HTTPException(status_code=403, detail="Only organization admins can untag applications")
    elif entity_type == "report":
        report = adapter.get_report(payload.entity_id)
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        if not can_edit_report(user, report, adapter):
            raise HTTPException(status_code=403, detail="You don't have permission to untag this report")
    elif entity_type == "finding":
        finding = adapter.get_finding(payload.entity_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        report = adapter.get_report(finding.report_id)
        if not report or not can_edit_report(user, report, adapter):
            raise HTTPException(status_code=403, detail="You don't have permission to untag this finding")
    
    ok = adapter.remove_entity_tag(payload.tag_id, payload.entity_type, payload.entity_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Tag assignment not found")
    return {"ok": True}


@router.get("/tags/entity/{entity_type}/{entity_id}")
def list_entity_tags(
    entity_type: str,
    entity_id: str,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """List all tags on a specific entity."""
    entity_type = entity_type.strip().lower()
    if entity_type not in VALID_ENTITY_TYPES:
        raise HTTPException(status_code=400, detail=f"entity_type must be one of: {', '.join(sorted(VALID_ENTITY_TYPES))}")
    
    # Verify user has access to the entity's organization
    org_id = get_org_id_from_request(request, user, adapter)
    if not org_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="You are not a member of any organization")
    
    # Verify the entity belongs to the user's organization
    if entity_type == "client":
        entity = adapter.get_client(entity_id)
        if not entity:
            raise HTTPException(status_code=404, detail="Team not found")
        entity_org = entity.organization_id or SYSTEM_ORG_ID
    elif entity_type == "application":
        entity = adapter.get_application(entity_id)
        if not entity:
            raise HTTPException(status_code=404, detail="Application not found")
        entity_org = entity.organization_id or SYSTEM_ORG_ID
    elif entity_type == "report":
        entity = adapter.get_report(entity_id)
        if not entity:
            raise HTTPException(status_code=404, detail="Report not found")
        if not can_view_report(user, entity, adapter):
            raise HTTPException(status_code=403, detail="Access denied")
        entity_org = entity.organization_id or SYSTEM_ORG_ID
    elif entity_type == "finding":
        entity = adapter.get_finding(entity_id)
        if not entity:
            raise HTTPException(status_code=404, detail="Finding not found")
        report = adapter.get_report(entity.report_id)
        if report and not can_view_report(user, report, adapter):
            raise HTTPException(status_code=403, detail="Access denied")
        entity_org = report.organization_id if report else SYSTEM_ORG_ID
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported entity_type: {entity_type}")
    
    if user.role != "admin" and entity_org != org_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    tags = list(adapter.list_entity_tags(entity_type, entity_id))
    # Remove created_by field for non-admin users
    if user.role != "admin":
        return [{"id": t.id, "name": t.name, "organization_id": t.organization_id, "created_at": t.created_at} for t in tags]
    return tags


@router.get("/tags/entity-bulk/{entity_type}")
def list_entity_tags_bulk(
    entity_type: str,
    ids: str = "",
    request: Request = None,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Return a map of entity_id -> [tag_name, ...] for multiple entities at once.
    
    Only returns tags for entities the user has access to (same org).
    Silently skips entities user cannot access.
    """
    entity_type = entity_type.strip().lower()
    if entity_type not in VALID_ENTITY_TYPES:
        raise HTTPException(status_code=400, detail=f"entity_type must be one of: {', '.join(sorted(VALID_ENTITY_TYPES))}")
    
    # Get user's org ID for verification
    org_id = get_org_id_from_request(request, user, adapter)
    if not org_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="You are not a member of any organization")
    
    entity_ids = [eid.strip() for eid in ids.split(",") if eid.strip()]
    result = {}
    
    for eid in entity_ids:
        # Verify user has access to this specific entity
        try:
            entity_org = None
            
            if entity_type == "client":
                entity = adapter.get_client(eid)
                if entity:
                    entity_org = entity.organization_id or SYSTEM_ORG_ID
            elif entity_type == "application":
                entity = adapter.get_application(eid)
                if entity:
                    entity_org = entity.organization_id or SYSTEM_ORG_ID
            elif entity_type == "report":
                entity = adapter.get_report(eid)
                if entity and can_view_report(user, entity, adapter):
                    entity_org = entity.organization_id or SYSTEM_ORG_ID
            elif entity_type == "finding":
                entity = adapter.get_finding(eid)
                if entity:
                    report = adapter.get_report(entity.report_id)
                    if report and can_view_report(user, report, adapter):
                        entity_org = report.organization_id
            
            # Only include tags if user has access (same org or system admin)
            if entity_org and (user.role == "admin" or entity_org == org_id):
                tags = list(adapter.list_entity_tags(entity_type, eid))
                result[eid] = [t.name for t in tags]
        except Exception as e:
            # Skip entities that cause errors (deleted, invalid, etc.)
            log.debug(f"Skipping entity {eid} in bulk tag query: {e}")
            continue
    
    return result


@router.delete("/tags/{tag_id}")
@require_organization_admin()
def delete_tag(
    tag_id: str,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Delete a tag and all its entity associations (org_admin or org_owner only)."""
    from app.services.rbac import get_org_id_from_request
    
    tag = adapter.get_tag(tag_id)
    if not tag:
        raise HTTPException(status_code=404, detail="Tag not found")
    
    # HIGH-5 fix: Verify tag belongs to user's organization
    user_org_id = get_org_id_from_request(request, user, adapter)
    tag_org_id = tag.organization_id or SYSTEM_ORG_ID
    
    if not user_org_id:
        raise HTTPException(status_code=403, detail="You are not a member of any organization")
    
    if user.role != "admin" and tag_org_id != user_org_id:
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to delete this tag"
        )
    
    ok = adapter.delete_tag(tag_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Tag not found")
    log_delete(adapter, tag_org_id, user.id, "tag", tag_id, request, name=tag.name)
    return {"ok": True}


# ── Connectors ──────────────────────────────────────────────────────────────


@router.get("/connectors")
def list_connectors(
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """List all configured connectors for the user's organization."""
    org_id = get_org_id_from_request(request, user, adapter)
    if not org_id:
        raise HTTPException(status_code=403, detail="You are not a member of any organization")
    connectors = list(adapter.list_connectors(organization_id=org_id))
    # Don't expose sensitive config in list view
    for c in connectors:
        if c.config:
            import json as _json
            try:
                config = _json.loads(c.config)
                # Mask sensitive fields
                if 'api_token' in config:
                    config['api_token'] = '***' if config['api_token'] else ''
                if 'password' in config:
                    config['password'] = '***' if config['password'] else ''
                c.config = _json.dumps(config)
            except Exception:
                import logging
                logging.getLogger("lazeport.connectors").warning("Failed to parse connector config for %s", c.id)
    return connectors


@router.post("/connectors")
@require_organization_admin()
def create_connector(
    payload: ConnectorPayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Create a new connector (org_admin or org_owner only)."""
    import json as _json
    from app.services.crypto import encrypt_text
    from app.services.rbac import get_org_id_from_request
    
    # HIGH-3 fix: Get user's organization
    org_id = get_org_id_from_request(request, user, adapter)
    if not org_id:
        raise HTTPException(status_code=403, detail="You are not a member of any organization")
    
    # Encrypt sensitive fields
    config = payload.config.copy()
    if 'api_token' in config and config['api_token']:
        config['api_token'] = encrypt_text(config['api_token'])
    if 'password' in config and config['password']:
        config['password'] = encrypt_text(config['password'])
    
    connector = adapter.create_connector(
        type=payload.type,
        name=payload.name,
        config=_json.dumps(config),
        organization_id=org_id,
    )
    
    log_create(
        adapter,
        org_id,
        user.id,
        "connector",
        connector.id,
        request,
        name=payload.name,
        connector_type=payload.type,
    )
    return connector


@router.put("/connectors/{connector_id}")
@require_organization_admin()
def update_connector(
    connector_id: str,
    payload: ConnectorPayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Update a connector (org_admin or org_owner only)."""
    import json as _json
    from app.services.crypto import encrypt_text
    from app.services.rbac import get_org_id_from_request
    
    # Get existing connector to preserve encrypted fields if not changed
    existing = adapter.get_connector(connector_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Connector not found")
    
    # HIGH-2 fix: Verify connector belongs to user's organization
    user_org_id = get_org_id_from_request(request, user, adapter)
    connector_org_id = existing.organization_id or SYSTEM_ORG_ID
    
    if not user_org_id:
        raise HTTPException(status_code=403, detail="You are not a member of any organization")
    
    if user.role != "admin" and connector_org_id != user_org_id:
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to update this connector"
        )
    
    config = payload.config.copy()
    
    # Handle encrypted fields
    if 'api_token' in config:
        if config['api_token'] and config['api_token'] != '***':
            # New token provided, encrypt it
            config['api_token'] = encrypt_text(config['api_token'])
        elif config['api_token'] == '***':
            # Keep existing encrypted token
            try:
                existing_config = _json.loads(existing.config)
                config['api_token'] = existing_config.get('api_token', '')
            except Exception as e:
                log.warning("Failed to preserve existing api_token for connector %s: %s", connector_id, type(e).__name__)
                config['api_token'] = ''  # nosec B105
    
    if 'password' in config:
        if config['password'] and config['password'] != '***':
            config['password'] = encrypt_text(config['password'])
        elif config['password'] == '***':
            try:
                existing_config = _json.loads(existing.config)
                config['password'] = existing_config.get('password', '')
            except Exception as e:
                log.warning("Failed to preserve existing password for connector %s: %s", connector_id, type(e).__name__)
                config['password'] = ''  # nosec B105
    
    connector = adapter.update_connector(
        connector_id,
        name=payload.name,
        config=_json.dumps(config),
        enabled=payload.enabled,
    )
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")
    org_id = connector.organization_id or _ensure_system_org_id(adapter)
    log_update(
        adapter,
        org_id,
        user.id,
        "connector",
        connector_id,
        request,
        name=payload.name,
        connector_type=payload.type,
        enabled=payload.enabled,
    )
    return connector


@router.delete("/connectors/{connector_id}")
@require_organization_admin()
def delete_connector(
    connector_id: str,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Delete a connector (org_admin or org_owner only)."""
    from app.services.rbac import get_org_id_from_request
    
    existing = adapter.get_connector(connector_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Connector not found")
    
    # HIGH-2 fix: Verify connector belongs to user's organization
    user_org_id = get_org_id_from_request(request, user, adapter)
    connector_org_id = existing.organization_id or SYSTEM_ORG_ID
    
    if not user_org_id:
        raise HTTPException(status_code=403, detail="You are not a member of any organization")
    
    if user.role != "admin" and connector_org_id != user_org_id:
        raise HTTPException(
            status_code=403,
            detail="You do not have permission to delete this connector"
        )
    ok = adapter.delete_connector(connector_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Connector not found")
    org_id = existing.organization_id or _ensure_system_org_id(adapter)
    log_delete(
        adapter,
        org_id,
        user.id,
        "connector",
        connector_id,
        request,
        name=existing.name,
        connector_type=existing.type,
    )
    return {"ok": True}


@router.post("/connectors/jira/test")
@require_organization_admin()
def test_jira_connection(
    payload: ConnectorPayload,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Test Jira connection without saving."""
    from app.services.jira import JiraClient
    
    config = payload.config
    url = config.get('url', '').strip()
    email = config.get('email', '').strip()
    api_token = config.get('api_token', '').strip()
    
    if not all([url, email, api_token]):
        raise HTTPException(status_code=400, detail="Missing required fields: url, email, api_token")
    
    client = JiraClient(url=url, email=email, api_token=api_token)
    success, message = client.test_connection()
    
    return {"success": success, "message": message}


def _get_jira_client_or_error(adapter: StorageAdapter, organization_id: str):
    """Load the Jira connector for the given organization, decrypt its config, and return client + connector.

    Raises HTTPException on missing config or decryption failure.
    Shared by list_jira_projects and create_jira_issue_from_finding.
    
    Args:
        adapter: Storage adapter
        organization_id: Organization ID to scope the connector lookup
        
    Returns:
        tuple: (JiraClient, Connector)
    """
    from app.services.jira import get_jira_client
    from app.services.crypto import decrypt_text
    import json as _json

    connector = adapter.get_connector_by_type("jira", organization_id)
    if not connector or not connector.enabled:
        raise HTTPException(status_code=404, detail="Jira connector not configured")
    try:
        config = _json.loads(connector.config)
        if 'api_token' in config and config['api_token']:
            config['api_token'] = decrypt_text(config['api_token'])
        config_json = _json.dumps(config)
    except Exception as e:
        log.error(f"Failed to decrypt Jira config for org {organization_id}: {e}")
        raise HTTPException(status_code=500, detail="Configuration error. Please reconfigure the Jira connector.")
    client = get_jira_client(config_json)
    if not client:
        raise HTTPException(status_code=500, detail="Invalid Jira configuration")
    return (client, connector)


@router.get("/connectors/jira/projects")
@require_consultant()
def list_jira_projects(
    request: Request,
    query: str = "",
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """List Jira projects (requires configured Jira connector for user's organization)."""
    org_id = get_org_id_from_request(request, user, adapter)
    if not org_id:
        raise HTTPException(status_code=403, detail="You are not a member of any organization")
    
    client, _ = _get_jira_client_or_error(adapter, org_id)
    projects = client.list_projects(query=query)
    return {"projects": projects}


@router.post("/connectors/jira/create-issue")
def create_jira_issue_from_finding(
    payload: JiraIssuePayload,
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Create a Jira issue from a finding using the organization's Jira connector."""
    import json as _json
    
    org_id = get_org_id_from_request(request, user, adapter)
    if not org_id:
        raise HTTPException(status_code=403, detail="You are not a member of any organization")

    client, connector = _get_jira_client_or_error(adapter, org_id)
    
    # Get connector URL for building issue_url
    connector_config = _json.loads(connector.config)
    from app.services.crypto import decrypt_text
    jira_url = connector_config.get('url', '').rstrip('/')

    # Get finding and check permissions
    finding = adapter.get_finding(payload.finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if finding.report_id:
        _require_report_edit(finding.report_id, user, adapter)
    
    # Prevent duplicate issue creation
    if finding.jira_issue_key:
        raise HTTPException(
            status_code=400, 
            detail=f"Finding already linked to Jira issue {finding.jira_issue_key}. Unlink first to create a new issue."
        )

    # Parse finding content (LOW-19: log on parse failure)
    content = _parse_finding_content_safe(finding.content_json, finding.id)
    
    # Build issue summary and description
    summary = finding.title or "Security Finding"
    
    # Build description from ALL content fields (template-agnostic)
    description_parts = []
    
    # Metadata fields first (single-line)
    metadata_fields = ['Severity', 'CVSS v3.1', 'CWE', 'CVE', 'OWASP', 'Affected Roles', 'Confidence']
    for field in metadata_fields:
        if content.get(field):
            value = str(content[field]).strip()
            if value and value != 'Not provided in evidence':
                description_parts.append(f"{field}: {value}")
    
    if description_parts:
        description_parts.append("")  # Blank line after metadata
    
    # Narrative sections (multi-line) - render all remaining fields
    for key, value in content.items():
        if key not in metadata_fields and key not in ['title', 'Affected Files']:
            value_str = str(value).strip()
            if value_str and value_str != 'Not provided in evidence':
                description_parts.append(f"## {key}")
                description_parts.append(value_str)
                description_parts.append("")
    
    # Append validation guidance if cached
    if finding.validation_guidance and finding.validation_guidance.strip():
        description_parts.append("---")
        description_parts.append("")
        description_parts.append("## Validation Steps")
        description_parts.append(finding.validation_guidance.strip())
    
    description = "\n".join(description_parts)
    
    # Map severity to Jira priority
    severity = (content.get('Severity') or '').strip().lower()
    if severity == 'information':
        severity = 'informational'
    priority_map = {
        'critical': 'Highest',
        'high': 'High',
        'medium': 'Medium',
        'low': 'Low',
        'informational': 'Lowest',
    }
    priority = priority_map.get(severity)
    
    # Create issue
    success, message, issue_key = client.create_issue(
        project_key=payload.project_key,
        summary=summary,
        description=description,
        issue_type=payload.issue_type,
        priority=priority,
        labels=['security', 'pentest'],
    )
    
    if success:
        # Save issue key and URL to finding (MED-26: use atomic operation to prevent race)
        issue_url = f"{jira_url}/browse/{issue_key}"
        link_success, existing_key = adapter.atomic_set_jira_link(
            finding_id=payload.finding_id,
            jira_issue_key=issue_key,
            jira_issue_url=issue_url
        )
        
        if not link_success:
            # Race condition: another request already linked a ticket
            if existing_key:
                raise HTTPException(
                    status_code=409,
                    detail=f"Finding was linked to {existing_key} by another request. Created {issue_key} but did not link it."
                )
            else:
                raise HTTPException(status_code=404, detail="Finding not found")
        
        return {"success": True, "message": message, "issue_key": issue_key, "issue_url": issue_url}
    else:
        raise HTTPException(status_code=500, detail=message)


@router.delete("/connectors/jira/unlink/{finding_id}")
def unlink_jira_ticket(
    finding_id: str,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Remove Jira ticket link from finding."""
    # Get finding and check permissions
    finding = adapter.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if finding.report_id:
        _require_report_edit(finding.report_id, user, adapter)
    
    # Clear Jira fields
    adapter.update_finding(
        finding_id=finding_id,
        jira_issue_key="",
        jira_issue_url=""
    )
    return {"success": True, "message": "Jira ticket unlinked"}


# ═══════════════════════════════════════════════════════
# Trends: aggregated analytics from real data
# ═══════════════════════════════════════════════════════

@router.get("/trends")
def get_trends(
    request: Request,
    days: Optional[int] = None,
    client_id: List[str] = Query(default=[], alias="client_id"),
    application_id: List[str] = Query(default=[], alias="application_id"),
    severity: List[str] = Query(default=[], alias="severity"),
    status: List[str] = Query(default=[], alias="status"),
    tag: List[str] = Query(default=[], alias="tag"),
    cwe: List[str] = Query(default=[], alias="cwe"),
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """
    Return aggregated trends data computed from real findings, reports, clients, tags.
    Accepts optional filters; returns KPI, time-series, heatmap, remediation, and tag data.
    ``days`` limits findings to those with Found Date within the last N days (default: all).
    """
    from datetime import datetime, timedelta
    from collections import defaultdict

    org_id = get_org_id_from_request(request, user, adapter)
    if not org_id:
        raise HTTPException(status_code=403, detail="You are not a member of any organization")

    now = datetime.utcnow()
    
    # ── Check user role: consultants can only see their own reports ──
    user_role = None
    if user.role != "admin":
        user_role = get_user_role_in_org(user.id, org_id, adapter)

    # ── Gather all findings across all reports ──
    UNASSIGNED = "__unassigned__"
    client_ids = [t for t in client_id if t]
    app_ids = [a for a in application_id if a]
    client_include_unassigned = UNASSIGNED in client_ids
    app_include_unassigned = UNASSIGNED in app_ids
    client_actual_ids = [t for t in client_ids if t != UNASSIGNED]
    app_actual_ids = [a for a in app_ids if a != UNASSIGNED]

    if len(client_ids) == 1 and len(app_ids) <= 1 and not client_include_unassigned and not app_include_unassigned:
        reports = list(adapter.list_reports(
            organization_id=org_id,
            client_id=client_ids[0] if client_ids else None,
            application_id=app_ids[0] if app_ids else None,
        ))
    else:
        reports = list(adapter.list_reports(organization_id=org_id))
        if client_ids:
            if client_include_unassigned and not client_actual_ids:
                reports = [r for r in reports if r.client_id is None or r.client_id == ""]
            elif client_include_unassigned:
                reports = [r for r in reports if r.client_id in client_actual_ids or r.client_id is None or r.client_id == ""]
            else:
                reports = [r for r in reports if r.client_id in client_actual_ids]
        if app_ids:
            if app_include_unassigned and not app_actual_ids:
                reports = [r for r in reports if r.application_id is None or r.application_id == ""]
            elif app_include_unassigned:
                reports = [r for r in reports if r.application_id in app_actual_ids or r.application_id is None or r.application_id == ""]
            else:
                reports = [r for r in reports if r.application_id in app_actual_ids]
    
    # Filter reports by creator for consultants and readonly users
    if user_role in ("consultant", "readonly"):
        reports = [r for r in reports if r.created_by == user.id]
    
    report_map = {r.id: r for r in reports}

    report_ids = [r.id for r in reports]
    findings_bulk = list(adapter.list_findings_bulk(report_ids)) if report_ids else []
    all_findings = []
    for f in findings_bulk:
        content = _parse_finding_content_safe(f.content_json, f.id)
        all_findings.append({
            "id": f.id,
            "report_id": f.report_id,
            "title": f.title,
            "severity": (content.get("Severity") or "").strip(),
            "status": (content.get("Status") or "Open").strip(),
            "cwe": (content.get("CWE") or "").strip(),
            "created_at": f.created_at.isoformat() if f.created_at else None,
            "found_date": content.get("Found Date"),
            "closed_date": content.get("Closed Date"),
            "client_id": report_map.get(f.report_id, None) and report_map[f.report_id].client_id,
            "application_id": report_map.get(f.report_id, None) and report_map[f.report_id].application_id,
        })

    # Apply additional filters
    if days:
        cutoff = now - timedelta(days=int(days))

        def _effective_date(f):
            """Use Found Date if present and parseable; else fallback to created_at."""
            fd = f.get("found_date")
            if fd and isinstance(fd, str):
                parsed = _parse_date(fd.strip())
                if parsed:
                    return parsed
            ca = f.get("created_at")
            if ca and isinstance(ca, str) and len(ca) >= 10:
                return _parse_date(ca[:10])
            return None

        all_findings = [
            f for f in all_findings
            if _effective_date(f) and _effective_date(f) >= cutoff
        ]
    severities_lower = [s.strip().lower() for s in severity if s and s.strip()]
    if severities_lower:
        all_findings = [f for f in all_findings if f["severity"].lower() in severities_lower]
    statuses_lower = [s.strip().lower() for s in status if s and s.strip()]
    if statuses_lower:
        statuses_set = {s for s in statuses_lower if s != "all"}
        if statuses_set:
            all_findings = [f for f in all_findings if f["status"].lower() in statuses_set]
    tag_filters = [_validate_tag_query(t) for t in tag if t]
    tag_filters = [t for t in tag_filters if t]
    if tag_filters:
        tagged_ids = set()
        for tag_filter in tag_filters:
            tagged_ids |= set(adapter.get_entity_ids_by_tag_name(org_id, tag_filter, "finding"))
        all_findings = [f for f in all_findings if f["id"] in tagged_ids]
    cwe_filters = [c.strip().upper() for c in cwe if c and c.strip()]
    if cwe_filters:
        all_findings = [f for f in all_findings if f["cwe"].upper() in cwe_filters]

    # ── Teams + Apps lookups ──
    # Include inactive clients so heatmap and remediation include findings from deleted/inactive clients (MED-40)
    clients_list = list(adapter.list_clients(organization_id=org_id, include_inactive=True))
    apps_list = list(adapter.list_applications(organization_id=org_id))
    client_name_by_id = {t.id: (t.name if t.is_active else f"{t.name} (inactive)") for t in clients_list}
    client_name_by_id[None] = UNASSIGNED  # For frontend to translate via reports.unassigned
    app_name_by_id = {a.id: a.name for a in apps_list}

    # ── KPI ──
    open_findings = [f for f in all_findings if f["status"].lower() != "closed"]
    closed_findings = [f for f in all_findings if f["status"].lower() == "closed"]
    critical_high = [f for f in open_findings if f["severity"].lower() in ("critical", "high")]

    # Oldest open (days)
    oldest_open_days = 0
    for f in open_findings:
        fd = f.get("found_date")
        if fd:
            try:
                delta = (now - datetime.strptime(fd, "%Y-%m-%d")).days
                oldest_open_days = max(oldest_open_days, delta)
            except ValueError:
                log.debug("Skipping finding with unparseable found_date in trends (finding_id=%s)", f.get("id"))

    # Median time to fix (for closed findings with both dates)
    fix_times = []
    for f in closed_findings:
        fd, cd = f.get("found_date"), f.get("closed_date")
        if fd and cd:
            try:
                delta = (datetime.strptime(cd, "%Y-%m-%d") - datetime.strptime(fd, "%Y-%m-%d")).days
                if delta >= 0:
                    fix_times.append(delta)
            except ValueError:
                log.debug("Skipping finding with unparseable date in fix-time calculation (finding_id=%s)", f.get("id"))
    fix_times.sort()
    median_fix = fix_times[len(fix_times) // 2] if fix_times else 0

    # Opened vs closed (last 30 days)
    cutoff_30d = now - timedelta(days=30)
    recent_opened = sum(1 for f in all_findings if f.get("found_date") and _parse_date(f["found_date"]) and _parse_date(f["found_date"]) >= cutoff_30d)
    recent_closed = sum(1 for f in closed_findings if f.get("closed_date") and _parse_date(f["closed_date"]) and _parse_date(f["closed_date"]) >= cutoff_30d)

    kpi = {
        "open": len(open_findings),
        "criticalHigh": len(critical_high),
        "oldestOpen": oldest_open_days,
        "medianFix": round(median_fix, 1),
        "openedVsClosed": recent_opened - recent_closed,
    }

    # ── Time series: open findings over time (last 12 weeks) ──
    # Point-in-time snapshots: at each week, how many findings were open?
    # A finding is open at week W if: found_date <= W AND (still open OR closed_date > W)
    sev_order = ["Informational", "Low", "Medium", "High", "Critical"]
    weeks = []
    week_labels = []
    for w in range(11, -1, -1):
        week_start = now - timedelta(weeks=w)
        weeks.append(week_start)
        week_labels.append(week_start.strftime("%b %d"))

    area_series = []
    for sev in sev_order:
        data = []
        for week_dt in weeks:
            count = 0
            for f in all_findings:
                if f["severity"].lower() != sev.lower():
                    continue
                fd = _parse_date(f.get("found_date") or "")
                if not fd or fd > week_dt:
                    continue  # not yet found at this point in time
                # Was it still open at this week?
                cd = _parse_date(f.get("closed_date") or "")
                if cd and cd <= week_dt:
                    continue  # already closed by this week
                count += 1
            data.append(count)
        area_series.append({"name": sev, "data": data})

    # ── Aging distribution ──
    age_buckets = [
        ("0-7d", 0, 7), ("7-14d", 7, 14), ("14-30d", 14, 30),
        ("30-60d", 30, 60), ("60-90d", 60, 90), ("90d+", 90, 9999),
    ]
    aging_labels = [b[0] for b in age_buckets]
    aging_values = []
    aging_colors_list = ["#22d3ee", "#38bdf8", "#3b82f6", "#6366f1", "#8b5cf6", "#a78bfa"]
    for _, lo, hi in age_buckets:
        count = 0
        for f in open_findings:
            fd = f.get("found_date")
            if fd:
                try:
                    age = (now - datetime.strptime(fd, "%Y-%m-%d")).days
                    if lo <= age < hi:
                        count += 1
                except ValueError:
                    log.debug("Skipping finding with unparseable found_date in aging distribution (finding_id=%s)", f.get("id"))
        aging_values.append(count)

    # ── Heatmap: Team × Severity ──
    sev_cols = ["Critical", "High", "Med", "Low"]
    heatmap_rows = []
    heatmap_data = []
    # Unassigned row first (findings with no client)
    unassigned_row = []
    for col in sev_cols:
        col_lower = col.lower() if col != "Med" else "medium"
        count = sum(1 for f in open_findings if (f["client_id"] is None or f["client_id"] == "") and f["severity"].lower() == col_lower)
        unassigned_row.append(count)
    if any(unassigned_row):
        heatmap_rows.append(UNASSIGNED)
        heatmap_data.append(unassigned_row)
    for client in clients_list:
        short_name = client.name.replace("Team ", "")
        heatmap_rows.append(short_name)
        row = []
        for col in sev_cols:
            col_lower = col.lower() if col != "Med" else "medium"
            count = sum(1 for f in open_findings if f["client_id"] == client.id and f["severity"].lower() == col_lower)
            row.append(count)
        heatmap_data.append(row)

    # ── Remediation performance (by client) ──
    client_fix_times = defaultdict(list)
    for f in closed_findings:
        fd, cd = f.get("found_date"), f.get("closed_date")
        tid = f.get("client_id")
        if fd and cd and tid:
            try:
                delta = (datetime.strptime(cd, "%Y-%m-%d") - datetime.strptime(fd, "%Y-%m-%d")).days
                if delta >= 0:
                    client_fix_times[tid].append(delta)
            except ValueError:
                log.debug("Skipping finding with unparseable date in client fix-time calculation (finding_id=%s)", f.get("id"))

    quickest = []
    oldest_list = []
    for tid, times in client_fix_times.items():
        times.sort()
        median = times[len(times) // 2] if times else 0
        quickest.append({"client": client_name_by_id.get(tid, "Unknown client"), "value": f"{median}d"})
    quickest.sort(key=lambda x: float(x["value"].replace("d", "")))

    # Oldest open per client
    client_oldest = defaultdict(int)
    for f in open_findings:
        fd = f.get("found_date")
        tid = f.get("client_id")
        if fd and tid:
            try:
                age = (now - datetime.strptime(fd, "%Y-%m-%d")).days
                client_oldest[tid] = max(client_oldest[tid], age)
            except ValueError:
                log.debug("Skipping finding with unparseable found_date in oldest-open calculation (finding_id=%s)", f.get("id"))
    for tid, age in sorted(client_oldest.items(), key=lambda x: -x[1]):
        oldest_list.append({"client": client_name_by_id.get(tid, "Unknown client"), "value": f"{age}d"})

    # ── Opened vs Closed line (weekly) ──
    line_opened = []
    line_closed = []
    line_labels = []
    for w in range(7, -1, -1):
        ws = now - timedelta(weeks=w + 1)
        we = now - timedelta(weeks=w)
        line_labels.append(f"W{8 - w}")
        opened_count = sum(1 for f in all_findings if f.get("found_date") and _parse_date(f["found_date"]) and ws <= _parse_date(f["found_date"]) < we)
        closed_count = sum(1 for f in closed_findings if f.get("closed_date") and _parse_date(f["closed_date"]) and ws <= _parse_date(f["closed_date"]) < we)
        line_opened.append(opened_count)
        line_closed.append(closed_count)

    # ── Tags with counts (only from findings user can see) ──
    allowed_finding_ids = {f["id"] for f in all_findings}
    tags_all = list(adapter.list_tags(org_id))
    tag_counts = []
    for tag in tags_all:
        entities = list(adapter.list_entities_by_tag(tag.id))
        count = len([e for e in entities if e.entity_type == "finding" and e.entity_id in allowed_finding_ids])
        tag_counts.append({"name": tag.name, "count": count})
    tag_counts.sort(key=lambda x: -x["count"])

    # ── CWE distribution (from filtered findings) ──
    cwe_counter: dict[str, int] = defaultdict(int)
    for f in all_findings:
        cwe_val = f["cwe"].upper()
        if cwe_val:
            cwe_counter[cwe_val] += 1
    cwe_counts = [
        {"id": cwe_id, "count": cnt}
        for cwe_id, cnt in sorted(cwe_counter.items(), key=lambda x: -x[1])
    ]

    # ── Detail findings (top matches for current filter) ──
    detail_findings = []
    for f in open_findings[:15]:
        age_days = 0
        fd = f.get("found_date")
        if fd:
            try:
                age_days = (now - datetime.strptime(fd, "%Y-%m-%d")).days
            except ValueError:
                log.debug("Skipping unparseable found_date in detail findings (finding_id=%s)", f.get("id"))
        detail_findings.append({
            "title": f["title"],
            "severity": f["severity"],
            "age": f"{age_days}d",
            "report_id": f["report_id"],
            "finding_id": f["id"],
        })

    return {
        "kpi": kpi,
        "areaXData": week_labels,
        "areaSeries": area_series,
        "agingXData": aging_labels,
        "agingYData": aging_values,
        "agingColors": aging_colors_list,
        "heatmapRows": heatmap_rows,
        "heatmapCols": sev_cols,
        "heatmapData": heatmap_data,
        "remediationQuickest": quickest[:6],
        "remediationOldest": oldest_list[:6],
        "lineXData": line_labels,
        "lineOpened": line_opened,
        "lineClosed": line_closed,
        "tagCounts": tag_counts[:12],
        "cweCounts": cwe_counts[:20],
        "detailFindings": detail_findings,
        "meta": {
            "totalFindings": len(all_findings),
            "totalReports": len(reports),
            "totalTeams": len(clients_list),
            "totalApps": len(apps_list),
        },
    }


# Trends filter presets: per-user, per-org, stored in DB. Readonly may create/delete own presets.
def _parse_json_safe(s: str) -> dict:
    if not s or not s.strip():
        return {}
    try:
        out = json.loads(s)
        return out if isinstance(out, dict) else {}
    except Exception:
        return {}


class TrendsPresetCreate(BaseModel):
    name: str
    filters: dict  # { dateRange, client, app, severity, status, tag }


@router.get("/trends-presets")
def list_trends_presets(
    request: Request,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """List current user's saved trends filter presets for the current org. Allowed for readonly."""
    org_id = get_org_id_from_request(request, user, adapter)
    if not org_id:
        raise HTTPException(status_code=403, detail="You are not a member of any organization")
    presets = list(adapter.list_trends_presets(user.id, org_id))
    return [
        {"id": p.id, "name": p.name, "filters": _parse_json_safe(p.filters)}
        for p in presets
    ]


@router.post("/trends-presets")
def create_trends_preset(
    request: Request,
    body: TrendsPresetCreate,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Create or replace a saved trends filter preset. Allowed for readonly."""
    org_id = get_org_id_from_request(request, user, adapter)
    if not org_id:
        raise HTTPException(status_code=403, detail="You are not a member of any organization")
    name = (body.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Preset name is required")
    filters_json = json.dumps(body.filters) if body.filters is not None else "{}"
    preset = adapter.create_trends_preset(user.id, org_id, name, filters_json)
    return {"id": preset.id, "name": preset.name, "filters": _parse_json_safe(preset.filters)}


@router.delete("/trends-presets/{preset_id}")
def delete_trends_preset(
    preset_id: str,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Delete a saved trends filter preset. User can only delete their own. Allowed for readonly."""
    deleted = adapter.delete_trends_preset(preset_id, user.id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Preset not found")
    return {"ok": True}


def _parse_date(s: str):
    """Parse YYYY-MM-DD string to datetime, or None."""
    from datetime import datetime
    try:
        return datetime.strptime(s, "%Y-%m-%d")
    except Exception:
        return None


@router.delete("/reports/{report_id}/import-sessions")
def clear_import_sessions(
    report_id: str,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Clear all import sessions for a report (useful after bulk deleting findings)."""
    report = adapter.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    _require_report_edit(report_id, user, adapter)
    
    deleted = adapter.delete_import_sessions_for_report(report_id)
    return {"deleted": deleted}


# ── PDF to Markdown ──────────────────────────────────────────────────────────

MAX_PDF_SIZE = 25 * 1024 * 1024  # 25 MB


@router.post("/parse-pdf")
async def parse_pdf_to_markdown(
    file: UploadFile = File(...),
    user=Depends(get_current_user),
):
    """
    Upload a PDF and get back its content as Markdown text.
    Uses PyMuPDF (via pymupdf4llm) for high-fidelity text + table extraction.
    """
    import logging

    log = logging.getLogger(__name__)

    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")

    ext = Path(file.filename).suffix.lower()
    if ext != ".pdf":
        raise HTTPException(status_code=400, detail="Only PDF files are supported")

    content = await file.read()
    if len(content) > MAX_PDF_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"PDF too large ({len(content) // (1024*1024)}MB). Max is {MAX_PDF_SIZE // (1024*1024)}MB.",
        )

    try:
        import pymupdf4llm
        import pymupdf  # noqa: F401 – ensures the C extension is loaded

        doc = pymupdf.open(stream=content, filetype="pdf")
        page_count = len(doc)
        doc.close()

        md_text = pymupdf4llm.to_markdown(
            pymupdf.open(stream=content, filetype="pdf"),
            show_progress=False,
        )

        # Light cleanup: collapse excessive blank lines
        import re as _re
        md_text = _re.sub(r"\n{4,}", "\n\n\n", md_text).strip()

        log.info("Parsed PDF '%s': %d pages, %d chars of markdown", file.filename, page_count, len(md_text))

        return {
            "markdown": md_text,
            "filename": file.filename,
            "pages": page_count,
            "chars": len(md_text),
        }

    except ImportError:
        log.error("pymupdf4llm not installed – PDF parsing unavailable")
        raise HTTPException(
            status_code=500,
            detail="PDF parsing is not available. Install PyMuPDF and pymupdf4llm.",
        )
    except Exception as exc:
        log.error("PDF parsing failed for '%s': %s", file.filename, exc, exc_info=True)
        raise HTTPException(status_code=422, detail=f"Failed to parse PDF: {str(exc)}")


# ═══════════════════════════════════════════════════════════════════════════
# Organization Settings - Confidence Levels
# ═══════════════════════════════════════════════════════════════════════════

DEFAULT_CONFIDENCE_LEVELS = ["Confirmed", "Suspected", "Tentative", "False Positive"]


@router.get("/confidence-levels")
async def get_confidence_levels(
    request: Request,
    user: models.User = Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """
    Get confidence levels for the current organization.
    Returns default levels if not configured.
    """
    org_id = get_org_id_from_request(request, user, adapter)
    if not org_id:
        raise HTTPException(status_code=403, detail="You are not a member of any organization")
    
    org = adapter.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    try:
        settings_data = json.loads(org.settings) if org.settings else {}
    except json.JSONDecodeError:
        settings_data = {}
    
    levels = settings_data.get("confidence_levels", DEFAULT_CONFIDENCE_LEVELS)
    return {"levels": levels}


class OrganizationSettingsPayload(BaseModel):
    confidence_levels: Optional[List[str]] = None
    twofa_policy: Optional[str] = None


@router.put("/organization/settings")
@require_organization_admin()
async def update_organization_settings(
    payload: OrganizationSettingsPayload,
    request: Request,
    user: models.User = Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Update organization settings (org admin only). Supports: confidence_levels, twofa_policy."""
    org_id = get_org_id_from_request(request, user, adapter)
    if not org_id:
        raise HTTPException(status_code=403, detail="You are not a member of any organization")
    
    org = adapter.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    # Parse existing settings
    try:
        settings_data = json.loads(org.settings) if org.settings else {}
    except json.JSONDecodeError:
        settings_data = {}
    
    # Update confidence levels if provided
    if payload.confidence_levels is not None:
        if len(payload.confidence_levels) < 2:
            raise HTTPException(
                status_code=400,
                detail="Must provide at least 2 confidence levels"
            )
        # Validate each level is non-empty
        clean_levels = [level.strip() for level in payload.confidence_levels if level.strip()]
        if len(clean_levels) < 2:
            raise HTTPException(
                status_code=400,
                detail="All confidence levels must be non-empty strings"
            )
        settings_data["confidence_levels"] = clean_levels
    
    # Update 2FA policy if provided
    if payload.twofa_policy is not None:
        allowed_policies = {"disabled", "optional", "mandatory"}
        if payload.twofa_policy not in allowed_policies:
            raise HTTPException(
                status_code=400,
                detail=f"2FA policy must be one of: {', '.join(allowed_policies)}"
            )
        settings_data["twofa_policy"] = payload.twofa_policy
    
    # Save back to database
    updated_org = adapter.update_organization(
        org_id=org_id,
        settings=json.dumps(settings_data)
    )
    
    if not updated_org:
        raise HTTPException(status_code=500, detail="Failed to update organization settings")
    
    log_update(
        adapter=adapter,
        user_id=user.id,
        org_id=org_id,
        action="update",
        resource_type="organization_settings",
        resource_id=org_id,
        details=json.dumps({"confidence_levels": settings_data.get("confidence_levels")})
    )
    
    return {"success": True, "settings": settings_data}


