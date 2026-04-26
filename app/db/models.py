from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import uuid4

from sqlmodel import Field, SQLModel, UniqueConstraint

# Canonical system organization ID (used for bootstrap, fallbacks, audit)
SYSTEM_ORG_ID = "00000000-0000-0000-0000-000000000001"


def _uuid() -> str:
    return str(uuid4())


class User(SQLModel, table=True):
    id: str = Field(default_factory=_uuid, primary_key=True)
    email: str = Field(index=True, unique=True)
    name: str = ""
    role: str = "user"  # "admin" | "user" (kept for backward compat)
    provider: str = "google"  # "google" | "local"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None
    is_active: bool = True
    password_hash: str = ""
    
    # User profile fields
    contact_email: str = ""
    phone: str = ""
    title: str = ""  # Job title
    theme: str = "dark"
    company_name: str = ""
    department_name: str = ""
    default_master_template: str = "master"
    default_finding_template: str = ""  # name of default finding template (empty = first available)
    # Encrypted per-user API keys (JSON dict of provider->key); use org/env default when empty
    openai_api_key_encrypted: str = ""
    # Which AI provider the user last used (for UI convenience)
    ai_key_provider: str = ""
    # Optional instructions appended to every AI request (style, tone, etc.); stored in DB for long prompts
    llm_extra_instructions: str = ""
    
    # 2FA fields
    twofa_secret: str = ""  # Encrypted TOTP secret
    twofa_enabled: bool = False
    twofa_backup_codes: str = ""  # JSON array of hashed backup codes
    twofa_configured_at: Optional[datetime] = None  # When 2FA was enabled
    session_version: int = Field(default=0)


class ApiKey(SQLModel, table=True):
    """
    API Key for programmatic access.
    The key itself is only shown once upon creation and stored as a hash.
    """
    __tablename__ = "api_key"
    
    id: str = Field(default_factory=_uuid, primary_key=True)
    user_id: str = Field(foreign_key="user.id", index=True)
    name: str = Field(default="Default Key")
    key_hash: str = Field(index=True)
    prefix: str = ""  # First 4 chars of the key for identification
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_used_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None


class Organization(SQLModel, table=True):
    """
    Organization/tenant. All resources belong to an organization.
    Supports multi-tenancy and org-level isolation.
    """
    id: str = Field(default_factory=_uuid, primary_key=True)
    name: str = Field(index=True, max_length=255)
    slug: str = Field(unique=True, index=True, max_length=255)  # URL-friendly identifier
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Organization settings (JSON-encoded for flexibility)
    settings: str = ""  # JSON: theme, defaults, etc.

    # Severity criteria (JSON: {Critical, High, Medium, Low, Informational} -> definitions)
    severity_criteria: Optional[str] = None  # JSON dict of severity level definitions

    # Organization status
    is_active: bool = True

    # Subscription/limits (for future SaaS features)
    max_users: Optional[int] = None
    max_reports: Optional[int] = None


class OrganizationMember(SQLModel, table=True):
    """
    Join table for User <-> Organization with role.
    A user can belong to multiple organizations with different roles.
    """
    __tablename__ = "organization_member"
    __table_args__ = (UniqueConstraint('organization_id', 'user_id', name='unique_org_user'),)
    
    id: str = Field(default_factory=_uuid, primary_key=True)
    organization_id: str = Field(foreign_key="organization.id", index=True)
    user_id: str = Field(foreign_key="user.id", index=True)
    role: str = Field(index=True)  # org_owner, org_admin, consultant, readonly
    joined_at: datetime = Field(default_factory=datetime.utcnow)
    invited_by: Optional[str] = Field(foreign_key="user.id", default=None)


class OrganizationInvite(SQLModel, table=True):
    """
    Invitation token for joining an organization.
    Tokens are stored as hashes and expire after a short period.
    """
    __tablename__ = "organization_invite"
    __table_args__ = (UniqueConstraint('organization_id', 'email', name='unique_org_email_invite'),)

    id: str = Field(default_factory=_uuid, primary_key=True)
    organization_id: str = Field(foreign_key="organization.id", index=True)
    email: str = Field(index=True)
    role: str = Field(index=True)
    user_id: Optional[str] = Field(foreign_key="user.id", default=None)
    invited_by: Optional[str] = Field(foreign_key="user.id", default=None)
    token_hash: str = Field(index=True)
    expires_at: datetime = Field(index=True)
    used_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class AuditLog(SQLModel, table=True):
    """
    Audit trail for all actions in the system.
    Enables security monitoring, compliance, and incident response.
    """
    __tablename__ = "audit_log"
    
    id: str = Field(default_factory=_uuid, primary_key=True)
    organization_id: str = Field(foreign_key="organization.id", index=True)
    user_id: str = Field(foreign_key="user.id", index=True)
    action: str = Field(index=True)  # create, update, delete, login, logout, etc.
    resource_type: str = Field(default="", index=True)  # client, application, report, finding, user, template, connector, etc.
    resource_id: Optional[str] = Field(default=None, index=True)
    details: str = ""  # JSON-encoded details
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow, index=True)


class Settings(SQLModel, table=True):
    id: int = Field(default=1, primary_key=True)
    org_name: str = ""
    author_name: str = ""
    author_email: str = ""
    author_phone: str = ""
    author_title: str = ""  # e.g., "Principal Consultant"
    voice_style: str = ""  # e.g., "DevSecOps"
    company_name: str = ""
    department_name: str = ""
    theme: str = "dark"  # "light" | "dark" | "solarized-light" | "solarized-dark" | "accessibility"
    default_master_template: str = "master"  # name of default master template for severity criteria
    default_finding_template: str = ""  # name of default finding template (empty = first available)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Team(SQLModel, table=True):
    """Remediation owner / development client (formerly 'Client')."""
    id: str = Field(default_factory=_uuid, primary_key=True)
    organization_id: str = Field(foreign_key="organization.id", index=True)
    name: str = Field(index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[str] = Field(foreign_key="user.id", default=None)
    is_active: bool = True
    settings_json: str = ""  # JSON: future jira project key, etc.


class Application(SQLModel, table=True):
    """The thing being tested: web app, API, mobile app, firmware, etc."""
    id: str = Field(default_factory=_uuid, primary_key=True)
    organization_id: str = Field(foreign_key="organization.id", index=True)
    name: str = Field(index=True)
    type: Optional[str] = None  # web, api, ios, android, hardware
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[str] = Field(foreign_key="user.id", default=None)
    description: str = ""


class Report(SQLModel, table=True):
    id: str = Field(default_factory=_uuid, primary_key=True)
    organization_id: str = Field(foreign_key="organization.id", index=True)
    client_id: Optional[str] = Field(default=None, foreign_key="team.id", index=True)
    application_id: Optional[str] = Field(default=None, foreign_key="application.id", index=True)
    name: str = Field(index=True)
    summary_executive: str = ""
    summary_technical: str = ""
    summary_recommendations: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[str] = Field(foreign_key="user.id", default=None)


class Finding(SQLModel, table=True):
    id: str = Field(default_factory=_uuid, primary_key=True)
    organization_id: str = Field(foreign_key="organization.id", index=True)
    report_id: str = Field(foreign_key="report.id", index=True)
    title: str = ""
    content_json: str = ""
    notes: str = ""
    template: str = ""
    evidence_payload: str = ""  # Immutable scanner evidence snapshot (all sources: SARIF, Burp, notes) - JSON container for EvidencePayload
    metadata_json: str = ""     # LLM generation metadata (flow_version, flags, previous_evidence_hash)
    validation_guidance: str = ""  # Cached LLM-generated validation steps for this finding
    jira_issue_key: str = ""    # Linked Jira issue key (e.g., "PROJ-1234")
    jira_issue_url: str = ""    # Full URL to Jira issue
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[str] = Field(foreign_key="user.id", default=None)


class ReportShare(SQLModel, table=True):
    """
    Explicit per-user access to a report.
    """
    __tablename__ = "report_share"
    __table_args__ = (UniqueConstraint('report_id', 'user_id', name='unique_report_user'),)

    id: str = Field(default_factory=_uuid, primary_key=True)
    report_id: str = Field(foreign_key="report.id", index=True)
    user_id: str = Field(foreign_key="user.id", index=True)
    shared_by: str = Field(foreign_key="user.id", index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class FindingTemplate(SQLModel, table=True):
    id: str = Field(default_factory=_uuid, primary_key=True)
    organization_id: Optional[str] = Field(foreign_key="organization.id", index=True, default=None)
    name: str = Field(index=True)
    content: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[str] = Field(foreign_key="user.id", default=None)


class MasterTemplate(SQLModel, table=True):
    id: str = Field(default_factory=_uuid, primary_key=True)
    organization_id: Optional[str] = Field(foreign_key="organization.id", index=True, default=None)
    name: str = Field(index=True)
    content: bytes  # DOCX file as binary blob
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[str] = Field(foreign_key="user.id", default=None)


class BootstrapAdminSecret(SQLModel, table=True):
    id: int = Field(default=1, primary_key=True)
    encrypted_password: str


class Connector(SQLModel, table=True):
    id: str = Field(default_factory=_uuid, primary_key=True)
    organization_id: str = Field(foreign_key="organization.id", index=True)
    type: str = Field(index=True)  # "jira", "github", etc.
    name: str = ""  # User-friendly name
    config: str = ""  # JSON-encoded config (encrypted sensitive fields)
    enabled: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[str] = Field(foreign_key="user.id", default=None)


class LoginAttempt(SQLModel, table=True):
    """
    Track login attempts for rate limiting.
    Used to prevent brute force attacks.
    """
    __tablename__ = "login_attempt"
    
    id: str = Field(default_factory=_uuid, primary_key=True)
    identifier: str = Field(index=True)  # Email or IP address
    ip_address: Optional[str] = None
    success: bool = False
    attempted_at: datetime = Field(default_factory=datetime.utcnow, index=True)


class Tag(SQLModel, table=True):
    """
    Organization-scoped free-form tag.
    Tags are reusable labels that can be applied to findings, reports, clients, members, and applications.
    """
    __table_args__ = (UniqueConstraint('organization_id', 'name', name='unique_org_tag_name'),)

    id: str = Field(default_factory=_uuid, primary_key=True)
    organization_id: str = Field(foreign_key="organization.id", index=True)
    name: str = Field(index=True, max_length=50)  # alphanumeric, spaces, periods
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[str] = Field(foreign_key="user.id", default=None)


class EntityTag(SQLModel, table=True):
    """
    Polymorphic join table: associates a Tag with any taggable entity.
    entity_type is one of: finding, report, client, member, application.
    entity_id is the UUID of the tagged entity.
    """
    __tablename__ = "entity_tag"
    __table_args__ = (UniqueConstraint('tag_id', 'entity_type', 'entity_id', name='unique_tag_entity'),)

    id: str = Field(default_factory=_uuid, primary_key=True)
    tag_id: str = Field(foreign_key="tag.id", index=True)
    entity_type: str = Field(index=True)  # finding, report, client, member
    entity_id: str = Field(index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[str] = Field(foreign_key="user.id", default=None)


class OrgOidcConfig(SQLModel, table=True):
    """
    Per-org OIDC provider config (Okta, Google, etc.).
    Each org can have one OIDC provider for SSO.
    """
    __tablename__ = "org_oidc_config"
    __table_args__ = (UniqueConstraint('organization_id', 'provider_id', name='unique_org_provider'),)

    id: str = Field(default_factory=_uuid, primary_key=True)
    organization_id: str = Field(foreign_key="organization.id", index=True)
    provider_id: str = Field(index=True)  # okta, google, microsoft
    provider_label: str = ""  # Display name for login button
    issuer: str = ""  # OIDC discovery URL, e.g. https://dev-xxx.okta.com
    client_id: str = ""
    client_secret_encrypted: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class OrgDomain(SQLModel, table=True):
    """
    Email domains for an org. Used for OIDC routing: user enters email,
    we extract domain, find org, redirect to that org's IdP.
    """
    __tablename__ = "org_domain"
    __table_args__ = (UniqueConstraint('domain', name='unique_org_domain'),)

    id: str = Field(default_factory=_uuid, primary_key=True)
    organization_id: str = Field(foreign_key="organization.id", index=True)
    domain: str = Field(index=True)  # e.g. acme.com (lowercase, no @)


class BurpImportSession(SQLModel, table=True):
    """
    Persisted Burp import session per report and file hash.
    Enables resume when user closes dialog and returns later.
    """
    __tablename__ = "burp_import_session"
    __table_args__ = (UniqueConstraint('report_id', 'content_hash', name='unique_report_content_hash'),)

    id: str = Field(default_factory=_uuid, primary_key=True)
    report_id: str = Field(foreign_key="report.id", index=True)
    content_hash: str = Field(index=True)  # SHA-256 of file content
    file_name: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    # JSON array of {index, status, finding} - status: pending|generating|completed|skipped|failed
    tasks_json: str = "[]"


class GenerationTask(SQLModel, table=True):
    """
    Persisted background generation task. Allows LLM calls to run in Celery
    and survive page refresh, navigation, and browser close.
    """
    __tablename__ = "generation_task"

    id: str = Field(default_factory=_uuid, primary_key=True)
    user_id: str = Field(index=True)
    organization_id: str = Field(index=True)
    report_id: Optional[str] = Field(default=None, index=True)
    finding_id: Optional[str] = Field(default=None)          # set post-completion for generate_finding
    task_type: str = Field(index=True)                        # 'generate_finding' | 'regenerate_finding' | 'generate_summaries' | 'vision_extraction'
    title: str = ""                                           # human-readable label shown in TaskBar
    status: str = Field(default="pending", index=True)        # pending | running | completed | failed | cancelled
    celery_task_id: Optional[str] = Field(default=None)
    current_step: int = Field(default=0)
    total_steps: int = Field(default=0)
    progress_log: str = Field(default="[]")                   # JSON array of curated progress strings (never raw logs)
    result_json: str = Field(default="")                      # JSON result payload (capped at ~64KB by worker)
    error: str = Field(default="")
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    started_at: Optional[datetime] = Field(default=None)
    finished_at: Optional[datetime] = Field(default=None)


class TrendsFilterPreset(SQLModel, table=True):
    """
    Per-user, per-org saved filter presets for the Trends page.
    Readonly users are allowed to create and delete their own presets.
    """
    __tablename__ = "trends_filter_preset"
    __table_args__ = (UniqueConstraint('user_id', 'organization_id', 'name', name='unique_user_org_preset_name'),)

    id: str = Field(default_factory=_uuid, primary_key=True)
    user_id: str = Field(foreign_key="user.id", index=True)
    organization_id: str = Field(foreign_key="organization.id", index=True)
    name: str = Field(index=True, max_length=255)
    filters: str = ""  # JSON: { dateRange, client, app, severity, status, tag }
    created_at: datetime = Field(default_factory=datetime.utcnow)
