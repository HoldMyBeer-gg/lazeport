"""
Audit logging service.

Records all important actions in the system for security,
compliance, and incident response.
"""
import json
from typing import Any
from fastapi import Request
from app.db.adapter import StorageAdapter


def log_action(
    adapter: StorageAdapter,
    organization_id: str,
    user_id: str,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    details: dict[str, Any] | None = None,
    request: Request | None = None,
) -> None:
    """
    Log an action to the audit trail.
    
    Args:
        adapter: Database adapter
        organization_id: Organization this action belongs to
        user_id: User who performed the action
        action: Action type (create, update, delete, login, etc.)
        resource_type: Type of resource (client, report, finding, user, etc.)
        resource_id: ID of the affected resource
        details: Additional context (as dict, will be JSON-encoded)
        request: FastAPI request (for IP and user agent)
    """
    ip_address = None
    user_agent = None
    
    if request:
        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")
    
    details_json = json.dumps(details or {})
    adapter.create_audit_log(
        organization_id=organization_id,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details_json,
        ip_address=ip_address,
        user_agent=user_agent,
    )


def log_create(
    adapter: StorageAdapter,
    org_id: str,
    user_id: str,
    resource_type: str,
    resource_id: str,
    request: Request | None = None,
    **details
):
    """Log resource creation."""
    log_action(adapter, org_id, user_id, "create", resource_type, resource_id, details, request)


def log_update(
    adapter: StorageAdapter,
    org_id: str,
    user_id: str,
    resource_type: str,
    resource_id: str,
    request: Request | None = None,
    **details
):
    """Log resource update."""
    log_action(adapter, org_id, user_id, "update", resource_type, resource_id, details, request)


def log_delete(
    adapter: StorageAdapter,
    org_id: str,
    user_id: str,
    resource_type: str,
    resource_id: str,
    request: Request | None = None,
    **details
):
    """Log resource deletion."""
    log_action(adapter, org_id, user_id, "delete", resource_type, resource_id, details, request)


def log_auth(
    adapter: StorageAdapter,
    org_id: str,
    user_id: str,
    action: str,  # login, logout, failed_login
    request: Request | None = None,
    **details
):
    """Log authentication event."""
    log_action(adapter, org_id, user_id, action, "auth", None, details, request)
