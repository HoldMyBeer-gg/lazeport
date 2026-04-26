"""
Role-Based Access Control (RBAC) system.

Provides decorators and utilities for checking user permissions
within organizations.
"""
from functools import wraps
import inspect
import logging
from typing import Callable
from fastapi import HTTPException, Depends, Request
from app.db import get_adapter
from app.db.adapter import StorageAdapter
from app.db import models
from app.db.models import SYSTEM_ORG_ID
from app.services.auth import get_current_user

log = logging.getLogger(__name__)


# Role hierarchy (higher = more permissions)
ROLE_HIERARCHY = {
    "readonly": 1,
    "consultant": 2,
    "org_admin": 3,
    "org_owner": 4,
    "admin": 5,  # System admin (global)
}


def get_org_id_from_request(request: Request, user: models.User = None, adapter: StorageAdapter = None) -> str | None:
    """
    Extract organization ID from request with proper security.
    
    Priority order:
    1. Query parameter 'organization_id' (if user is member)
    2. Path parameter 'org_id' (if user is member)
    3. User's first organization membership
    4. System org (fallback for system admins only)
    
    Returns None if user has no org access.
    """
    # Check query parameter first
    org_id = request.query_params.get("organization_id")
    if not org_id:
        # Check path parameters
        if hasattr(request, "path_params"):
            org_id = request.path_params.get("org_id")
    
    # Verify user has access to requested org
    if org_id and user and adapter:
        user_role = get_user_role_in_org(user.id, org_id, adapter)
        if user_role:
            return org_id
        # User requested an org they're not a member of
        return None
    
    # No org specified - use user's first org membership
    if user and adapter:
        orgs = list(adapter.get_user_organizations(user.id))
        if orgs:
            return orgs[0].id
    
    # Fallback to System org only for system admins
    if user and user.role == "admin":
        return SYSTEM_ORG_ID
    
    return None


def get_user_role_in_org(
    user_id: str,
    org_id: str,
    adapter: StorageAdapter
) -> str | None:
    """
    Get user's role in the specified organization.
    Returns None if user is not a member.
    """
    # Check if user is system admin
    user = adapter.get_user_by_id(user_id)
    if user and user.role == "admin":
        return "admin"
    
    # Check organization membership
    with adapter._session() as session:
        from sqlmodel import select
        stmt = (
            select(models.OrganizationMember)
            .where(models.OrganizationMember.organization_id == org_id)
            .where(models.OrganizationMember.user_id == user_id)
        )
        member = session.exec(stmt).first()
        return member.role if member else None


def has_permission(
    user_role: str | None,
    required_roles: list[str]
) -> bool:
    """Check if user's role meets the minimum requirement."""
    if not user_role:
        return False
    
    user_level = ROLE_HIERARCHY.get(user_role, 0)
    required_level = min(ROLE_HIERARCHY.get(role, 999) for role in required_roles)
    
    return user_level >= required_level


def require_org_role(*allowed_roles: str):
    """
    Decorator to enforce organization-level role requirements.
    
    Usage:
        @router.post("/orgs/{org_id}/clients")
        @require_org_role("org_admin", "consultant")
        async def create_client(org_id: str, ...):
            ...
    
    Allowed roles:
    - readonly: View-only access
    - consultant: Can create/edit resources
    - org_admin: Can manage org settings
    - org_owner: Full org control
    - admin: System admin (bypasses all checks)
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(
            *args,
            request: Request = None,
            user: models.User = Depends(get_current_user),
            adapter: StorageAdapter = Depends(get_adapter),
            **kwargs
        ):
            # Extract org_id (from path param, query, or default)
            org_id = kwargs.get("org_id")
            if not org_id:
                # Try to get from request (with user context for proper org resolution)
                if request:
                    org_id = get_org_id_from_request(request, user, adapter)
                
                # Use default System org if not specified
                if not org_id:
                    org_id = SYSTEM_ORG_ID
            
            # Get user's role in this organization
            user_role = get_user_role_in_org(user.id, org_id, adapter)
            
            # Debug logging for permission checks
            log.info(f"[RBAC] User {user.id} role in org {org_id}: {user_role}, required: {allowed_roles}")
            
            if not user_role:
                raise HTTPException(
                    status_code=403,
                    detail="You are not a member of this organization"
                )
            
            # Check if user has required role
            if not has_permission(user_role, list(allowed_roles)):
                log.warning(f"[RBAC] Permission denied for user {user.id}: has {user_role}, needs one of {allowed_roles}")
                raise HTTPException(
                    status_code=403,
                    detail=f"Insufficient permissions. Required: {', '.join(allowed_roles)}"
                )
            
            # User has permission - proceed with request
            # Only inject parameters that the function actually accepts
            sig = inspect.signature(func)
            call_kwargs = kwargs.copy()
            
            if 'request' in sig.parameters:
                call_kwargs['request'] = request
            if 'user' in sig.parameters:
                call_kwargs['user'] = user
            if 'adapter' in sig.parameters:
                call_kwargs['adapter'] = adapter
            
            if inspect.iscoroutinefunction(func):
                return await func(*args, **call_kwargs)
            return func(*args, **call_kwargs)
        
        return wrapper
    return decorator


def require_resource_owner(resource_type: str):
    """
    Decorator to enforce resource ownership.
    
    Consultants can only edit/delete resources they created.
    Org admins and owners can edit/delete any resource in their org.
    
    Usage:
        @require_resource_owner("report")
        async def delete_report(report_id: str, user: User, adapter: StorageAdapter):
            ...
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(
            *args,
            user: models.User = Depends(get_current_user),
            adapter: StorageAdapter = Depends(get_adapter),
            **kwargs
        ):
            # Get resource ID from kwargs
            resource_id = (
                kwargs.get("report_id") or
                kwargs.get("finding_id") or
                kwargs.get("client_id") or
                kwargs.get("template_id")
            )
            
            if not resource_id:
                # No specific resource - proceed
                # Only inject parameters that function accepts
                sig = inspect.signature(func)
                call_kwargs = kwargs.copy()
                if 'user' in sig.parameters:
                    call_kwargs['user'] = user
                if 'adapter' in sig.parameters:
                    call_kwargs['adapter'] = adapter
                return await func(*args, **call_kwargs)
            
            # HIGH-4 fix: Fetch resource first to determine its actual organization
            with adapter._session() as session:
                resource = None
                if resource_type == "report":
                    resource = session.get(models.Report, resource_id)
                elif resource_type == "finding":
                    # Finding doesn't have organization_id, need to get it from report
                    finding = session.get(models.Finding, resource_id)
                    if finding and finding.report_id:
                        report = session.get(models.Report, finding.report_id)
                        if report:
                            resource = finding
                            # Use report's org for permission check
                            org_id = report.organization_id or SYSTEM_ORG_ID
                        else:
                            resource = finding
                            org_id = SYSTEM_ORG_ID
                    else:
                        org_id = SYSTEM_ORG_ID
                elif resource_type == "client":
                    resource = session.get(models.Team, resource_id)
                    org_id = resource.organization_id if resource else SYSTEM_ORG_ID
                else:
                    org_id = SYSTEM_ORG_ID
                
                # If resource has organization_id attribute, use it
                if resource and hasattr(resource, "organization_id"):
                    org_id = resource.organization_id or SYSTEM_ORG_ID
                
                # Get user's role in the resource's organization
                user_role = get_user_role_in_org(user.id, org_id, adapter)
                
                # Admins and org owners/admins can do anything in their org
                if user_role in ("admin", "org_owner", "org_admin"):
                    sig = inspect.signature(func)
                    call_kwargs = kwargs.copy()
                    if 'user' in sig.parameters:
                        call_kwargs['user'] = user
                    if 'adapter' in sig.parameters:
                        call_kwargs['adapter'] = adapter
                    return await func(*args, **call_kwargs)
                
                # Consultants can only modify their own resources
                if user_role == "consultant":
                    if resource and hasattr(resource, "created_by"):
                        if resource.created_by != user.id:
                            raise HTTPException(
                                status_code=403,
                                detail="You can only modify resources you created"
                            )
                    sig = inspect.signature(func)
                    call_kwargs = kwargs.copy()
                    if 'user' in sig.parameters:
                        call_kwargs['user'] = user
                    if 'adapter' in sig.parameters:
                        call_kwargs['adapter'] = adapter
                    return await func(*args, **call_kwargs)
                
                # No permission
                raise HTTPException(
                    status_code=403,
                    detail="You do not have permission to access this resource"
                )
        
        return wrapper
    return decorator


# Shorthand decorators for common permissions
def require_consultant():
    """Shorthand for requiring consultant role or higher."""
    return require_org_role("consultant", "org_admin", "org_owner", "admin")


def require_organization_admin():
    """Shorthand for requiring org admin role or higher."""
    return require_org_role("org_admin", "org_owner", "admin")


def require_owner():
    """Shorthand for requiring org owner or system admin."""
    return require_org_role("org_owner", "admin")


def can_view_report(user: models.User, report: models.Report, adapter: StorageAdapter) -> bool:
    """Return True if user can view the report."""
    if user.role == "admin":
        return True

    org_id = report.organization_id or SYSTEM_ORG_ID
    user_role = get_user_role_in_org(user.id, org_id, adapter)
    if not user_role:
        return False

    if user_role in ("org_admin", "org_owner", "admin"):
        return True

    if report.created_by and report.created_by == user.id:
        return True

    if not report.created_by:
        # Legacy reports without owner stay visible to org members.
        return True

    return adapter.get_report_share(report.id, user.id) is not None


def can_edit_report(user: models.User, report: models.Report, adapter: StorageAdapter) -> bool:
    """Return True if user can modify the report or its findings."""
    if user.role == "admin":
        return True

    org_id = report.organization_id or SYSTEM_ORG_ID
    user_role = get_user_role_in_org(user.id, org_id, adapter)
    if not user_role:
        return False

    # Readonly can never edit, even if they created the report
    if user_role == "readonly":
        return False

    if user_role in ("org_admin", "org_owner", "admin"):
        return True

    if report.created_by and report.created_by == user.id:
        return True

    if not report.created_by and has_permission(user_role, ["consultant"]):
        return True

    return False


def can_access_finding(user: models.User, finding, adapter: StorageAdapter) -> bool:
    """Return True if user can access the finding (via org membership or report share)."""
    if user.role == "admin":
        return True
    orgs = list(adapter.get_user_organizations(user.id))
    org_ids = [o.id for o in orgs]
    if finding.organization_id in org_ids:
        return True
    if finding.report_id:
        return adapter.get_report_share(finding.report_id, user.id) is not None
    return False


def can_manage_report_shares(user: models.User, report: models.Report, adapter: StorageAdapter) -> bool:
    """Return True if user can share/unshare the report."""
    if user.role == "admin":
        return True

    org_id = report.organization_id or SYSTEM_ORG_ID
    user_role = get_user_role_in_org(user.id, org_id, adapter)
    if not user_role:
        return False

    if user_role in ("org_admin", "org_owner", "admin"):
        return True

    return report.created_by == user.id if report.created_by else False


def verify_resource_org_access(
    user: models.User,
    resource_org_id: str,
    adapter: StorageAdapter,
    resource_type: str = "resource"
) -> None:
    """
    Verify user has access to a resource's organization.
    Raises HTTPException(403) if not.
    
    This is a critical security check - ALWAYS call this when accessing
    a resource by ID to prevent cross-org data leakage.
    """
    if user.role == "admin":
        return  # System admins can access any org
    
    user_role = get_user_role_in_org(user.id, resource_org_id, adapter)
    if not user_role:
        raise HTTPException(
            status_code=403,
            detail=f"Access denied: {resource_type} belongs to a different organization"
        )
