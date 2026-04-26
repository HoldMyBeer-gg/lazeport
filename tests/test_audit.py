"""Tests for app.services.audit."""
import json
from unittest.mock import MagicMock

import pytest

from app.db import get_adapter
from app.services.audit import log_auth, log_create, log_delete, log_update


def test_log_create_records_audit():
    """log_create records a create action in the audit log."""
    adapter = get_adapter()
    adapter.init()
    org_id = adapter.ensure_system_org()
    user = adapter.upsert_user(email="audit-create@test.com", name="Audit User", provider="local")
    resource_id = "res-123"
    resource_type = "client"

    log_create(adapter, org_id, user.id, resource_type, resource_id, name="Test Team")

    logs = list(adapter.list_audit_logs(org_id, limit=10))
    assert any(
        l.action == "create" and l.resource_type == resource_type and l.resource_id == resource_id
        for l in logs
    )
    create_log = next(l for l in logs if l.action == "create" and l.resource_type == resource_type)
    details = json.loads(create_log.details or "{}")
    assert details.get("name") == "Test Team"


def test_log_update_records_audit():
    """log_update records an update action in the audit log."""
    adapter = get_adapter()
    adapter.init()
    org_id = adapter.ensure_system_org()
    user = adapter.upsert_user(email="audit-update@test.com", name="Audit User", provider="local")
    resource_id = "res-456"
    resource_type = "report"

    log_update(adapter, org_id, user.id, resource_type, resource_id, fields=["title", "status"])

    logs = list(adapter.list_audit_logs(org_id, limit=10))
    assert any(
        l.action == "update" and l.resource_type == resource_type and l.resource_id == resource_id
        for l in logs
    )
    update_log = next(l for l in logs if l.action == "update" and l.resource_type == resource_type)
    details = json.loads(update_log.details or "{}")
    assert "fields" in details
    assert "title" in details["fields"]
    assert "status" in details["fields"]


def test_log_delete_records_audit():
    """log_delete records a delete action in the audit log."""
    adapter = get_adapter()
    adapter.init()
    org_id = adapter.ensure_system_org()
    user = adapter.upsert_user(email="audit-delete@test.com", name="Audit User", provider="local")
    resource_id = "res-789"
    resource_type = "finding"

    log_delete(adapter, org_id, user.id, resource_type, resource_id)

    logs = list(adapter.list_audit_logs(org_id, limit=10))
    assert any(
        l.action == "delete" and l.resource_type == resource_type and l.resource_id == resource_id
        for l in logs
    )


def test_log_with_request_captures_ip_and_user_agent():
    """log_auth with request captures IP and user agent."""
    adapter = get_adapter()
    adapter.init()
    org_id = adapter.ensure_system_org()
    user = adapter.upsert_user(email="audit-request@test.com", name="Audit User", provider="local")

    mock_request = MagicMock()
    mock_request.client.host = "192.168.1.100"
    mock_request.headers.get.return_value = "Mozilla/5.0 TestBrowser"

    log_auth(adapter, org_id, user.id, "login", request=mock_request)

    logs = list(adapter.list_audit_logs(org_id, limit=10))
    auth_log = next(l for l in logs if l.action == "login" and l.resource_type == "auth")
    assert auth_log.ip_address == "192.168.1.100"
    assert auth_log.user_agent == "Mozilla/5.0 TestBrowser"
