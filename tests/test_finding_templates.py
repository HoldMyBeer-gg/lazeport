"""Tests for finding-template CRUD endpoints."""
from fastapi.testclient import TestClient

from app.db import get_adapter
from app.main import app

client = TestClient(app)

FAKE_UUID = "00000000-0000-0000-0000-000000099999"


def test_finding_template_crud():
    # list should start empty
    r = client.get("/api/admin/finding-templates")
    assert r.status_code == 200
    assert r.json() == []

    # create
    r = client.post(
        "/api/admin/finding-templates",
        json={"name": "OWASP Web", "content": "# {{TITLE}}\n## Summary\n{{SUMMARY}}"},
    )
    assert r.status_code == 200
    t = r.json()
    assert t["name"] == "OWASP Web"
    assert "TITLE" in t["content"]
    tid = t["id"]
    assert isinstance(tid, str) and len(tid) > 8  # UUID

    # list now has one
    r = client.get("/api/admin/finding-templates")
    assert r.status_code == 200
    assert len(r.json()) == 1

    # update
    r = client.put(
        f"/api/admin/finding-templates/{tid}",
        json={"name": "OWASP Web v2", "content": "updated content"},
    )
    assert r.status_code == 200
    assert r.json()["name"] == "OWASP Web v2"
    assert r.json()["content"] == "updated content"

    # delete
    r = client.delete(f"/api/admin/finding-templates/{tid}")
    assert r.status_code == 200

    # list is empty again
    r = client.get("/api/admin/finding-templates")
    assert r.status_code == 200
    assert r.json() == []

    adapter = get_adapter()
    org_id = adapter.ensure_system_org()
    logs = list(adapter.list_audit_logs(org_id, limit=50))
    assert any(l.action == "create" and l.resource_type == "finding_template" for l in logs)
    assert any(l.action == "update" and l.resource_type == "finding_template" for l in logs)
    assert any(l.action == "delete" and l.resource_type == "finding_template" for l in logs)


def test_finding_template_validation():
    # empty name should fail
    r = client.post(
        "/api/admin/finding-templates",
        json={"name": "  ", "content": "something"},
    )
    assert r.status_code == 400

    # update non-existent should 404
    r = client.put(
        f"/api/admin/finding-templates/{FAKE_UUID}",
        json={"name": "nope", "content": "x"},
    )
    assert r.status_code == 404

    # delete non-existent should 404
    r = client.delete(f"/api/admin/finding-templates/{FAKE_UUID}")
    assert r.status_code == 404
