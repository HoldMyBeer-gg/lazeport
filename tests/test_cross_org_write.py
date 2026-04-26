"""
Cross-Organization Write Correctness Tests

These tests verify that resources created via the API endpoints
are assigned to the correct organization — not silently falling
back to the system org.

Also verifies that update_report rejects cross-org client/application
assignments.

Covers:
  BUG 1: POST /api/admin/applications must assign to the user's org
  BUG 2: POST /api/admin/finding-templates must assign to the user's org
  BUG 3: PUT /api/admin/reports/{id} must reject cross-org client/app
"""
import uuid

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db import get_adapter
from app.services.auth import get_current_user


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def two_orgs():
    """Two orgs, each with an org_admin user, a client, and an app."""
    adapter = get_adapter()
    adapter.init()
    suffix = uuid.uuid4().hex[:8]

    org_a = adapter.create_organization(name=f"Write Org A {suffix}", slug=f"write-org-a-{suffix}")
    user_a = adapter.upsert_user(
        email=f"write-a-{suffix}@test.com", name="Write User A",
        provider="local", role="user",
    )
    adapter.create_organization_member(
        org_id=org_a.id, user_id=user_a.id, role="org_admin",
    )
    client_a = adapter.create_client(f"Write Team A {suffix}", organization_id=org_a.id)
    app_a = adapter.create_application(f"Write App A {suffix}", organization_id=org_a.id)

    org_b = adapter.create_organization(name=f"Write Org B {suffix}", slug=f"write-org-b-{suffix}")
    user_b = adapter.upsert_user(
        email=f"write-b-{suffix}@test.com", name="Write User B",
        provider="local", role="user",
    )
    adapter.create_organization_member(
        org_id=org_b.id, user_id=user_b.id, role="org_admin",
    )
    client_b = adapter.create_client(f"Write Team B {suffix}", organization_id=org_b.id)
    app_b = adapter.create_application(f"Write App B {suffix}", organization_id=org_b.id)

    yield {
        "org_a": org_a, "user_a": user_a,
        "client_a": client_a, "app_a": app_a,
        "org_b": org_b, "user_b": user_b,
        "client_b": client_b, "app_b": app_b,
    }

    app.dependency_overrides.clear()


# ── BUG 1: Application org assignment ────────────────────────────

def test_created_application_belongs_to_users_org(client, two_orgs):
    """POST /api/admin/applications assigns the app to the requesting user's org."""
    app.dependency_overrides[get_current_user] = lambda: two_orgs["user_a"]

    resp = client.post(
        "/api/admin/applications",
        json={"name": "New Web App Via API", "type": "web"},
    )
    assert resp.status_code == 200, f"body: {resp.text}"
    created = resp.json()
    assert created["organization_id"] == two_orgs["org_a"].id


def test_created_application_not_visible_to_other_org(client, two_orgs):
    """An app created by User A must not appear in User B's list."""
    app.dependency_overrides[get_current_user] = lambda: two_orgs["user_a"]
    resp = client.post(
        "/api/admin/applications",
        json={"name": "OrgA Only App", "type": "api"},
    )
    assert resp.status_code == 200
    created_id = resp.json()["id"]

    app.dependency_overrides[get_current_user] = lambda: two_orgs["user_b"]
    resp = client.get("/api/admin/applications")
    assert resp.status_code == 200
    app_ids = [a["id"] for a in resp.json()]
    assert created_id not in app_ids


# ── BUG 2: Finding template org assignment ───────────────────────

def test_created_finding_template_belongs_to_users_org(client, two_orgs):
    """POST /api/admin/finding-templates assigns the template to the user's org."""
    app.dependency_overrides[get_current_user] = lambda: two_orgs["user_a"]

    resp = client.post(
        "/api/admin/finding-templates",
        json={"name": "API Template", "content": "## {{TITLE}}"},
    )
    assert resp.status_code == 200
    created = resp.json()
    assert created["organization_id"] == two_orgs["org_a"].id


def test_created_finding_template_not_visible_to_other_org(client, two_orgs):
    """A template created by User A must not appear in User B's list."""
    app.dependency_overrides[get_current_user] = lambda: two_orgs["user_a"]
    resp = client.post(
        "/api/admin/finding-templates",
        json={"name": "OrgA Template", "content": "# OrgA"},
    )
    assert resp.status_code == 200
    created_id = resp.json()["id"]

    app.dependency_overrides[get_current_user] = lambda: two_orgs["user_b"]
    resp = client.get("/api/admin/finding-templates")
    assert resp.status_code == 200
    template_ids = [t["id"] for t in resp.json()]
    assert created_id not in template_ids


# ── BUG 3: Report update cross-org client/application ─────────────

def test_update_report_rejects_cross_org_client(client, two_orgs):
    """PUT /api/admin/reports rejects a client_id from a different org."""
    adapter = get_adapter()
    report_a = adapter.create_report(
        "CrossOrg Report A",
        organization_id=two_orgs["org_a"].id,
        created_by=two_orgs["user_a"].id,
        client_id=two_orgs["client_a"].id,
        application_id=two_orgs["app_a"].id,
    )

    app.dependency_overrides[get_current_user] = lambda: two_orgs["user_a"]

    resp = client.put(
        f"/api/admin/reports/{report_a.id}",
        json={"name": "CrossOrg Report A", "client_id": two_orgs["client_b"].id},
    )
    assert resp.status_code == 403
    assert "organization" in resp.json()["detail"].lower()


def test_update_report_rejects_cross_org_application(client, two_orgs):
    """PUT /api/admin/reports rejects an application_id from a different org."""
    adapter = get_adapter()
    report_a = adapter.create_report(
        "CrossOrg Report A2",
        organization_id=two_orgs["org_a"].id,
        created_by=two_orgs["user_a"].id,
        client_id=two_orgs["client_a"].id,
        application_id=two_orgs["app_a"].id,
    )

    app.dependency_overrides[get_current_user] = lambda: two_orgs["user_a"]

    resp = client.put(
        f"/api/admin/reports/{report_a.id}",
        json={"name": "CrossOrg Report A2", "application_id": two_orgs["app_b"].id},
    )
    assert resp.status_code == 403
    assert "organization" in resp.json()["detail"].lower()


def test_update_report_accepts_same_org_client_and_app(client, two_orgs):
    """PUT /api/admin/reports accepts client/app from the same org as the report."""
    adapter = get_adapter()
    report_a = adapter.create_report(
        "SameOrg Report",
        organization_id=two_orgs["org_a"].id,
        created_by=two_orgs["user_a"].id,
    )

    app.dependency_overrides[get_current_user] = lambda: two_orgs["user_a"]

    resp = client.put(
        f"/api/admin/reports/{report_a.id}",
        json={
            "name": "SameOrg Report",
            "client_id": two_orgs["client_a"].id,
            "application_id": two_orgs["app_a"].id,
        },
    )
    assert resp.status_code == 200
    updated = resp.json()
    assert updated["client_id"] == two_orgs["client_a"].id
    assert updated["application_id"] == two_orgs["app_a"].id
