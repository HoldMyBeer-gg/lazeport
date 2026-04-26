"""Tests for HIGH-4: require_resource_owner Uses Hardcoded System Org.

Tests verify that the require_resource_owner decorator correctly checks
permissions in the resource's actual organization, not the System org.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db import get_adapter
from app.services.auth import get_current_user, hash_password


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
def multi_org_with_resources():
    """Create two organizations with clients, apps, and reports."""
    adapter = get_adapter()
    adapter.init()
    
    # Create Organization A
    org_a = adapter.create_organization(name="Organization A", slug="org-a-ro")
    
    # Org A admin
    admin_a = adapter.upsert_user(
        email="admin-a@orga.com",
        name="Admin A",
        provider="local",
        role="user"
    )
    adapter.create_organization_member(org_a.id, admin_a.id, "org_admin")
    
    # Org A consultant
    consultant_a = adapter.upsert_user(
        email="consultant-a@orga.com",
        name="Consultant A",
        provider="local",
        role="user"
    )
    adapter.create_organization_member(org_a.id, consultant_a.id, "consultant")
    
    # Create client and app in Org A
    client_a = adapter.create_client(name="Team A", organization_id=org_a.id)
    app_a = adapter.create_application(
        name="App A",
        type="web",
        description="",
        organization_id=org_a.id
    )
    
    # Create report in Org A by consultant
    report_a = adapter.create_report(
        "Report A",
        organization_id=org_a.id,
        created_by=consultant_a.id,
        client_id=client_a.id,
        application_id=app_a.id,
    )
    
    # Create Organization B
    org_b = adapter.create_organization(name="Organization B", slug="org-b-ro")
    
    # Org B consultant
    consultant_b = adapter.upsert_user(
        email="consultant-b@orgb.com",
        name="Consultant B",
        provider="local",
        role="user"
    )
    adapter.create_organization_member(org_b.id, consultant_b.id, "consultant")
    
    # Create client and app in Org B
    client_b = adapter.create_client(name="Team B", organization_id=org_b.id)
    app_b = adapter.create_application(
        name="App B",
        type="web",
        description="",
        organization_id=org_b.id
    )
    
    # Create report in Org B by consultant
    report_b = adapter.create_report(
        "Report B",
        organization_id=org_b.id,
        created_by=consultant_b.id,
        client_id=client_b.id,
        application_id=app_b.id,
    )
    
    return {
        "org_a": org_a,
        "org_b": org_b,
        "admin_a": admin_a,
        "consultant_a": consultant_a,
        "consultant_b": consultant_b,
        "client_a": client_a,
        "client_b": client_b,
        "app_a": app_a,
        "app_b": app_b,
        "report_a": report_a,
        "report_b": report_b,
    }


def test_consultant_can_delete_own_report_in_correct_org(multi_org_with_resources):
    """Test that consultant can delete their own report (HIGH-4 fix ensures correct org check)."""
    setup = multi_org_with_resources
    
    # Org A consultant deletes their own report
    client = _make_client_as(setup["consultant_a"])
    response = client.delete(f"/api/admin/reports/{setup['report_a'].id}")
    
    # Should succeed
    assert response.status_code == 200


def test_consultant_cannot_delete_other_consultant_report_same_org(multi_org_with_resources):
    """Test that consultant cannot delete another consultant's report in same org."""
    setup = multi_org_with_resources
    adapter = get_adapter()
    
    # Create second consultant in Org A
    consultant_a2 = adapter.upsert_user(
        email="consultant-a2@orga.com",
        name="Consultant A2",
        provider="local",
        role="user"
    )
    adapter.create_organization_member(setup["org_a"].id, consultant_a2.id, "consultant")
    
    # Create report by consultant_a2
    client_a = setup["client_a"]
    app_a = setup["app_a"]
    report_a2 = adapter.create_report(
        "Report A2",
        organization_id=setup["org_a"].id,
        created_by=consultant_a2.id,
        client_id=client_a.id,
        application_id=app_a.id,
    )
    
    # consultant_a tries to delete consultant_a2's report
    client = _make_client_as(setup["consultant_a"])
    response = client.delete(f"/api/admin/reports/{report_a2.id}")
    
    # Should be forbidden
    assert response.status_code == 403


def test_org_admin_can_delete_any_report_in_their_org(multi_org_with_resources):
    """Test that org admin can delete any report in their org (HIGH-4 fix uses correct org)."""
    setup = multi_org_with_resources
    
    # Org A admin deletes consultant's report
    client = _make_client_as(setup["admin_a"])
    response = client.delete(f"/api/admin/reports/{setup['report_a'].id}")
    
    # Should succeed (org admin has permission)
    assert response.status_code == 200


def test_consultant_cannot_delete_client_they_did_not_create(multi_org_with_resources):
    """Test that consultant cannot delete client (created by system, not by user)."""
    setup = multi_org_with_resources
    
    # Consultant tries to delete client
    client = _make_client_as(setup["consultant_a"])
    response = client.delete(f"/api/admin/clients/{setup['client_a'].id}")
    
    # Should be forbidden (requires org_admin)
    assert response.status_code == 403


def test_org_admin_from_different_org_cannot_delete_report(multi_org_with_resources):
    """Test that org admin from Org A cannot delete report from Org B (HIGH-4 fix)."""
    setup = multi_org_with_resources
    
    # Org A admin tries to delete Org B's report
    client = _make_client_as(setup["admin_a"])
    response = client.delete(f"/api/admin/reports/{setup['report_b'].id}")
    
    # Should be forbidden (admin_a has no role in Org B)
    assert response.status_code in [403, 404]


def test_consultant_from_different_org_cannot_access_report(multi_org_with_resources):
    """Test that consultant from Org B cannot access report from Org A."""
    setup = multi_org_with_resources
    
    # Org B consultant tries to delete Org A's report
    client = _make_client_as(setup["consultant_b"])
    response = client.delete(f"/api/admin/reports/{setup['report_a'].id}")
    
    # Should be forbidden
    assert response.status_code in [403, 404]


def test_permission_check_uses_resource_org_not_system_org(multi_org_with_resources):
    """Test that permission check uses resource's org, not System org (core HIGH-4 fix)."""
    setup = multi_org_with_resources
    adapter = get_adapter()
    
    # Create a third consultant who is only in Org B
    consultant_only_b = adapter.upsert_user(
        email="only-b@orgb.com",
        name="Only B",
        provider="local",
        role="user"
    )
    adapter.create_organization_member(setup["org_b"].id, consultant_only_b.id, "consultant")
    
    # consultant_only_b tries to access Org A's report
    # Before HIGH-4 fix: would check role in System org (wrong)
    # After HIGH-4 fix: checks role in Org A (correct), finds none, denies access
    client = _make_client_as(consultant_only_b)
    response = client.delete(f"/api/admin/reports/{setup['report_a'].id}")
    
    # Should be forbidden because user has no role in Org A
    assert response.status_code in [403, 404]


def test_readonly_cannot_delete_finding_even_if_creator(multi_org_with_resources):
    """Test that readonly user cannot delete findings, even when they created the report."""
    setup = multi_org_with_resources
    adapter = get_adapter()

    # Create readonly user in Org A
    readonly_user = adapter.upsert_user(
        email="readonly@orga.com",
        name="ReadOnly",
        provider="local",
        role="user"
    )
    adapter.create_organization_member(setup["org_a"].id, readonly_user.id, "readonly")

    # Create report and finding with readonly as creator (e.g. they were demoted from consultant)
    report = adapter.create_report(
        "ReadOnly Creator Report",
        organization_id=setup["org_a"].id,
        created_by=readonly_user.id,
        client_id=setup["client_a"].id,
        application_id=setup["app_a"].id,
    )
    finding = adapter.create_finding(
        report_id=report.id,
        title="Test Finding",
        content_json='{"Summary": "Test"}',
        notes="",
        template="",
    )

    # Readonly tries to delete the finding
    client = _make_client_as(readonly_user)
    response = client.delete(f"/api/admin/findings/{finding.id}")

    assert response.status_code == 403


def test_system_admin_can_access_any_resource_any_org(multi_org_with_resources):
    """Test that system admin can access resources in any organization."""
    setup = multi_org_with_resources
    adapter = get_adapter()
    
    # Create system admin
    system_admin = adapter.upsert_user(
        email="sysadmin@system.com",
        name="System Admin",
        provider="local",
        role="admin"
    )
    
    # System admin can delete report from Org A
    client = _make_client_as(system_admin)
    response = client.delete(f"/api/admin/reports/{setup['report_a'].id}")
    
    # Should succeed
    assert response.status_code == 200
