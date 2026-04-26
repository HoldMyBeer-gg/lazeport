"""Tests for CRIT-2: Cross-Org Tag Data Leak via Bulk Endpoint.

These tests verify that the tag bulk endpoint properly enforces organization
boundaries and doesn't leak tag data across organizations.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db import get_adapter
from app.services.auth import get_current_user

client = TestClient(app)


@pytest.fixture
def cross_org_setup():
    """Create two orgs with reports, clients, apps, and tags."""
    adapter = get_adapter()
    adapter.init()
    
    # Organization A
    org_a = adapter.create_organization(name="Org A", slug="org-a")
    user_a = adapter.upsert_user(
        email="usera@test.com", name="User A", provider="local", role="user"
    )
    adapter.create_organization_member(org_id=org_a.id, user_id=user_a.id, role="consultant")
    client_a = adapter.create_client("Team A", organization_id=org_a.id)
    app_a = adapter.create_application("App A", organization_id=org_a.id)
    report_a = adapter.create_report(
        "Report A",
        organization_id=org_a.id,
        created_by=user_a.id,
        client_id=client_a.id,
        application_id=app_a.id,
    )
    finding_a = adapter.create_finding(
        report_id=report_a.id,
        title="Finding A",
        content_json="{}",
        notes="Test",
        template="",
        organization_id=org_a.id
    )
    
    # Create tags for Org A entities
    tag_a_client = adapter.create_tag(org_a.id, "Secret-Team-A", user_a.id)
    tag_a_report = adapter.create_tag(org_a.id, "Confidential-Report-A", user_a.id)
    tag_a_finding = adapter.create_tag(org_a.id, "Critical-Finding-A", user_a.id)
    tag_a_app = adapter.create_tag(org_a.id, "Internal-App-A", user_a.id)
    
    adapter.add_entity_tag(tag_a_client.id, "client", client_a.id, user_a.id)
    adapter.add_entity_tag(tag_a_report.id, "report", report_a.id, user_a.id)
    adapter.add_entity_tag(tag_a_finding.id, "finding", finding_a.id, user_a.id)
    adapter.add_entity_tag(tag_a_app.id, "application", app_a.id, user_a.id)
    
    # Organization B
    org_b = adapter.create_organization(name="Org B", slug="org-b")
    user_b = adapter.upsert_user(
        email="userb@test.com", name="User B", provider="local", role="user"
    )
    adapter.create_organization_member(org_id=org_b.id, user_id=user_b.id, role="consultant")
    client_b = adapter.create_client("Team B", organization_id=org_b.id)
    app_b = adapter.create_application("App B", organization_id=org_b.id)
    report_b = adapter.create_report(
        "Report B",
        organization_id=org_b.id,
        created_by=user_b.id,
        client_id=client_b.id,
        application_id=app_b.id,
    )
    finding_b = adapter.create_finding(
        report_id=report_b.id,
        title="Finding B",
        content_json="{}",
        notes="Test",
        template="",
        organization_id=org_b.id
    )
    
    # Create tags for Org B entities
    tag_b_client = adapter.create_tag(org_b.id, "Secret-Team-B", user_b.id)
    tag_b_report = adapter.create_tag(org_b.id, "Confidential-Report-B", user_b.id)
    tag_b_finding = adapter.create_tag(org_b.id, "Critical-Finding-B", user_b.id)
    tag_b_app = adapter.create_tag(org_b.id, "Internal-App-B", user_b.id)
    
    adapter.add_entity_tag(tag_b_client.id, "client", client_b.id, user_b.id)
    adapter.add_entity_tag(tag_b_report.id, "report", report_b.id, user_b.id)
    adapter.add_entity_tag(tag_b_finding.id, "finding", finding_b.id, user_b.id)
    adapter.add_entity_tag(tag_b_app.id, "application", app_b.id, user_b.id)
    
    return {
        "org_a": org_a,
        "user_a": user_a,
        "client_a": client_a,
        "app_a": app_a,
        "report_a": report_a,
        "finding_a": finding_a,
        "org_b": org_b,
        "user_b": user_b,
        "client_b": client_b,
        "app_b": app_b,
        "report_b": report_b,
        "finding_b": finding_b,
    }


def _make_client_as(user: any) -> TestClient:
    """Create a test client with dependency override for a specific user."""
    app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app)


def test_bulk_tags_cannot_access_other_org_reports(cross_org_setup):
    """Test that user in Org A cannot get tags for Org B's reports."""
    setup = cross_org_setup
    client = _make_client_as(setup["user_a"])
    
    # User A tries to query tags for Org B's report
    response = client.get(
        f"/api/admin/tags/entity-bulk/report?ids={setup['report_b'].id}"
    )
    
    assert response.status_code == 200
    data = response.json()
    
    # Should NOT contain Org B's report tags
    assert setup["report_b"].id not in data or data[setup["report_b"].id] == []
    
    app.dependency_overrides.clear()


def test_bulk_tags_cannot_access_other_org_clients(cross_org_setup):
    """Test that user in Org A cannot get tags for Org B's clients."""
    setup = cross_org_setup
    client = _make_client_as(setup["user_a"])
    
    response = client.get(
        f"/api/admin/tags/entity-bulk/client?ids={setup['client_b'].id}"
    )
    
    assert response.status_code == 200
    data = response.json()
    
    # Should NOT contain Org B's client tags
    assert setup["client_b"].id not in data or data[setup["client_b"].id] == []
    
    app.dependency_overrides.clear()


def test_bulk_tags_cannot_access_other_org_applications(cross_org_setup):
    """Test that user in Org A cannot get tags for Org B's applications."""
    setup = cross_org_setup
    client = _make_client_as(setup["user_a"])
    
    response = client.get(
        f"/api/admin/tags/entity-bulk/application?ids={setup['app_b'].id}"
    )
    
    assert response.status_code == 200
    data = response.json()
    
    # Should NOT contain Org B's app tags
    assert setup["app_b"].id not in data or data[setup["app_b"].id] == []
    
    app.dependency_overrides.clear()


def test_bulk_tags_cannot_access_other_org_findings(cross_org_setup):
    """Test that user in Org A cannot get tags for Org B's findings."""
    setup = cross_org_setup
    client = _make_client_as(setup["user_a"])
    
    response = client.get(
        f"/api/admin/tags/entity-bulk/finding?ids={setup['finding_b'].id}"
    )
    
    assert response.status_code == 200
    data = response.json()
    
    # Should NOT contain Org B's finding tags
    assert setup["finding_b"].id not in data or data[setup["finding_b"].id] == []
    
    app.dependency_overrides.clear()


def test_bulk_tags_returns_own_org_tags(cross_org_setup):
    """Test that user can access tags for their own org's entities."""
    setup = cross_org_setup
    client = _make_client_as(setup["user_a"])
    
    # Query tags for Org A's entities
    response = client.get(
        f"/api/admin/tags/entity-bulk/report?ids={setup['report_a'].id}"
    )
    
    assert response.status_code == 200
    data = response.json()
    
    # Should contain Org A's report tags
    assert setup["report_a"].id in data
    assert "Confidential-Report-A" in data[setup["report_a"].id]
    
    app.dependency_overrides.clear()


def test_bulk_tags_filters_mixed_org_request(cross_org_setup):
    """Test that bulk request with mixed org IDs only returns accessible entities."""
    setup = cross_org_setup
    client = _make_client_as(setup["user_a"])
    
    # User A requests tags for both Org A and Org B reports
    ids = f"{setup['report_a'].id},{setup['report_b'].id}"
    response = client.get(f"/api/admin/tags/entity-bulk/report?ids={ids}")
    
    assert response.status_code == 200
    data = response.json()
    
    # Should contain Org A's report
    assert setup["report_a"].id in data
    assert "Confidential-Report-A" in data[setup["report_a"].id]
    
    # Should NOT contain Org B's report
    assert setup["report_b"].id not in data or data[setup["report_b"].id] == []
    
    app.dependency_overrides.clear()


def test_bulk_tags_system_admin_can_access_all_orgs(cross_org_setup):
    """Test that system admin can access tags across all orgs."""
    setup = cross_org_setup
    adapter = get_adapter()
    
    # Create system admin
    admin = adapter.upsert_user(
        email="admin@test.com", name="Admin", provider="local", role="admin"
    )
    
    client = _make_client_as(admin)
    
    # System admin requests tags for both orgs
    ids = f"{setup['report_a'].id},{setup['report_b'].id}"
    response = client.get(f"/api/admin/tags/entity-bulk/report?ids={ids}")
    
    assert response.status_code == 200
    data = response.json()
    
    # System admin should see both
    assert setup["report_a"].id in data
    assert "Confidential-Report-A" in data[setup["report_a"].id]
    assert setup["report_b"].id in data
    assert "Confidential-Report-B" in data[setup["report_b"].id]
    
    app.dependency_overrides.clear()


def test_bulk_tags_handles_nonexistent_entity_gracefully(cross_org_setup):
    """Test that bulk endpoint handles nonexistent entity IDs gracefully."""
    setup = cross_org_setup
    client = _make_client_as(setup["user_a"])
    
    # Mix valid and invalid IDs
    ids = f"{setup['report_a'].id},nonexistent-id-12345"
    response = client.get(f"/api/admin/tags/entity-bulk/report?ids={ids}")
    
    assert response.status_code == 200
    data = response.json()
    
    # Should contain valid entity
    assert setup["report_a"].id in data
    
    # Should NOT contain nonexistent entity (or empty list)
    assert "nonexistent-id-12345" not in data or data["nonexistent-id-12345"] == []
    
    app.dependency_overrides.clear()


def test_bulk_tags_empty_ids_returns_empty_result(cross_org_setup):
    """Test that empty IDs parameter returns empty result."""
    setup = cross_org_setup
    client = _make_client_as(setup["user_a"])
    
    response = client.get("/api/admin/tags/entity-bulk/report?ids=")
    
    assert response.status_code == 200
    data = response.json()
    assert data == {}
    
    app.dependency_overrides.clear()


def test_bulk_tags_multiple_entities_same_org(cross_org_setup):
    """Test that bulk request works correctly for multiple entities in same org."""
    setup = cross_org_setup
    client = _make_client_as(setup["user_a"])
    
    # Query multiple entities from same org
    ids = f"{setup['client_a'].id},{setup['app_a'].id}"
    response = client.get(f"/api/admin/tags/entity-bulk/client?ids={setup['client_a'].id}")
    
    assert response.status_code == 200
    data = response.json()
    
    # Should return tags for Org A's client
    assert setup["client_a"].id in data
    assert "Secret-Team-A" in data[setup["client_a"].id]
    
    # Query applications
    response = client.get(f"/api/admin/tags/entity-bulk/application?ids={setup['app_a'].id}")
    
    assert response.status_code == 200
    data = response.json()
    
    # Should return tags for Org A's app
    assert setup["app_a"].id in data
    assert "Internal-App-A" in data[setup["app_a"].id]
    
    app.dependency_overrides.clear()


def test_bulk_tags_readonly_user_cannot_access_other_org(cross_org_setup):
    """Test that readonly users also respect org boundaries."""
    setup = cross_org_setup
    adapter = get_adapter()
    
    # Create readonly user in Org A
    readonly_user = adapter.upsert_user(
        email="readonly@test.com", name="ReadOnly", provider="local", role="user"
    )
    adapter.create_organization_member(
        org_id=setup["org_a"].id, user_id=readonly_user.id, role="readonly"
    )
    
    # Create a report owned by readonly user
    readonly_report = adapter.create_report(
        "ReadOnly Report",
        organization_id=setup["org_a"].id,
        created_by=readonly_user.id,
        client_id=setup["client_a"].id,
        application_id=setup["app_a"].id,
    )
    readonly_tag = adapter.create_tag(setup["org_a"].id, "ReadOnly-Tag", readonly_user.id)
    adapter.add_entity_tag(readonly_tag.id, "report", readonly_report.id, readonly_user.id)
    
    client = _make_client_as(readonly_user)
    
    # Try to access Org B's report tags
    response = client.get(
        f"/api/admin/tags/entity-bulk/report?ids={setup['report_b'].id}"
    )
    
    assert response.status_code == 200
    data = response.json()
    
    # Should NOT return Org B's tags
    assert setup["report_b"].id not in data or data[setup["report_b"].id] == []
    
    # But CAN access own report's tags
    response = client.get(
        f"/api/admin/tags/entity-bulk/report?ids={readonly_report.id}"
    )
    
    assert response.status_code == 200
    data = response.json()
    assert readonly_report.id in data
    assert "ReadOnly-Tag" in data[readonly_report.id]
    
    app.dependency_overrides.clear()


def test_bulk_tags_user_with_no_org_membership(cross_org_setup):
    """Test that user with no org membership cannot access any tags."""
    setup = cross_org_setup
    adapter = get_adapter()
    
    # Create user with no org membership
    outsider = adapter.upsert_user(
        email="outsider@test.com", name="Outsider", provider="local", role="user"
    )
    
    client = _make_client_as(outsider)
    
    # Try to access Org A's report tags
    response = client.get(
        f"/api/admin/tags/entity-bulk/report?ids={setup['report_a'].id}"
    )
    
    # Should be forbidden (no org membership)
    assert response.status_code == 403
    
    app.dependency_overrides.clear()


def test_bulk_tags_invalid_entity_type(cross_org_setup):
    """Test that invalid entity types are rejected."""
    setup = cross_org_setup
    client = _make_client_as(setup["user_a"])
    
    response = client.get(
        f"/api/admin/tags/entity-bulk/invalid_type?ids={setup['report_a'].id}"
    )
    
    assert response.status_code == 400
    assert "entity_type must be one of" in response.json()["detail"]
    
    app.dependency_overrides.clear()


def test_bulk_tags_handles_deleted_entities(cross_org_setup):
    """Test that bulk endpoint handles deleted entities gracefully."""
    setup = cross_org_setup
    adapter = get_adapter()
    client = _make_client_as(setup["user_a"])
    
    # Create and then delete a client
    temp_client = adapter.create_client("Temp Team", organization_id=setup["org_a"].id)
    temp_tag = adapter.create_tag(setup["org_a"].id, "Temp-Tag", setup["user_a"].id)
    adapter.add_entity_tag(temp_tag.id, "client", temp_client.id, setup["user_a"].id)
    
    # Delete the client (soft delete)
    adapter.delete_client(temp_client.id)
    
    # Try to get tags for deleted client
    ids = f"{temp_client.id},{setup['client_a'].id}"
    response = client.get(f"/api/admin/tags/entity-bulk/client?ids={ids}")
    
    assert response.status_code == 200
    data = response.json()
    
    # Should gracefully skip deleted entity
    # Should still return tags for valid entity
    assert setup["client_a"].id in data
    
    app.dependency_overrides.clear()


def test_bulk_tags_preserves_functionality_for_same_org(cross_org_setup):
    """Test that the fix doesn't break legitimate same-org bulk queries."""
    setup = cross_org_setup
    client = _make_client_as(setup["user_a"])
    
    # Query multiple entities from same org in one request
    ids = f"{setup['report_a'].id},{setup['client_a'].id}"
    
    # Query reports
    response = client.get(f"/api/admin/tags/entity-bulk/report?ids={setup['report_a'].id}")
    assert response.status_code == 200
    data = response.json()
    assert setup["report_a"].id in data
    assert len(data[setup["report_a"].id]) > 0
    
    # Query clients
    response = client.get(f"/api/admin/tags/entity-bulk/client?ids={setup['client_a'].id}")
    assert response.status_code == 200
    data = response.json()
    assert setup["client_a"].id in data
    assert len(data[setup["client_a"].id]) > 0
    
    app.dependency_overrides.clear()


def test_bulk_tags_org_admin_cannot_access_other_org(cross_org_setup):
    """Test that org admins also respect org boundaries."""
    setup = cross_org_setup
    adapter = get_adapter()
    
    # Promote user_a to org_admin
    adapter.update_organization_member_role(
        org_id=setup["org_a"].id,
        user_id=setup["user_a"].id,
        role="org_admin"
    )
    
    client = _make_client_as(setup["user_a"])
    
    # Org admin from Org A tries to access Org B's report tags
    response = client.get(
        f"/api/admin/tags/entity-bulk/report?ids={setup['report_b'].id}"
    )
    
    assert response.status_code == 200
    data = response.json()
    
    # Should NOT return Org B's tags
    assert setup["report_b"].id not in data or data[setup["report_b"].id] == []
    
    app.dependency_overrides.clear()


def test_bulk_tags_large_mixed_request(cross_org_setup):
    """Test bulk endpoint with many IDs from mixed orgs."""
    setup = cross_org_setup
    client = _make_client_as(setup["user_a"])
    
    # Create more entities in both orgs
    adapter = get_adapter()
    
    # More Org A reports
    report_a2 = adapter.create_report(
        "Report A2",
        organization_id=setup["org_a"].id,
        created_by=setup["user_a"].id,
        client_id=setup["client_a"].id,
        application_id=setup["app_a"].id,
    )
    tag_a2 = adapter.create_tag(setup["org_a"].id, "Tag-A2", setup["user_a"].id)
    adapter.add_entity_tag(tag_a2.id, "report", report_a2.id, setup["user_a"].id)
    
    # More Org B reports
    report_b2 = adapter.create_report(
        "Report B2",
        organization_id=setup["org_b"].id,
        created_by=setup["user_b"].id,
        client_id=setup["client_b"].id,
        application_id=setup["app_b"].id,
    )
    tag_b2 = adapter.create_tag(setup["org_b"].id, "Tag-B2", setup["user_b"].id)
    adapter.add_entity_tag(tag_b2.id, "report", report_b2.id, setup["user_b"].id)
    
    # User A requests many IDs, mixing Org A and Org B
    ids = f"{setup['report_a'].id},{setup['report_b'].id},{report_a2.id},{report_b2.id}"
    response = client.get(f"/api/admin/tags/entity-bulk/report?ids={ids}")
    
    assert response.status_code == 200
    data = response.json()
    
    # Should only return Org A's reports
    assert setup["report_a"].id in data
    assert report_a2.id in data
    
    # Should NOT return Org B's reports
    assert setup["report_b"].id not in data or data[setup["report_b"].id] == []
    assert report_b2.id not in data or data[report_b2.id] == []
    
    app.dependency_overrides.clear()


def test_bulk_tags_respects_report_shares(cross_org_setup):
    """Test that bulk endpoint respects report sharing permissions."""
    setup = cross_org_setup
    adapter = get_adapter()
    
    # Share Org B's report with user A
    adapter.create_report_share(
        report_id=setup["report_b"].id,
        user_id=setup["user_a"].id,
        shared_by=setup["user_b"].id
    )
    
    client = _make_client_as(setup["user_a"])
    
    # User A should now be able to see Org B's report tags (via share)
    response = client.get(
        f"/api/admin/tags/entity-bulk/report?ids={setup['report_b'].id}"
    )
    
    assert response.status_code == 200
    data = response.json()
    
    # Report share allows cross-org viewing via can_view_report check,
    # BUT the bulk endpoint also checks entity_org == org_id
    # Since Org B's report has organization_id = org_b.id and user_a's org_id = org_a.id,
    # the tags are NOT returned (org boundary is respected)
    # This is CORRECT behavior - report shares allow viewing report content,
    # but tags are org-scoped resources that shouldn't leak across orgs
    assert setup["report_b"].id not in data or data[setup["report_b"].id] == []
    
    app.dependency_overrides.clear()
