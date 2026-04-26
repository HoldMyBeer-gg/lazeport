"""Tests for HIGH-9: Partial Update Overwrites Omitted Fields.

Tests verify that partial updates to findings preserve existing field values
when fields are omitted from the update payload.
"""
import pytest
import json
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
def org_with_finding():
    """Create an organization with a finding that has all fields populated."""
    adapter = get_adapter()
    adapter.init()
    
    # Create organization
    org = adapter.create_organization(name="Test Org", slug="test-org-update")
    
    # Create admin
    admin = adapter.upsert_user(
        email="admin@test.com",
        name="Admin",
        provider="local",
        role="user"
    )
    adapter.set_user_password_hash(admin.id, hash_password("password123"))
    adapter.create_organization_member(org.id, admin.id, "org_admin")
    
    # Create client, app, and report
    client = adapter.create_client(name="Test Team", organization_id=org.id)
    app_entity = adapter.create_application(
        name="Test App",
        type="web",
        description="",
        organization_id=org.id
    )
    report = adapter.create_report(
        "Test Report",
        organization_id=org.id,
        created_by=admin.id,
        client_id=client.id,
        application_id=app_entity.id,
    )
    
    # Create finding with all fields populated
    content = {
        "Description": "Original description content",
        "Remediation": "Original remediation steps",
        "Affected Files": "original.js"
    }
    finding = adapter.create_finding(
        report_id=report.id,
        title="Original Title",
        content_json=json.dumps(content),
        notes="Original notes here",
        template="original_template",
        organization_id=org.id
    )
    
    return {
        "org": org,
        "admin": admin,
        "client": client,
        "app": app_entity,
        "report": report,
        "finding": finding,
        "original_content": content,
    }


def test_update_only_title_preserves_other_fields(org_with_finding):
    """Test that updating only title preserves content_json, notes, template (HIGH-9 fix)."""
    setup = org_with_finding
    adapter = get_adapter()
    
    client = _make_client_as(setup["admin"])
    response = client.put(
        f"/api/admin/findings/{setup['finding'].id}",
        json={"title": "Updated Title"}
    )
    
    assert response.status_code == 200
    updated_finding = response.json()
    
    # Title should be updated
    assert updated_finding["title"] == "Updated Title"
    
    # Other fields should be preserved
    assert updated_finding["content_json"] == setup["finding"].content_json
    assert updated_finding["notes"] == setup["finding"].notes
    assert updated_finding["template"] == setup["finding"].template
    
    # Verify in database
    db_finding = adapter.get_finding(setup["finding"].id)
    assert db_finding.title == "Updated Title"
    assert db_finding.content_json == setup["finding"].content_json
    assert db_finding.notes == setup["finding"].notes
    assert db_finding.template == setup["finding"].template


def test_update_only_content_preserves_other_fields(org_with_finding):
    """Test that updating only content_json preserves title, notes, template."""
    setup = org_with_finding
    adapter = get_adapter()
    
    new_content = {
        "Description": "Updated description",
        "Remediation": "Updated remediation"
    }
    
    client = _make_client_as(setup["admin"])
    response = client.put(
        f"/api/admin/findings/{setup['finding'].id}",
        json={"content_json": json.dumps(new_content)}
    )
    
    assert response.status_code == 200
    updated_finding = response.json()
    
    # Content should be updated
    updated_content = json.loads(updated_finding["content_json"])
    assert updated_content["Description"] == "Updated description"
    
    # Other fields should be preserved
    assert updated_finding["title"] == setup["finding"].title
    assert updated_finding["notes"] == setup["finding"].notes
    assert updated_finding["template"] == setup["finding"].template


def test_update_only_notes_preserves_other_fields(org_with_finding):
    """Test that updating only notes preserves title, content_json, template."""
    setup = org_with_finding
    adapter = get_adapter()
    
    client = _make_client_as(setup["admin"])
    response = client.put(
        f"/api/admin/findings/{setup['finding'].id}",
        json={"notes": "Updated notes content"}
    )
    
    assert response.status_code == 200
    updated_finding = response.json()
    
    # Notes should be updated
    assert updated_finding["notes"] == "Updated notes content"
    
    # Other fields should be preserved
    assert updated_finding["title"] == setup["finding"].title
    assert updated_finding["content_json"] == setup["finding"].content_json
    assert updated_finding["template"] == setup["finding"].template


def test_update_only_template_preserves_other_fields(org_with_finding):
    """Test that updating only template preserves title, content_json, notes."""
    setup = org_with_finding
    adapter = get_adapter()
    
    client = _make_client_as(setup["admin"])
    response = client.put(
        f"/api/admin/findings/{setup['finding'].id}",
        json={"template": "new_template"}
    )
    
    assert response.status_code == 200
    updated_finding = response.json()
    
    # Template should be updated
    assert updated_finding["template"] == "new_template"
    
    # Other fields should be preserved
    assert updated_finding["title"] == setup["finding"].title
    assert updated_finding["content_json"] == setup["finding"].content_json
    assert updated_finding["notes"] == setup["finding"].notes


def test_update_multiple_fields_preserves_omitted_fields(org_with_finding):
    """Test that updating multiple fields preserves the omitted ones."""
    setup = org_with_finding
    adapter = get_adapter()
    
    client = _make_client_as(setup["admin"])
    response = client.put(
        f"/api/admin/findings/{setup['finding'].id}",
        json={
            "title": "New Title",
            "notes": "New notes"
        }
    )
    
    assert response.status_code == 200
    updated_finding = response.json()
    
    # Updated fields
    assert updated_finding["title"] == "New Title"
    assert updated_finding["notes"] == "New notes"
    
    # Preserved fields
    assert updated_finding["content_json"] == setup["finding"].content_json
    assert updated_finding["template"] == setup["finding"].template


def test_update_all_fields_works(org_with_finding):
    """Test that updating all fields works correctly."""
    setup = org_with_finding
    adapter = get_adapter()
    
    new_content = {"Description": "All new", "Remediation": "All new rem"}
    
    client = _make_client_as(setup["admin"])
    response = client.put(
        f"/api/admin/findings/{setup['finding'].id}",
        json={
            "title": "All New Title",
            "content_json": json.dumps(new_content),
            "notes": "All new notes",
            "template": "all_new_template"
        }
    )
    
    assert response.status_code == 200
    updated_finding = response.json()
    
    # All fields should be updated
    assert updated_finding["title"] == "All New Title"
    assert json.loads(updated_finding["content_json"]) == new_content
    assert updated_finding["notes"] == "All new notes"
    assert updated_finding["template"] == "all_new_template"


def test_update_with_empty_strings_replaces_fields(org_with_finding):
    """Test that explicitly providing empty strings replaces the field content."""
    setup = org_with_finding
    adapter = get_adapter()
    
    client = _make_client_as(setup["admin"])
    response = client.put(
        f"/api/admin/findings/{setup['finding'].id}",
        json={
            "title": "Keep Title",
            "notes": ""  # Explicitly empty
        }
    )
    
    assert response.status_code == 200
    updated_finding = response.json()
    
    # Title updated
    assert updated_finding["title"] == "Keep Title"
    
    # Notes explicitly set to empty
    assert updated_finding["notes"] == ""
    
    # content_json and template preserved
    assert updated_finding["content_json"] == setup["finding"].content_json
    assert updated_finding["template"] == setup["finding"].template


def test_partial_update_does_not_lose_complex_content(org_with_finding):
    """Test that partial update preserves complex JSON content."""
    setup = org_with_finding
    adapter = get_adapter()
    
    # Verify initial complex content
    original_content = json.loads(setup["finding"].content_json)
    assert "Description" in original_content
    assert "Remediation" in original_content
    
    # Update only notes
    client = _make_client_as(setup["admin"])
    response = client.put(
        f"/api/admin/findings/{setup['finding'].id}",
        json={"notes": "Just updating notes"}
    )
    
    assert response.status_code == 200
    updated_finding = response.json()
    
    # Content should be completely intact
    updated_content = json.loads(updated_finding["content_json"])
    assert updated_content == original_content
