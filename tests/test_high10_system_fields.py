"""Tests for HIGH-10: System-Owned Fields Overwritable via content_json.

Tests verify that system-managed fields like "Affected Files" are protected
from user modification and always derived from evidence_payload.
"""
import pytest
import json
from fastapi.testclient import TestClient
from app.main import app
from app.db import get_adapter
from app.services.auth import get_current_user, hash_password
from app.services.evidence_schema import (
    EvidencePayload,
    EvidenceSource,
    EvidenceLocation,
    EVIDENCE_SCHEMA_VERSION,
)


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
def org_with_finding_with_evidence():
    """Create a finding with evidence_payload that includes locations."""
    adapter = get_adapter()
    adapter.init()
    
    # Create organization
    org = adapter.create_organization(name="Test Org", slug="test-org-sysfields")
    
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
    
    # Create evidence payload with file locations
    evidence = EvidencePayload(
        schema_version=EVIDENCE_SCHEMA_VERSION,
        source=EvidenceSource(type="sarif", tool="test_scanner", rule_id="RULE-001"),
        verbatim_text="Security issue found in multiple files.",
        locations=[
            EvidenceLocation(file="app/auth.py", line=45, snippet="password = 'hardcoded'"),
            EvidenceLocation(file="app/config.py", line=12, snippet="SECRET = 'exposed'"),
        ],
        artifacts={}
    )
    evidence.compute_hash()
    evidence_json = evidence.to_json()
    
    # Create finding with evidence
    content = {
        "Description": "Test finding with evidence",
        "Remediation": "Fix the issues",
        "Affected Files": "app/auth.py:45\napp/config.py:12"
    }
    finding = adapter.create_finding(
        report_id=report.id,
        title="Test Finding",
        content_json=json.dumps(content),
        notes="Test notes",
        template="test_template",
        organization_id=org.id,
        evidence_payload=evidence_json
    )
    
    return {
        "org": org,
        "admin": admin,
        "client": client,
        "app": app_entity,
        "report": report,
        "finding": finding,
        "evidence": evidence,
    }


def test_user_cannot_override_affected_files(org_with_finding_with_evidence):
    """Test that user cannot override Affected Files field (HIGH-10 fix)."""
    setup = org_with_finding_with_evidence
    adapter = get_adapter()
    
    # Attempt to update with malicious Affected Files
    malicious_content = {
        "Description": "Updated description",
        "Remediation": "Updated remediation",
        "Affected Files": "attacker-controlled/malicious.js\nevil/payload.php"
    }
    
    client = _make_client_as(setup["admin"])
    response = client.put(
        f"/api/admin/findings/{setup['finding'].id}",
        json={"content_json": json.dumps(malicious_content)}
    )
    
    assert response.status_code == 200
    updated_finding = response.json()
    
    # Affected Files should be restored from evidence, not user input
    updated_content = json.loads(updated_finding["content_json"])
    affected_files = updated_content.get("Affected Files", "")
    
    # Should contain evidence-based files
    assert "app/auth.py:45" in affected_files
    assert "app/config.py:12" in affected_files
    
    # Should NOT contain attacker-controlled files
    assert "attacker-controlled" not in affected_files
    assert "malicious.js" not in affected_files
    assert "evil/payload.php" not in affected_files


def test_system_fields_restored_even_if_removed(org_with_finding_with_evidence):
    """Test that system fields are restored even if user removes them."""
    setup = org_with_finding_with_evidence
    
    # Update without Affected Files in content_json
    user_content = {
        "Description": "Updated description without affected files",
        "Remediation": "Updated remediation"
    }
    
    client = _make_client_as(setup["admin"])
    response = client.put(
        f"/api/admin/findings/{setup['finding'].id}",
        json={"content_json": json.dumps(user_content)}
    )
    
    assert response.status_code == 200
    updated_finding = response.json()
    
    # Affected Files should be added back from evidence
    updated_content = json.loads(updated_finding["content_json"])
    assert "Affected Files" in updated_content
    assert "app/auth.py:45" in updated_content["Affected Files"]
    assert "app/config.py:12" in updated_content["Affected Files"]


def test_other_fields_can_be_updated_freely(org_with_finding_with_evidence):
    """Test that non-system fields can still be updated by users."""
    setup = org_with_finding_with_evidence
    
    # Update non-system fields
    new_content = {
        "Description": "Completely new description",
        "Remediation": "Completely new remediation steps",
        "Impact": "High impact on system",
        "Affected Files": "THIS WILL BE OVERWRITTEN"
    }
    
    client = _make_client_as(setup["admin"])
    response = client.put(
        f"/api/admin/findings/{setup['finding'].id}",
        json={"content_json": json.dumps(new_content)}
    )
    
    assert response.status_code == 200
    updated_finding = response.json()
    
    # User fields should be updated
    updated_content = json.loads(updated_finding["content_json"])
    assert updated_content["Description"] == "Completely new description"
    assert updated_content["Remediation"] == "Completely new remediation steps"
    assert updated_content["Impact"] == "High impact on system"
    
    # System fields should be from evidence
    assert "app/auth.py:45" in updated_content["Affected Files"]
    assert "app/config.py:12" in updated_content["Affected Files"]
    assert "THIS WILL BE OVERWRITTEN" not in updated_content["Affected Files"]


def test_finding_without_evidence_allows_free_update(org_with_finding_with_evidence):
    """Test that findings without evidence_payload can update all fields freely."""
    setup = org_with_finding_with_evidence
    adapter = get_adapter()
    
    # Create finding without evidence_payload
    content = {
        "Description": "Manual finding",
        "Remediation": "Manual remediation",
        "Affected Files": "manual/file.js"
    }
    manual_finding = adapter.create_finding(
        report_id=setup["report"].id,
        title="Manual Finding",
        content_json=json.dumps(content),
        notes="Manual notes",
        template="test_template",
        organization_id=setup["org"].id,
        evidence_payload=""  # No evidence
    )
    
    # Update with different Affected Files
    new_content = {
        "Description": "Updated manual",
        "Remediation": "Updated manual rem",
        "Affected Files": "updated/manual.js"
    }
    
    client = _make_client_as(setup["admin"])
    response = client.put(
        f"/api/admin/findings/{manual_finding.id}",
        json={"content_json": json.dumps(new_content)}
    )
    
    assert response.status_code == 200
    updated_finding = response.json()
    
    # Since there's no evidence, user's Affected Files should be accepted
    updated_content = json.loads(updated_finding["content_json"])
    assert updated_content["Affected Files"] == "updated/manual.js"


def test_multiple_file_locations_preserved_correctly(org_with_finding_with_evidence):
    """Test that multiple file locations from evidence are preserved correctly."""
    setup = org_with_finding_with_evidence
    adapter = get_adapter()
    
    # Create evidence with many file locations
    evidence = EvidencePayload(
        schema_version=EVIDENCE_SCHEMA_VERSION,
        source=EvidenceSource(type="sarif", tool="scanner", rule_id="RULE-002"),
        verbatim_text="Multiple file issue",
        locations=[
            EvidenceLocation(file="src/auth.ts", line=10, snippet="code1"),
            EvidenceLocation(file="src/api.ts", line=20, snippet="code2"),
            EvidenceLocation(file="src/utils.ts", line=30, snippet="code3"),
        ],
        artifacts={}
    )
    evidence.compute_hash()
    evidence_json = evidence.to_json()
    
    content = {"Description": "Multi-file issue", "Affected Files": "placeholder"}
    multi_finding = adapter.create_finding(
        report_id=setup["report"].id,
        title="Multi File Finding",
        content_json=json.dumps(content),
        notes="Notes",
        template="template",
        organization_id=setup["org"].id,
        evidence_payload=evidence_json
    )
    
    # Try to override Affected Files
    client = _make_client_as(setup["admin"])
    response = client.put(
        f"/api/admin/findings/{multi_finding.id}",
        json={
            "content_json": json.dumps({
                "Description": "Still multi-file",
                "Affected Files": "attacker.js"
            })
        }
    )
    
    assert response.status_code == 200
    updated_finding = response.json()
    
    # Should have all three files from evidence
    updated_content = json.loads(updated_finding["content_json"])
    affected_files = updated_content["Affected Files"]
    assert "src/auth.ts:10" in affected_files
    assert "src/api.ts:20" in affected_files
    assert "src/utils.ts:30" in affected_files
    assert "attacker.js" not in affected_files


def test_corrupted_evidence_returns_400_on_update(org_with_finding_with_evidence):
    """LOW-9: Updating a finding with corrupted evidence_payload returns 400 with clear message."""
    setup = org_with_finding_with_evidence
    adapter = get_adapter()

    # Create finding with corrupted evidence (missing required fields)
    corrupted_evidence = '{"schema_version":"v1"}'
    content = {"Description": "Finding with bad evidence", "Affected Files": "x"}
    bad_finding = adapter.create_finding(
        report_id=setup["report"].id,
        title="Corrupted Evidence Finding",
        content_json=json.dumps(content),
        notes="Notes",
        template="template",
        organization_id=setup["org"].id,
        evidence_payload=corrupted_evidence,
    )

    client = _make_client_as(setup["admin"])
    response = client.put(
        f"/api/admin/findings/{bad_finding.id}",
        json={"content_json": json.dumps({"Description": "Updated"})},
    )

    assert response.status_code == 400
    detail = response.json().get("detail", "")
    assert "corrupted" in detail.lower() or "regenerate" in detail.lower()
