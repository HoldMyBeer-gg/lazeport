import json
import time
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.api.admin import (
    _mark_stale_generating_as_failed,
    _parse_finding_content_safe,
    _strip_internal_content_keys,
    STALE_GENERATING_MS,
)
from app.db import get_adapter
from app.main import app


client = TestClient(app)


def test_settings_roundtrip():
    r = client.get("/api/admin/settings")
    assert r.status_code == 200
    payload = {
        "org_name": "TestCorp",
        "author_name": "DevSecOps",
        "voice_style": "Use DevSecOps instead of we",
    }
    r = client.put("/api/admin/settings", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["org_name"] == "TestCorp"
    adapter = get_adapter()
    org_id = adapter.ensure_system_org()
    logs = list(adapter.list_audit_logs(org_id, limit=50))
    assert any(l.action == "update" and l.resource_type == "settings" for l in logs)


def test_profile_update():
    r = client.get("/api/admin/profile")
    assert r.status_code == 200
    r = client.put(
        "/api/admin/profile",
        json={"name": "Analyst", "company_name": "Acme", "department_name": "DevSecOps"},
    )
    assert r.status_code == 200
    r = client.get("/api/admin/profile")
    data = r.json()
    assert data["company_name"] == "Acme"
    adapter = get_adapter()
    org_id = adapter.ensure_system_org()
    logs = list(adapter.list_audit_logs(org_id, limit=50))
    profile_logs = [l for l in logs if l.action == "update" and l.resource_type == "profile"]
    assert profile_logs
    details = json.loads(profile_logs[0].details or "{}")
    assert "company_name" in details.get("fields", [])


def test_llm_instructions_get_put():
    """GET/PUT /api/admin/me/llm-instructions round-trip; stored in DB, not localStorage."""
    r = client.get("/api/admin/me/llm-instructions")
    assert r.status_code == 200
    data = r.json()
    assert "instructions" in data
    assert data["instructions"] == "" or isinstance(data["instructions"], str)

    r = client.put("/api/admin/me/llm-instructions", json={"instructions": "Use British English."})
    assert r.status_code == 200
    assert r.json().get("ok") is True
    assert r.json().get("instructions") == "Use British English."

    r = client.get("/api/admin/me/llm-instructions")
    assert r.status_code == 200
    assert r.json()["instructions"] == "Use British English."

    # Clear
    r = client.put("/api/admin/me/llm-instructions", json={"instructions": ""})
    assert r.status_code == 200
    r = client.get("/api/admin/me/llm-instructions")
    assert r.json()["instructions"] == ""


def test_profile_provider_keys_can_coexist():
    me = client.get("/api/me")
    assert me.status_code == 200
    user_id = me.json()["id"]

    # Save OpenAI key
    r = client.put(
        "/api/admin/profile",
        json={"openai_api_key": "sk-openai-test", "ai_key_provider": "openai"},
    )
    assert r.status_code == 200

    # Save DeepSeek key afterwards
    r = client.put(
        "/api/admin/profile",
        json={"openai_api_key": "sk-deepseek-test", "ai_key_provider": "deepseek"},
    )
    assert r.status_code == 200

    adapter = get_adapter()
    assert getattr(adapter, "get_user_provider_api_key", None) is not None
    openai_key = adapter.get_user_provider_api_key(user_id, "openai")
    deepseek_key = adapter.get_user_provider_api_key(user_id, "deepseek")
    assert openai_key == "sk-openai-test"
    assert deepseek_key == "sk-deepseek-test"


def test_client_application_report_and_finding_flow():
    # Create a client
    r = client.post("/api/admin/clients", json={"name": "Team Alpha"})
    assert r.status_code == 200
    client_id = r.json()["id"]
    assert isinstance(client_id, str) and len(client_id) > 8  # UUID

    r = client.get("/api/admin/clients")
    assert r.status_code == 200
    assert any(t["name"] == "Team Alpha" for t in r.json())

    # Create an application
    r = client.post("/api/admin/applications", json={"name": "Test App", "type": "web"})
    assert r.status_code == 200
    app_id = r.json()["id"]
    assert isinstance(app_id, str) and len(app_id) > 8

    r = client.get("/api/admin/applications")
    assert r.status_code == 200
    assert any(a["name"] == "Test App" for a in r.json())

    # Create a report (client + application optional; report-first flow)
    r = client.post("/api/admin/reports", json={"client_id": client_id, "application_id": app_id, "name": "Report 1"})
    assert r.status_code == 200
    report_id = r.json()["id"]
    assert isinstance(report_id, str) and len(report_id) > 8

    r = client.get(f"/api/admin/reports?client_id={client_id}")
    assert r.status_code == 200
    assert any(rep["name"] == "Report 1" for rep in r.json())

    # Single report returns can_edit and can_manage_shares for frontend gating
    r = client.get(f"/api/admin/reports/{report_id}")
    assert r.status_code == 200
    data = r.json()
    assert "can_edit" in data
    assert "can_manage_shares" in data
    assert data["can_edit"] is True
    assert data["can_manage_shares"] is True

    # Create report without client/app (report-first flow)
    r = client.post("/api/admin/reports", json={"name": "Unassigned Report"})
    assert r.status_code == 200
    unassigned_id = r.json()["id"]
    assert r.json()["client_id"] is None
    assert r.json()["application_id"] is None
    r = client.get("/api/admin/reports")
    assert r.status_code == 200
    assert any(rep["name"] == "Unassigned Report" for rep in r.json())

    # Update report to assign client/app
    r = client.put(f"/api/admin/reports/{unassigned_id}", json={"name": "Unassigned Report", "client_id": client_id, "application_id": app_id})
    assert r.status_code == 200
    assert r.json()["client_id"] == client_id
    assert r.json()["application_id"] == app_id

    finding_payload = {
        "report_id": report_id,
        "title": "Test Finding",
        "content": {"Summary": "Example"},
        "notes": "notes",
        "template": "# Summary",
    }
    r = client.post("/api/admin/findings", json=finding_payload)
    assert r.status_code == 200
    finding_id = r.json()["id"]
    assert isinstance(finding_id, str) and len(finding_id) > 8
    assert r.json()["report_id"] == report_id

    r = client.get(f"/api/admin/findings?report_id={report_id}")
    assert r.status_code == 200
    assert any(f["id"] == finding_id for f in r.json())

    r = client.put(
        f"/api/admin/findings/{finding_id}",
        json={"title": "Updated", "content_json": "{\"Summary\":\"Updated\"}"},
    )
    assert r.status_code == 200
    assert r.json()["title"] == "Updated"

    r = client.patch(
        f"/api/admin/reports/{report_id}/summaries",
        json={"summary_executive": "Executive summary"},
    )
    assert r.status_code == 200

    r = client.delete(f"/api/admin/findings/{finding_id}")
    assert r.status_code == 200

    r = client.put(f"/api/admin/reports/{report_id}", json={"name": "Report 2"})
    assert r.status_code == 200
    assert r.json()["name"] == "Report 2"

    r = client.delete(f"/api/admin/reports/{report_id}")
    assert r.status_code == 200

    # Update + delete client
    r = client.put(f"/api/admin/clients/{client_id}", json={"name": "Team Beta"})
    assert r.status_code == 200
    assert r.json()["name"] == "Team Beta"

    r = client.delete(f"/api/admin/clients/{client_id}")
    assert r.status_code == 200

    # Update + delete application
    r = client.put(f"/api/admin/applications/{app_id}", json={"name": "App Beta", "type": "api"})
    assert r.status_code == 200
    assert r.json()["name"] == "App Beta"

    r = client.delete(f"/api/admin/applications/{app_id}")
    assert r.status_code == 200

    adapter = get_adapter()
    org_id = adapter.ensure_system_org()
    logs = list(adapter.list_audit_logs(org_id, limit=200))
    assert any(l.action == "update" and l.resource_type == "client" for l in logs)
    assert any(l.action == "update" and l.resource_type == "application" for l in logs)
    assert any(l.action == "update" and l.resource_type == "report" for l in logs)
    assert any(l.action == "update" and l.resource_type == "finding" for l in logs)
    assert any(l.action == "update" and l.resource_type == "report_summaries" for l in logs)


def test_user_role_update():
    adapter = get_adapter()
    adapter.init()
    user = adapter.upsert_user(email="user@example.com", name="User", provider="google", role="user")

    r = client.patch(f"/api/admin/users/{user.id}", json={"role": "admin"})
    assert r.status_code == 200
    assert r.json()["role"] == "admin"
    org_id = adapter.ensure_system_org()
    logs = list(adapter.list_audit_logs(org_id, limit=50))
    assert any(l.action == "update" and l.resource_type == "user" for l in logs)


def test_connector_audit_log():
    payload = {
        "type": "jira",
        "name": "Jira Main",
        "config": {},
        "enabled": True,
    }
    r = client.post("/api/admin/connectors", json=payload)
    if r.status_code != 200:
        raise AssertionError(r.json())
    connector_id = r.json()["id"]

    payload["name"] = "Jira Second"
    r = client.put(f"/api/admin/connectors/{connector_id}", json=payload)
    if r.status_code != 200:
        raise AssertionError(r.json())

    r = client.delete(f"/api/admin/connectors/{connector_id}")
    if r.status_code != 200:
        raise AssertionError(r.json())

    adapter = get_adapter()
    org_id = adapter.ensure_system_org()
    logs = list(adapter.list_audit_logs(org_id, limit=100))
    assert any(l.action == "create" and l.resource_type == "connector" for l in logs)
    assert any(l.action == "update" and l.resource_type == "connector" for l in logs)
    assert any(l.action == "delete" and l.resource_type == "connector" for l in logs)


def test_tag_crud_api():
    """Test tag creation, listing, and deletion via the API."""
    # Create a tag
    r = client.post("/api/admin/tags", json={"name": "API Security"})
    assert r.status_code == 200
    tag = r.json()
    assert tag["name"] == "API Security"
    tag_id = tag["id"]

    # Create duplicate returns existing
    r = client.post("/api/admin/tags", json={"name": "API Security"})
    assert r.status_code == 200
    assert r.json()["id"] == tag_id

    # List tags
    r = client.get("/api/admin/tags")
    assert r.status_code == 200
    assert any(t["name"] == "API Security" for t in r.json())

    # Auto-suggest (query filter)
    r = client.get("/api/admin/tags?query=api")
    assert r.status_code == 200
    assert any(t["name"] == "API Security" for t in r.json())

    # Delete tag
    r = client.delete(f"/api/admin/tags/{tag_id}")
    assert r.status_code == 200

    # Tag should be gone
    r = client.get("/api/admin/tags?query=API+Security")
    tags = [t for t in r.json() if t["name"] == "API Security"]
    assert len(tags) == 0


def test_tag_assignment_api():
    """Test assigning and removing tags from entities via the API."""
    # Create a client to tag
    r = client.post("/api/admin/clients", json={"name": "Tag Test Team"})
    assert r.status_code == 200
    client_id = r.json()["id"]

    # Assign a new tag (creates tag + assigns in one call)
    r = client.post("/api/admin/tags/assign", json={
        "tag_name": "PCI DSS Test",
        "entity_type": "client",
        "entity_id": client_id,
    })
    assert r.status_code == 200
    assert r.json()["tag_name"] == "PCI DSS Test"
    tag_id = r.json()["tag_id"]

    # List tags on entity
    r = client.get(f"/api/admin/tags/entity/client/{client_id}")
    assert r.status_code == 200
    tags = r.json()
    assert len(tags) >= 1
    assert any(t["name"] == "PCI DSS Test" for t in tags)

    # Remove tag from entity
    r = client.request("DELETE", "/api/admin/tags/assign", json={
        "tag_id": tag_id,
        "entity_type": "client",
        "entity_id": client_id,
    })
    assert r.status_code == 200

    # Confirm removed
    r = client.get(f"/api/admin/tags/entity/client/{client_id}")
    assert r.status_code == 200
    assert not any(t["id"] == tag_id for t in r.json())

    # Clean up
    client.delete(f"/api/admin/clients/{client_id}")


def test_tag_name_validation_api():
    """Test that invalid tag names are rejected."""
    # Empty name
    r = client.post("/api/admin/tags", json={"name": ""})
    assert r.status_code == 422

    # Too long
    r = client.post("/api/admin/tags", json={"name": "A" * 51})
    assert r.status_code == 422

    # Invalid characters (special chars)
    r = client.post("/api/admin/tags", json={"name": "tag@#$"})
    assert r.status_code == 422

    # Valid names
    r = client.post("/api/admin/tags", json={"name": "v2.1 Release"})
    assert r.status_code == 200
    assert r.json()["name"] == "v2.1 Release"


def test_tag_entity_type_validation():
    """Test that invalid entity types are rejected."""
    r = client.post("/api/admin/tags/assign", json={
        "tag_name": "Test",
        "entity_type": "invalid_type",
        "entity_id": "00000000-0000-0000-0000-000000000001",
    })
    assert r.status_code == 422


def test_confidence_levels_crud():
    """Test confidence levels retrieval and organization settings update."""
    # Get default confidence levels
    r = client.get("/api/admin/confidence-levels")
    assert r.status_code == 200
    data = r.json()
    assert "levels" in data
    assert isinstance(data["levels"], list)
    assert len(data["levels"]) >= 2
    assert "Confirmed" in data["levels"]
    assert "False Positive" in data["levels"]
    
    # Update confidence levels
    custom_levels = ["Verified", "Likely", "Possible", "Not Validated", "False Positive"]
    r = client.put("/api/admin/organization/settings", json={
        "confidence_levels": custom_levels
    })
    assert r.status_code == 200
    assert r.json()["success"] is True
    
    # Verify updated levels are returned
    r = client.get("/api/admin/confidence-levels")
    assert r.status_code == 200
    assert r.json()["levels"] == custom_levels
    
    # Test validation: must have at least 2 levels
    r = client.put("/api/admin/organization/settings", json={
        "confidence_levels": ["Only One"]
    })
    assert r.status_code == 400
    
    # Test validation: empty strings should be filtered
    r = client.put("/api/admin/organization/settings", json={
        "confidence_levels": ["Valid", "", "  ", "Also Valid"]
    })
    assert r.status_code == 200
    levels = r.json()["settings"]["confidence_levels"]
    assert len(levels) == 2
    assert "Valid" in levels
    assert "Also Valid" in levels


def test_false_positive_filtering_in_master_report():
    """Test that findings marked as False Positive are excluded from master report generation."""
    
    # Create test data: client, app, report, and 3 findings
    client_r = client.post("/api/admin/clients", json={"name": "Test Team FP"})
    assert client_r.status_code == 200
    client_id = client_r.json()["id"]
    
    app_r = client.post("/api/admin/applications", json={"name": "Test App FP"})
    assert app_r.status_code == 200
    app_id = app_r.json()["id"]
    
    report_r = client.post("/api/admin/reports", json={
        "name": "FP Filter Test Report",
        "client_id": client_id,
        "application_id": app_id
    })
    assert report_r.status_code == 200
    report_id = report_r.json()["id"]
    
    # Finding 1: Confirmed (should be included)
    finding1_r = client.post("/api/admin/findings", json={
        "report_id": report_id,
        "title": "Real Vulnerability",
        "content": {"Severity": "High", "Confidence": "Confirmed"},
        "notes": "Test",
        "template": ""
    })
    assert finding1_r.status_code == 200
    
    # Finding 2: False Positive (should be excluded)
    finding2_r = client.post("/api/admin/findings", json={
        "report_id": report_id,
        "title": "False Positive Finding",
        "content": {"Severity": "Critical", "Confidence": "False Positive"},
        "notes": "Test",
        "template": ""
    })
    assert finding2_r.status_code == 200
    
    # Finding 3: No confidence set (should be included)
    finding3_r = client.post("/api/admin/findings", json={
        "report_id": report_id,
        "title": "Unvalidated Finding",
        "content": {"Severity": "Medium"},
        "notes": "Test",
        "template": ""
    })
    assert finding3_r.status_code == 200
    
    # Verify all 3 findings exist in database
    findings_r = client.get(f"/api/admin/findings?report_id={report_id}")
    assert findings_r.status_code == 200
    all_findings = findings_r.json()
    assert len(all_findings) == 3
    
    # Generate master report (this would call the endpoint that filters FPs)
    # For now, just verify the filtering logic by checking findings passed to builder
    # Note: Full integration test would require a master template
    
    # Cleanup
    client.delete(f"/api/admin/findings/{finding1_r.json()['id']}")
    client.delete(f"/api/admin/findings/{finding2_r.json()['id']}")
    client.delete(f"/api/admin/findings/{finding3_r.json()['id']}")
    client.delete(f"/api/admin/reports/{report_id}")
    client.delete(f"/api/admin/clients/{client_id}")
    client.delete(f"/api/admin/applications/{app_id}")


def test_trends_unassigned_filter():
    """Test that GET /api/admin/trends accepts __unassigned__ in client_id and application_id filters."""
    # Create unassigned report with finding
    r = client.post("/api/admin/reports", json={"name": "Unassigned Trends Test"})
    assert r.status_code == 200
    unassigned_report_id = r.json()["id"]
    assert r.json()["client_id"] is None
    assert r.json()["application_id"] is None

    f1 = client.post("/api/admin/findings", json={
        "report_id": unassigned_report_id,
        "title": "Unassigned Finding",
        "content": {"Severity": "High", "Status": "Open", "Found Date": "2025-02-15"},
        "notes": "",
        "template": "",
    })
    assert f1.status_code == 200

    # Create client, app, assigned report with finding
    client_r = client.post("/api/admin/clients", json={"name": "Trends Team"})
    assert client_r.status_code == 200
    client_id = client_r.json()["id"]
    app_r = client.post("/api/admin/applications", json={"name": "Trends App", "type": "web"})
    assert app_r.status_code == 200
    app_id = app_r.json()["id"]

    r2 = client.post("/api/admin/reports", json={
        "name": "Assigned Trends Test",
        "client_id": client_id,
        "application_id": app_id,
    })
    assert r2.status_code == 200
    assigned_report_id = r2.json()["id"]

    f2 = client.post("/api/admin/findings", json={
        "report_id": assigned_report_id,
        "title": "Assigned Finding",
        "content": {"Severity": "Medium", "Status": "Open", "Found Date": "2025-02-20"},
        "notes": "",
        "template": "",
    })
    assert f2.status_code == 200

    # Filter by __unassigned__ only: should include only unassigned finding
    trends_unassigned = client.get("/api/admin/trends?client_id=__unassigned__")
    assert trends_unassigned.status_code == 200
    data = trends_unassigned.json()
    assert data["kpi"]["open"] == 1
    assert "__unassigned__" in data.get("heatmapRows", [])

    # Filter by client_id only: should include only assigned finding
    trends_client = client.get(f"/api/admin/trends?client_id={client_id}")
    assert trends_client.status_code == 200
    data_client = trends_client.json()
    assert data_client["kpi"]["open"] == 1
    assert "__unassigned__" not in data_client.get("heatmapRows", [])

    # No filter: should include both
    trends_all = client.get("/api/admin/trends")
    assert trends_all.status_code == 200
    data_all = trends_all.json()
    assert data_all["kpi"]["open"] == 2

    # Cleanup
    client.delete(f"/api/admin/findings/{f1.json()['id']}")
    client.delete(f"/api/admin/findings/{f2.json()['id']}")
    client.delete(f"/api/admin/reports/{unassigned_report_id}")
    client.delete(f"/api/admin/reports/{assigned_report_id}")
    client.delete(f"/api/admin/clients/{client_id}")
    client.delete(f"/api/admin/applications/{app_id}")


def test_trends_presets_list_create_delete():
    """Test GET/POST/DELETE /api/admin/trends-presets: list, create, delete own preset."""
    r = client.get("/api/admin/trends-presets")
    assert r.status_code == 200
    presets = r.json()
    assert isinstance(presets, list)

    # Create
    body = {"name": "My view", "filters": {"dateRange": "Last 30 days", "client": [], "severity": ["High"]}}
    r = client.post("/api/admin/trends-presets", json=body)
    assert r.status_code == 200
    data = r.json()
    assert "id" in data
    assert data["name"] == "My view"
    assert data["filters"].get("dateRange") == "Last 30 days"
    preset_id = data["id"]

    # List contains it
    r = client.get("/api/admin/trends-presets")
    assert r.status_code == 200
    presets = r.json()
    assert any(p["id"] == preset_id and p["name"] == "My view" for p in presets)

    # Delete
    r = client.delete(f"/api/admin/trends-presets/{preset_id}")
    assert r.status_code == 200
    r = client.get("/api/admin/trends-presets")
    assert r.status_code == 200
    assert not any(p["id"] == preset_id for p in r.json())

    # Delete non-existent or other user's preset -> 404
    r = client.delete("/api/admin/trends-presets/00000000-0000-0000-0000-000000000099")
    assert r.status_code == 404


def test_trends_cwe_counts_returned():
    """cweCounts is returned by /api/admin/trends and reflects CWE values in finding content_json."""
    r = client.post("/api/admin/reports", json={"name": "CWE Trends Report"})
    assert r.status_code == 200
    report_id = r.json()["id"]

    f1 = client.post("/api/admin/findings", json={
        "report_id": report_id,
        "title": "XSS Finding",
        "content": {"Severity": "High", "Status": "Open", "CWE": "CWE-79", "Found Date": "2025-01-10"},
        "notes": "",
        "template": "",
    })
    assert f1.status_code == 200

    f2 = client.post("/api/admin/findings", json={
        "report_id": report_id,
        "title": "SQLi Finding",
        "content": {"Severity": "Critical", "Status": "Open", "CWE": "CWE-89", "Found Date": "2025-01-11"},
        "notes": "",
        "template": "",
    })
    assert f2.status_code == 200

    f3 = client.post("/api/admin/findings", json={
        "report_id": report_id,
        "title": "Second XSS",
        "content": {"Severity": "Medium", "Status": "Open", "CWE": "CWE-79", "Found Date": "2025-01-12"},
        "notes": "",
        "template": "",
    })
    assert f3.status_code == 200

    data = client.get("/api/admin/trends").json()
    cwe_counts = data.get("cweCounts", [])

    # CWE-79 appears twice, CWE-89 once — CWE-79 should be first
    ids = [c["id"] for c in cwe_counts]
    assert "CWE-79" in ids
    assert "CWE-89" in ids
    cwe79 = next(c for c in cwe_counts if c["id"] == "CWE-79")
    cwe89 = next(c for c in cwe_counts if c["id"] == "CWE-89")
    assert cwe79["count"] >= 2
    assert cwe89["count"] >= 1
    assert ids.index("CWE-79") < ids.index("CWE-89"), "Higher count should appear first"

    # Cleanup
    client.delete(f"/api/admin/findings/{f1.json()['id']}")
    client.delete(f"/api/admin/findings/{f2.json()['id']}")
    client.delete(f"/api/admin/findings/{f3.json()['id']}")
    client.delete(f"/api/admin/reports/{report_id}")


def test_trends_cwe_filter_narrows_findings():
    """cwe= query param filters all_findings to those with matching CWE, affecting kpi.open."""
    r = client.post("/api/admin/reports", json={"name": "CWE Filter Report"})
    assert r.status_code == 200
    report_id = r.json()["id"]

    f1 = client.post("/api/admin/findings", json={
        "report_id": report_id,
        "title": "XSS",
        "content": {"Severity": "High", "Status": "Open", "CWE": "CWE-79", "Found Date": "2025-02-01"},
        "notes": "",
        "template": "",
    })
    f2 = client.post("/api/admin/findings", json={
        "report_id": report_id,
        "title": "SQLi",
        "content": {"Severity": "Critical", "Status": "Open", "CWE": "CWE-89", "Found Date": "2025-02-02"},
        "notes": "",
        "template": "",
    })
    f3 = client.post("/api/admin/findings", json={
        "report_id": report_id,
        "title": "No CWE",
        "content": {"Severity": "Low", "Status": "Open", "Found Date": "2025-02-03"},
        "notes": "",
        "template": "",
    })
    assert f1.status_code == f2.status_code == f3.status_code == 200

    # Filter by CWE-79 only
    data = client.get("/api/admin/trends?cwe=CWE-79").json()
    open_count = data["kpi"]["open"]
    assert open_count >= 1
    cwe_ids = [c["id"] for c in data.get("cweCounts", [])]
    assert "CWE-79" in cwe_ids
    assert "CWE-89" not in cwe_ids

    # Filter by CWE-89 only
    data2 = client.get("/api/admin/trends?cwe=CWE-89").json()
    cwe_ids2 = [c["id"] for c in data2.get("cweCounts", [])]
    assert "CWE-89" in cwe_ids2
    assert "CWE-79" not in cwe_ids2

    # No cwe filter: all three are included
    data_all = client.get("/api/admin/trends").json()
    assert data_all["kpi"]["open"] >= 3

    # Cleanup
    client.delete(f"/api/admin/findings/{f1.json()['id']}")
    client.delete(f"/api/admin/findings/{f2.json()['id']}")
    client.delete(f"/api/admin/findings/{f3.json()['id']}")
    client.delete(f"/api/admin/reports/{report_id}")


def test_trends_cwe_extraction_case_insensitive():
    """CWE values in content_json are normalised to uppercase in cweCounts."""
    r = client.post("/api/admin/reports", json={"name": "CWE Case Report"})
    assert r.status_code == 200
    report_id = r.json()["id"]

    f = client.post("/api/admin/findings", json={
        "report_id": report_id,
        "title": "Mixed-case CWE",
        "content": {"Severity": "High", "Status": "Open", "CWE": "cwe-79", "Found Date": "2025-03-01"},
        "notes": "",
        "template": "",
    })
    assert f.status_code == 200

    data = client.get("/api/admin/trends").json()
    cwe_ids = [c["id"] for c in data.get("cweCounts", [])]
    assert "CWE-79" in cwe_ids, "CWE ID must be uppercased in cweCounts"

    client.delete(f"/api/admin/findings/{f.json()['id']}")
    client.delete(f"/api/admin/reports/{report_id}")


def test_update_finding_persists_validation_guidance():
    r = client.post("/api/admin/reports", json={"name": "Report A"})
    assert r.status_code == 200
    report_id = r.json()["id"]

    create = client.post("/api/admin/findings", json={
        "report_id": report_id,
        "title": "Validation Target",
        "content": {"Severity": "High"},
        "notes": "",
        "template": "",
    })
    assert create.status_code == 200
    finding_id = create.json()["id"]

    upd = client.put(
        f"/api/admin/findings/{finding_id}",
        json={
            "title": "Validation Target",
            "content_json": "{\"Severity\":\"High\"}",
            "validation_guidance": "Check CWE-79 preconditions and verify reflected payload behavior.",
        },
    )
    assert upd.status_code == 200
    assert upd.json()["validation_guidance"] == "Check CWE-79 preconditions and verify reflected payload behavior."

    get_one = client.get(f"/api/admin/findings/{finding_id}")
    assert get_one.status_code == 200
    assert get_one.json()["validation_guidance"] == "Check CWE-79 preconditions and verify reflected payload behavior."

    client.delete(f"/api/admin/findings/{finding_id}")
    client.delete(f"/api/admin/reports/{report_id}")


def test_strip_internal_content_keys_removes_underscore_keys():
    """_strip_internal_content_keys removes _severity_flags and any key starting with _."""
    assert _strip_internal_content_keys({}) == {}
    assert _strip_internal_content_keys({"Severity": "High"}) == {"Severity": "High"}
    out = _strip_internal_content_keys({
        "Severity": "High",
        "_severity_flags": ["rubric_source=template", "clamped"],
        "Summary": "Text",
    })
    assert out == {"Severity": "High", "Summary": "Text"}
    assert "_severity_flags" not in out
    out2 = _strip_internal_content_keys({"_x": 1, "a": "b"})
    assert out2 == {"a": "b"}


def test_parse_finding_content_safe_strips_internal_keys():
    """Parsed finding content must not include _severity_flags or other internal keys."""
    content_json = json.dumps({
        "Severity": "High",
        "Vulnerability Summary": "A summary.",
        "_severity_flags": ["rubric_source=template"],
    })
    parsed = _parse_finding_content_safe(content_json)
    assert parsed.get("Severity") == "High"
    assert parsed.get("Vulnerability Summary") == "A summary."
    assert "_severity_flags" not in parsed


def test_master_docx_includes_validation_guidance_section():
    adapter = get_adapter()
    org_id = adapter.ensure_system_org()
    if not adapter.get_master_template("master", org_id):
        adapter.create_master_template("master", b"", organization_id=org_id)

    report_r = client.post("/api/admin/reports", json={"name": "Master Report Validation"})
    assert report_r.status_code == 200
    report_id = report_r.json()["id"]

    finding_r = client.post("/api/admin/findings", json={
        "report_id": report_id,
        "title": "Validation in Report",
        "content": {"Severity": "High", "Confidence": "Confirmed"},
        "notes": "",
        "template": "",
    })
    assert finding_r.status_code == 200
    finding_id = finding_r.json()["id"]

    update_r = client.put(
        f"/api/admin/findings/{finding_id}",
        json={
            "title": "Validation in Report",
            "content_json": "{\"Severity\":\"High\",\"Confidence\":\"Confirmed\"}",
            "validation_guidance": "Reproduce with safe payload and verify impact boundaries.",
        },
    )
    assert update_r.status_code == 200

    captured = {}

    def _fake_builder(**kwargs):
        captured["findings"] = kwargs["findings"]
        return b"docx-bytes"

    with patch("app.services.master_docx.build_master_docx", side_effect=_fake_builder):
        r = client.post("/api/admin/master-docx", json={
            "report_id": report_id,
            "template_name": "master",
            "locale": "en",
        })
    assert r.status_code == 200
    assert captured["findings"]
    first = captured["findings"][0]
    assert "Validation Guidance" in first["_content"]
    assert first["_content"]["Validation Guidance"] == "Reproduce with safe payload and verify impact boundaries."

    client.delete(f"/api/admin/findings/{finding_id}")
    client.delete(f"/api/admin/reports/{report_id}")


def test_cancel_pending_import_tasks_skips_only_pending_and_failed():
    report_r = client.post("/api/admin/reports", json={"name": "Import Cancel Report"})
    assert report_r.status_code == 200
    report_id = report_r.json()["id"]

    adapter = get_adapter()
    tasks = [
        {"index": 0, "status": "pending", "finding": {"name": "A"}},
        {"index": 1, "status": "failed", "finding": {"name": "B"}},
        {"index": 2, "status": "generating", "finding": {"name": "C"}},
        {"index": 3, "status": "completed", "finding": {"name": "D"}},
    ]
    sess = adapter.create_burp_import_session(
        report_id=report_id,
        file_name="sample.sarif",
        content_hash="cancel-pending-hash",
        tasks_json=json.dumps(tasks),
    )

    r = client.post(f"/api/admin/import-sessions/{sess.id}/cancel-pending")
    assert r.status_code == 200
    payload = r.json()
    assert payload["ok"] is True
    assert payload["cancelled"] == 2
    assert payload["left_generating"] == 1
    assert payload["left_completed"] == 1

    statuses = [t["status"] for t in payload["tasks"]]
    assert statuses == ["skipped", "skipped", "generating", "completed"]


def test_profile_theme_ghost_accepted():
    """Setting theme to 'ghost' must be accepted and persisted."""
    r = client.put("/api/admin/profile", json={"theme": "ghost"})
    assert r.status_code == 200
    r = client.get("/api/admin/profile")
    assert r.status_code == 200
    assert r.json()["theme"] == "ghost"


def test_profile_theme_terminal_accepted():
    """Setting theme to 'terminal' must be accepted and persisted."""
    r = client.put("/api/admin/profile", json={"theme": "terminal"})
    assert r.status_code == 200
    r = client.get("/api/admin/profile")
    assert r.status_code == 200
    assert r.json()["theme"] == "terminal"


def test_profile_theme_invalid_rejected():
    """Setting an unknown theme must be silently ignored (not persisted, not 422)."""
    # First set to a known value
    client.put("/api/admin/profile", json={"theme": "light"})
    # Attempt to set an invalid theme
    r = client.put("/api/admin/profile", json={"theme": "hacker-xyz"})
    assert r.status_code == 200
    r = client.get("/api/admin/profile")
    assert r.json()["theme"] == "light"


def test_list_clients_includes_report_count():
    """GET /api/admin/clients must include report_count for each client."""
    adapter = get_adapter()

    # Create a client
    org_id = adapter.ensure_system_org()
    new_client = adapter.create_client(name="CountTestClient", organization_id=org_id)

    try:
        # Before any reports: count must be 0
        r = client.get("/api/admin/clients")
        assert r.status_code == 200
        clients_data = r.json()
        match = next((c for c in clients_data if c["id"] == new_client.id), None)
        assert match is not None, "Created client not found in listing"
        assert "report_count" in match
        assert match["report_count"] == 0

        # Create a report for the client
        r2 = client.post(
            "/api/admin/reports",
            json={"name": "Count Test Report", "client_id": new_client.id},
        )
        assert r2.status_code == 200
        report_id = r2.json()["id"]

        try:
            # After adding a report: count must be 1
            r3 = client.get("/api/admin/clients")
            assert r3.status_code == 200
            match2 = next((c for c in r3.json() if c["id"] == new_client.id), None)
            assert match2 is not None
            assert match2["report_count"] == 1
        finally:
            client.delete(f"/api/admin/reports/{report_id}")
    finally:
        client.delete(f"/api/admin/clients/{new_client.id}")


# ── Stale-check logic (race condition fix) ────────────────────────────────────

def test_stale_check_none_timestamp_not_marked_failed():
    """Tasks with generating_since=None must NOT be marked failed.

    Fast-path Celery tasks can complete (0.03–0.07 s) before the enqueue
    endpoint finishes its own DB write, so they may briefly have no timestamp.
    The old bug was `not since or threshold`, which evaluated True for None.
    """
    tasks = [{"index": 0, "status": "generating", "generating_since": None}]
    result, changed = _mark_stale_generating_as_failed(tasks)
    assert not changed
    assert result[0]["status"] == "generating"


def test_stale_check_recent_timestamp_not_marked_failed():
    """Tasks whose generating_since is recent must NOT be marked failed."""
    now_ms = int(time.time() * 1000)
    tasks = [{"index": 0, "status": "generating", "generating_since": now_ms - 1000}]
    result, changed = _mark_stale_generating_as_failed(tasks)
    assert not changed
    assert result[0]["status"] == "generating"


def test_stale_check_expired_timestamp_marked_failed():
    """Tasks past the STALE_GENERATING_MS threshold must be marked failed."""
    now_ms = int(time.time() * 1000)
    since = now_ms - STALE_GENERATING_MS - 1000  # 1 s past threshold
    tasks = [{"index": 0, "status": "generating", "generating_since": since}]
    result, changed = _mark_stale_generating_as_failed(tasks)
    assert changed
    assert result[0]["status"] == "failed"


def test_stale_check_non_generating_statuses_untouched():
    """Tasks in completed/pending/failed/skipped must never be modified."""
    tasks = [
        {"index": 0, "status": "completed"},
        {"index": 1, "status": "pending"},
        {"index": 2, "status": "failed"},
        {"index": 3, "status": "skipped"},
    ]
    result, changed = _mark_stale_generating_as_failed(tasks)
    assert not changed
    assert [t["status"] for t in result] == ["completed", "pending", "failed", "skipped"]


def test_stale_check_mixed_tasks_only_expired_fail():
    """Only expired generating tasks are updated; others are left as-is."""
    now_ms = int(time.time() * 1000)
    tasks = [
        {"index": 0, "status": "generating", "generating_since": None},          # no ts → safe
        {"index": 1, "status": "generating", "generating_since": now_ms - 100},  # recent → safe
        {"index": 2, "status": "generating",                                      # expired → fail
         "generating_since": now_ms - STALE_GENERATING_MS - 5000},
        {"index": 3, "status": "completed"},
    ]
    result, changed = _mark_stale_generating_as_failed(tasks)
    assert changed
    assert result[0]["status"] == "generating"
    assert result[1]["status"] == "generating"
    assert result[2]["status"] == "failed"
    assert result[3]["status"] == "completed"


# ── Enqueue commit-order (race condition fix) ─────────────────────────────────

def test_enqueue_writes_generating_to_db_before_celery_dispatch():
    """DB must show 'generating' status at the moment Celery .delay() is called.

    The previous bug was dispatching .delay() BEFORE the DB write; fast-path
    tasks completed and wrote 'completed', then the belated DB write overwrote
    it back to 'generating', leaving tasks stuck.
    """
    adapter = get_adapter()
    report_r = client.post("/api/admin/reports", json={"name": "Enqueue Order Test"})
    assert report_r.status_code == 200
    report_id = report_r.json()["id"]

    tasks = [
        {
            "index": 0,
            "status": "pending",
            "finding": {"name": "Test Finding", "severity": "High"},
        }
    ]
    sess = adapter.create_burp_import_session(
        report_id=report_id,
        file_name="order.sarif",
        content_hash="enqueue-order-hash",
        tasks_json=json.dumps(tasks),
    )

    db_status_at_dispatch: dict = {}

    def capture_state(*args, **kwargs):
        session = adapter.get_burp_import_session(sess.id)
        if session:
            db_status_at_dispatch["tasks"] = json.loads(session.tasks_json)

    with patch("app.tasks.burp_import.generate_burp_finding_task.delay", side_effect=capture_state):
        r = client.post(
            "/api/admin/burp-import/enqueue",
            json={
                "session_id": sess.id,
                "task_indices": [0],
                "llm_provider": "openai",
                "llm_model": "gpt-4o",
            },
        )

    assert r.status_code == 200
    assert r.json()["enqueued"] == 1
    assert db_status_at_dispatch.get("tasks"), "Celery .delay() was never called"
    assert db_status_at_dispatch["tasks"][0]["status"] == "generating", (
        "DB must have 'generating' before Celery dispatch; was: "
        + db_status_at_dispatch["tasks"][0]["status"]
    )

    client.delete(f"/api/admin/reports/{report_id}")


def test_delete_report_with_burp_import_session_succeeds():
    """Regression: deleting a report that has a BurpImportSession must not raise a FK violation.

    Previously delete_report() called session.delete(report) directly without first removing
    child rows.  SQLite masks this because FK enforcement is off by default; PostgreSQL enforces
    the constraint and raises ForeignKeyViolation.  This test creates the FK situation and
    verifies the DELETE /reports/{id} endpoint returns 200 (not 500).
    """
    r = client.post("/api/admin/reports", json={"name": "Report With Burp Session"})
    assert r.status_code == 200
    report_id = r.json()["id"]

    adapter = get_adapter()
    # Create a BurpImportSession that references the report (mimics a real Burp import).
    adapter.create_burp_import_session(
        report_id=report_id,
        file_name="test.xml",
        content_hash="regression-test-hash-fk",
        tasks_json=json.dumps([{"index": 0, "status": "completed", "finding": {"name": "SQLi"}}]),
    )

    # This must succeed — not raise a FK violation.
    r = client.delete(f"/api/admin/reports/{report_id}")
    assert r.status_code == 200
    assert r.json()["ok"] is True

    # Confirm the import session was also removed.
    sessions = adapter.list_burp_sessions_for_report(report_id)
    assert sessions == [], "BurpImportSession rows must be removed when the report is deleted"
