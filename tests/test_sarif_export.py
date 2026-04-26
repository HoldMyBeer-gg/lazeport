"""
Tests for SARIF export functionality.

Covers location extraction from evidence_payload.
"""
import pytest
import json
from app.services.sarif import findings_to_sarif
from app.services.evidence_schema import EvidencePayload, EvidenceSource, EvidenceLocation
from app.db.models import Finding
from datetime import datetime


def test_sarif_export_with_affected_files():
    """Test that SARIF locations come from evidence_payload.locations, not Affected Files."""
    payload = EvidencePayload(
        schema_version="v1",
        source=EvidenceSource(type="sarif", tool="test"),
        verbatim_text="test",
        locations=[
            EvidenceLocation(file="app/models/user.py", line=45),
            EvidenceLocation(file="app/api/auth.py", line=120),
            EvidenceLocation(file="utils/db.py")
        ]
    )
    
    finding = Finding(
        id="test-finding-123",
        organization_id="org-1",
        report_id="report-1",
        title="SQL Injection in User Module",
        content_json=json.dumps({
            "Severity": "Critical",
            "CWE": "CWE-89",
            "Vulnerability Summary": "SQL injection vulnerability detected",
            "Affected Files": "This is ignored by SARIF export"
        }),
        evidence_payload=payload.to_json(),
        metadata_json="{}",
        notes="Test notes",
        template="",
        created_at=datetime.utcnow(),
    )
    
    sarif = findings_to_sarif([finding], report_name="Test Report")
    
    # Verify SARIF structure
    assert sarif["$schema"]
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    
    # Check locations array is populated from evidence
    locations = results[0]["locations"]
    assert len(locations) == 3
    
    # Verify first location (with line number)
    assert locations[0]["physicalLocation"]["artifactLocation"]["uri"] == "app/models/user.py"
    assert locations[0]["physicalLocation"]["region"]["startLine"] == 45
    
    # Verify second location (with line number)
    assert locations[1]["physicalLocation"]["artifactLocation"]["uri"] == "app/api/auth.py"
    assert locations[1]["physicalLocation"]["region"]["startLine"] == 120
    
    # Verify third location (no line number)
    assert locations[2]["physicalLocation"]["artifactLocation"]["uri"] == "utils/db.py"
    assert "region" not in locations[2]["physicalLocation"]


def test_sarif_export_empty_affected_files():
    """Test that export works when Affected Files is empty."""
    finding = Finding(
        id="test-finding-456",
        organization_id="org-1",
        report_id="report-1",
        title="Configuration Issue",
        content_json=json.dumps({
            "Severity": "Medium",
            "Vulnerability Summary": "Config problem",
            "Affected Files": ""  # Empty
        }),
        notes="",
        template="",
        created_at=datetime.utcnow(),
    )
    
    sarif = findings_to_sarif([finding])
    
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    
    # Locations should be empty array
    assert results[0]["locations"] == []


def test_sarif_export_web_and_file_locations():
    """Test that both web URLs (from content) and file paths (from evidence_payload) can coexist."""
    payload = EvidencePayload(
        schema_version="v1",
        source=EvidenceSource(type="sarif", tool="test"),
        verbatim_text="test",
        locations=[
            EvidenceLocation(file="frontend/src/search.js", line=25)
        ]
    )
    
    finding = Finding(
        id="test-finding-789",
        organization_id="org-1",
        report_id="report-1",
        title="XSS Vulnerability",
        content_json=json.dumps({
            "Severity": "High",
            "URL": "https://example.com/api/search?q=test",
            "Affected Files": "Ignored"
        }),
        evidence_payload=payload.to_json(),
        metadata_json="{}",
        notes="",
        template="",
        created_at=datetime.utcnow(),
    )
    
    sarif = findings_to_sarif([finding])
    
    results = sarif["runs"][0]["results"]
    locations = results[0]["locations"]
    
    # Should have 1 location from evidence (URL from content is legacy fallback for old findings)
    assert len(locations) == 1
    
    # Should be the file path from evidence
    assert locations[0]["physicalLocation"]["artifactLocation"]["uri"] == "frontend/src/search.js"
    assert locations[0]["physicalLocation"]["region"]["startLine"] == 25


def test_sarif_export_handles_whitespace():
    """Test that evidence_payload.locations are used regardless of Affected Files formatting."""
    payload = EvidencePayload(
        schema_version="v1",
        source=EvidenceSource(type="sarif", tool="test"),
        verbatim_text="test",
        locations=[
            EvidenceLocation(file="app/test.py", line=10),
            EvidenceLocation(file="lib/utils.py")
        ]
    )
    
    finding = Finding(
        id="test-finding-999",
        organization_id="org-1",
        report_id="report-1",
        title="Test",
        content_json=json.dumps({
            "Severity": "Low",
            "Affected Files": "Badly\n  formatted\n\ntext"
        }),
        evidence_payload=payload.to_json(),
        metadata_json="{}",
        notes="",
        template="",
        created_at=datetime.utcnow(),
    )
    
    sarif = findings_to_sarif([finding])
    
    results = sarif["runs"][0]["results"]
    locations = results[0]["locations"]
    
    # Should use evidence.locations, ignoring badly formatted Affected Files
    assert len(locations) == 2
    assert locations[0]["physicalLocation"]["artifactLocation"]["uri"] == "app/test.py"
    assert locations[1]["physicalLocation"]["artifactLocation"]["uri"] == "lib/utils.py"


def test_sarif_export_windows_paths_with_line_numbers():
    """Test that Windows paths from evidence_payload are exported correctly."""
    payload = EvidencePayload(
        schema_version="v1",
        source=EvidenceSource(type="sarif", tool="test"),
        verbatim_text="test",
        locations=[
            EvidenceLocation(file="C:\\repo\\app\\MainActivity.kt", line=47)
        ]
    )
    
    finding = Finding(
        id="test-finding-win1",
        organization_id="org-1",
        report_id="report-1",
        title="Windows Path Test",
        content_json=json.dumps({
            "Severity": "High",
            "Affected Files": "Ignored"
        }),
        evidence_payload=payload.to_json(),
        metadata_json="{}",
        notes="",
        template="",
        created_at=datetime.utcnow(),
    )
    
    sarif = findings_to_sarif([finding])
    
    results = sarif["runs"][0]["results"]
    locations = results[0]["locations"]
    
    # Should have 1 location with correct Windows path from evidence
    assert len(locations) == 1
    assert locations[0]["physicalLocation"]["artifactLocation"]["uri"] == "C:\\repo\\app\\MainActivity.kt"
    assert locations[0]["physicalLocation"]["region"]["startLine"] == 47


def test_sarif_export_windows_paths_without_line_numbers():
    """Test that Windows paths from evidence_payload without line numbers are exported correctly."""
    payload = EvidencePayload(
        schema_version="v1",
        source=EvidenceSource(type="sarif", tool="test"),
        verbatim_text="test",
        locations=[
            EvidenceLocation(file="C:\\repo\\app\\MainActivity.kt")
        ]
    )
    
    finding = Finding(
        id="test-finding-win2",
        organization_id="org-1",
        report_id="report-1",
        title="Windows Path No Line",
        content_json=json.dumps({
            "Severity": "Medium",
            "Affected Files": "Ignored"
        }),
        evidence_payload=payload.to_json(),
        metadata_json="{}",
        notes="",
        template="",
        created_at=datetime.utcnow(),
    )
    
    sarif = findings_to_sarif([finding])
    
    results = sarif["runs"][0]["results"]
    locations = results[0]["locations"]
    
    # Should have 1 location with Windows path from evidence, no region
    assert len(locations) == 1
    assert locations[0]["physicalLocation"]["artifactLocation"]["uri"] == "C:\\repo\\app\\MainActivity.kt"
    assert "region" not in locations[0]["physicalLocation"]


def test_sarif_export_includes_code_snippets():
    """Test MED-30: SARIF export includes code snippets from evidence_payload."""
    payload = EvidencePayload(
        schema_version="v1",
        source=EvidenceSource(type="sarif", tool="Semgrep"),
        verbatim_text="test",
        locations=[
            EvidenceLocation(
                file="src/auth.py",
                line=42,
                snippet="password = request.form['password']\nif password == stored_password:"
            ),
            EvidenceLocation(
                file="src/utils.py",
                line=15,
                snippet="def unsafe_query(user_input):\n    query = f\"SELECT * FROM users WHERE id = {user_input}\""
            ),
            EvidenceLocation(
                file="config/settings.yaml"
            )
        ]
    )
    
    finding = Finding(
        id="test-snippet-finding",
        organization_id="org-1",
        report_id="report-1",
        title="Security Issue with Code Context",
        content_json=json.dumps({
            "Severity": "High",
            "CWE": "CWE-89",
            "Vulnerability Summary": "Multiple security issues found"
        }),
        evidence_payload=payload.to_json(),
        metadata_json="{}",
        notes="",
        template="",
        created_at=datetime.utcnow(),
    )
    
    sarif = findings_to_sarif([finding], report_name="Test Report")
    
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    
    locations = results[0]["locations"]
    assert len(locations) == 3
    
    # First location: has line and snippet
    loc1 = locations[0]["physicalLocation"]
    assert loc1["artifactLocation"]["uri"] == "src/auth.py"
    assert loc1["region"]["startLine"] == 42
    assert loc1["region"]["snippet"]["text"] == "password = request.form['password']\nif password == stored_password:"
    
    # Second location: has line and snippet
    loc2 = locations[1]["physicalLocation"]
    assert loc2["artifactLocation"]["uri"] == "src/utils.py"
    assert loc2["region"]["startLine"] == 15
    assert loc2["region"]["snippet"]["text"] == "def unsafe_query(user_input):\n    query = f\"SELECT * FROM users WHERE id = {user_input}\""
    
    # Third location: no line or snippet
    loc3 = locations[2]["physicalLocation"]
    assert loc3["artifactLocation"]["uri"] == "config/settings.yaml"
    assert "region" not in loc3


def test_sarif_export_snippet_without_line_number():
    """Test MED-30: SARIF export handles snippet without line number."""
    payload = EvidencePayload(
        schema_version="v1",
        source=EvidenceSource(type="notes", tool="Manual"),
        verbatim_text="test",
        locations=[
            EvidenceLocation(
                file="src/config.py",
                snippet="SECRET_KEY = 'hardcoded-secret-123'"
            )
        ]
    )
    
    finding = Finding(
        id="test-snippet-no-line",
        organization_id="org-1",
        report_id="report-1",
        title="Hardcoded Secret",
        content_json=json.dumps({
            "Severity": "Critical"
        }),
        evidence_payload=payload.to_json(),
        metadata_json="{}",
        notes="",
        template="",
        created_at=datetime.utcnow(),
    )
    
    sarif = findings_to_sarif([finding])
    
    results = sarif["runs"][0]["results"]
    locations = results[0]["locations"]
    
    # Should have location with snippet but no line number
    assert len(locations) == 1
    loc = locations[0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/config.py"
    assert loc["region"]["snippet"]["text"] == "SECRET_KEY = 'hardcoded-secret-123'"
    assert "startLine" not in loc["region"]


def test_sarif_roundtrip_preserves_snippets():
    """Test MED-30: SARIF import → export roundtrip preserves code snippets."""
    from app.api.findings import parse_sarif
    from app.services.evidence_schema import build_payload_from_sarif
    
    original_sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CodeScanner",
                    "rules": [{
                        "id": "sql-injection",
                        "name": "SQL Injection",
                        "fullDescription": {"text": "Detects SQL injection vulnerabilities"}
                    }]
                }
            },
            "results": [{
                "ruleId": "sql-injection",
                "level": "error",
                "message": {"text": "SQL injection detected"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "backend/db.py"},
                        "region": {
                            "startLine": 78,
                            "snippet": {"text": "cursor.execute(\"SELECT * FROM users WHERE id = \" + user_id)"}
                        }
                    }
                }]
            }]
        }]
    }
    
    # Parse SARIF (import)
    sarif_json = json.dumps(original_sarif)
    findings = parse_sarif(sarif_json)
    assert len(findings) == 1
    parsed_finding = findings[0]
    
    # Verify snippet was captured during import
    assert parsed_finding.codeSnippet == "cursor.execute(\"SELECT * FROM users WHERE id = \" + user_id)"
    
    # Build evidence payload from SARIF result
    sarif_data = json.loads(sarif_json)
    sarif_result = sarif_data["runs"][0]["results"][0]
    evidence_payload = build_payload_from_sarif(sarif_result, tool_name="CodeScanner")
    
    # Verify snippet is in evidence_payload.locations
    assert len(evidence_payload.locations) == 1
    assert evidence_payload.locations[0].snippet == "cursor.execute(\"SELECT * FROM users WHERE id = \" + user_id)"
    
    # Create a Finding object with evidence_payload
    finding_model = Finding(
        id="roundtrip-test",
        organization_id="org-1",
        report_id="report-1",
        title=parsed_finding.name,
        content_json=json.dumps({
            "Severity": parsed_finding.severity,
            "Vulnerability Summary": parsed_finding.description
        }),
        evidence_payload=evidence_payload.to_json(),
        metadata_json="{}",
        notes="",
        template="",
        created_at=datetime.utcnow(),
    )
    
    # Export back to SARIF
    exported_sarif = findings_to_sarif([finding_model], report_name="Roundtrip Test")
    
    # Verify snippet is present in exported SARIF (MED-30 fix)
    exported_results = exported_sarif["runs"][0]["results"]
    assert len(exported_results) == 1
    
    exported_locations = exported_results[0]["locations"]
    assert len(exported_locations) == 1
    
    exported_region = exported_locations[0]["physicalLocation"]["region"]
    assert exported_region["startLine"] == 78
    assert exported_region["snippet"]["text"] == "cursor.execute(\"SELECT * FROM users WHERE id = \" + user_id)"


def test_sarif_roundtrip_embeds_and_recovers_content():
    """
    Export embeds lazeport_content + lazeport_validation_guidance in result.properties.
    Re-importing the SARIF recovers both fields without LLM generation.
    """
    content = {
        "Finding Title": "SQL Injection in login",
        "Vulnerability Summary": "Unsanitised input passed to query.",
        "Severity": "High",
        "Remediation": "Use parameterised queries.",
    }
    validation_guidance = "## Validation Steps\n- Submit `' OR '1'='1` as username\n- Observe response"

    payload = EvidencePayload(
        schema_version="v1",
        source=EvidenceSource(type="sarif", tool="test"),
        verbatim_text="test",
        locations=[EvidenceLocation(file="app/db.py", line=12)],
    )

    finding = Finding(
        id="roundtrip-abc123",
        organization_id="org-rt",
        report_id="report-rt",
        title="SQL Injection in login",
        content_json=json.dumps(content),
        validation_guidance=validation_guidance,
        evidence_payload=payload.to_json(),
        created_at=datetime.utcnow(),
    )

    # ── Export ────────────────────────────────────────────────────────────────
    sarif = findings_to_sarif([finding], report_name="RT Test")
    result = sarif["runs"][0]["results"][0]
    props = result.get("properties", {})

    assert "lazeport_content" in props, "Export must embed lazeport_content"
    assert "lazeport_validation_guidance" in props, "Export must embed lazeport_validation_guidance"
    assert json.loads(props["lazeport_content"])["Severity"] == "High"
    assert "SQL Injection" in props["lazeport_validation_guidance"] or "Validation" in props["lazeport_validation_guidance"]

    # ── Re-import ─────────────────────────────────────────────────────────────
    from app.api.findings import parse_sarif, _merge_sarif_by_rule_id

    sarif_str = json.dumps(sarif)
    parsed = parse_sarif(sarif_str)
    assert len(parsed) == 1
    assert parsed[0].lazeport_content == props["lazeport_content"]
    assert parsed[0].lazeport_validation_guidance == validation_guidance

    merged = _merge_sarif_by_rule_id(parsed)
    assert len(merged) == 1
    assert merged[0]["lazeport_content"] == props["lazeport_content"]
    assert merged[0]["lazeport_validation_guidance"] == validation_guidance


def test_generate_burp_finding_task_fast_path_skips_llm():
    """When lazeport_content is present, the Celery task must create the finding
    without calling the LLM (structure_notes_with_context).

    This is the SARIF re-import fast path: exported SARIFs embed the original
    structured content so a re-import never needs to regenerate.
    """
    from unittest.mock import patch
    from app.db.sql_adapter import SQLAdapter
    from app.tasks.burp_import import generate_burp_finding_task

    adapter = SQLAdapter("sqlite:///:memory:")
    adapter.init()

    org = adapter.create_organization(name="Fast Path Org", slug="fast-path-org")
    user = adapter.upsert_user(
        email="fastpath@test.com", name="FP User", provider="local", role="admin"
    )
    adapter.create_organization_member(org.id, user.id, "org_admin")
    report = adapter.create_report(
        "Fast Path Report",
        organization_id=org.id,
        created_by=user.id,
    )

    content = {
        "Finding Title": "SQL Injection in login",
        "Severity": "High",
        "Vulnerability Summary": "Unsanitised input passed to query.",
        "Remediation": "Use parameterised queries.",
    }
    tasks = [
        {
            "index": 0,
            "status": "pending",
            "finding": {
                "name": "SQL Injection in login",
                "severity": "High",
                "lazeport_content": json.dumps(content),
                "lazeport_validation_guidance": "Submit ' OR '1'='1 and observe response.",
                "evidence_payload": json.dumps({
                    "schema_version": "v1",
                    "source": {"type": "sarif", "tool": "Lazeport"},
                    "verbatim_text": "",
                    "locations": [],
                    "artifacts": {},
                    "hash": "fp-test-hash",
                }),
            },
        }
    ]
    sess = adapter.create_burp_import_session(
        report_id=report.id,
        file_name="re-import.sarif",
        content_hash="fast-path-content-hash",
        tasks_json=json.dumps(tasks),
    )

    with patch("app.tasks.burp_import.get_adapter", return_value=adapter):
        with patch("app.tasks.burp_import.structure_notes_with_context") as mock_llm:
            result = generate_burp_finding_task(sess.id, 0)

    assert result.get("ok") is True, f"Task failed: {result}"
    assert result.get("skipped_llm") is True, "LLM must be skipped when lazeport_content is present"
    assert "finding_id" in result
    mock_llm.assert_not_called()

    # Verify the finding was created with correct content and validation guidance
    finding = adapter.get_finding(result["finding_id"])
    assert finding is not None
    assert finding.title == "SQL Injection in login"
    assert json.loads(finding.content_json)["Severity"] == "High"
    assert finding.validation_guidance == "Submit ' OR '1'='1 and observe response."

    # Verify the task is marked completed in the session
    session = adapter.get_burp_import_session(sess.id)
    task_state = json.loads(session.tasks_json)[0]
    assert task_state["status"] == "completed"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
