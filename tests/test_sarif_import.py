"""
Tests for SARIF import functionality.

Covers parsing, merging by ruleId, location extraction, and session caching.
"""
import pytest
import json
from app.api.findings import parse_sarif, _merge_sarif_by_rule_id, SarifFinding


def test_parse_sarif_basic():
    """Test basic SARIF parsing extracts all key fields."""
    sarif = {
        "runs": [{
            "tool": {
                "driver": {
                    "name": "TestTool",
                    "rules": [{
                        "id": "001",
                        "name": "Test Vulnerability",
                        "fullDescription": {"text": "This is a test vulnerability"},
                        "help": {"text": "Fix it like this"}
                    }]
                }
            },
            "results": [{
                "ruleId": "001",
                "level": "error",
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/file.py"},
                        "region": {
                            "startLine": 42,
                            "snippet": {"text": "dangerous_code()"}
                        }
                    }
                }]
            }]
        }]
    }
    
    findings = parse_sarif(json.dumps(sarif))
    
    assert len(findings) == 1
    assert findings[0].ruleId == "001"
    assert findings[0].name == "Test Vulnerability"
    assert findings[0].severity == "High"  # "error" maps to High
    assert findings[0].description == "This is a test vulnerability"
    assert findings[0].location == "src/file.py"
    assert findings[0].lineNumber == 42
    assert findings[0].codeSnippet == "dangerous_code()"
    assert findings[0].remediation == "Fix it like this"
    assert findings[0].tool == "TestTool"


def test_parse_sarif_severity_mapping():
    """Test SARIF level maps correctly to severity."""
    test_cases = [
        ("none", "Informational"),
        ("note", "Low"),
        ("warning", "Medium"),
        ("error", "High"),
    ]
    
    for level, expected_severity in test_cases:
        sarif = {
            "runs": [{
                "tool": {"driver": {"name": "Tool", "rules": [{"id": "R1", "name": "Test"}]}},
                "results": [{"ruleId": "R1", "level": level}]
            }]
        }
        findings = parse_sarif(json.dumps(sarif))
        assert findings[0].severity == expected_severity, f"Level {level} should map to {expected_severity}"


def test_merge_sarif_by_rule_id_single_rule_multiple_locations():
    """Test that multiple occurrences of same rule merge into one finding."""
    findings = [
        SarifFinding(
            ruleId="052",
            name="Insecure Crypto",
            severity="High",
            description="Weak cipher detected",
            location="app/crypto.py",
            lineNumber=10,
            codeSnippet="DES.new(key)",
            remediation="Use AES-256",
            cwe="CWE-327",
            tool="Semgrep"
        ),
        SarifFinding(
            ruleId="052",
            name="Insecure Crypto",
            severity="High",
            description="Weak cipher detected",
            location="tests/test_crypto.py",
            lineNumber=25,
            codeSnippet="TripleDES.encrypt()",
            remediation="Use AES-256",
            cwe="CWE-327",
            tool="Semgrep"
        ),
        SarifFinding(
            ruleId="052",
            name="Insecure Crypto",
            severity="High",
            description="Weak cipher detected",
            location="app/utils.py",
            lineNumber=99,
            codeSnippet="cipher = DES()",
            remediation="Use AES-256",
            cwe="CWE-327",
            tool="Semgrep"
        ),
    ]
    
    merged = _merge_sarif_by_rule_id(findings)
    
    # Should merge 3 findings with same ruleId into 1
    assert len(merged) == 1
    assert merged[0]["ruleId"] == "052"
    assert merged[0]["name"] == "Insecure Crypto"
    assert merged[0]["severity"] == "High"
    
    # Should preserve all 3 locations
    assert len(merged[0]["locations"]) == 3
    
    # Verify each location is preserved
    locations = merged[0]["locations"]
    assert {"file": "app/crypto.py", "line": 10, "snippet": "DES.new(key)"} in locations
    assert {"file": "tests/test_crypto.py", "line": 25, "snippet": "TripleDES.encrypt()"} in locations
    assert {"file": "app/utils.py", "line": 99, "snippet": "cipher = DES()"} in locations


def test_merge_sarif_by_rule_id_multiple_rules():
    """Test that different rules stay separate."""
    findings = [
        SarifFinding(
            ruleId="001",
            name="SQL Injection",
            severity="Critical",
            description="SQL injection vulnerability",
            location="api.py",
            lineNumber=50,
            tool="Bandit"
        ),
        SarifFinding(
            ruleId="002",
            name="XSS",
            severity="High",
            description="Cross-site scripting",
            location="views.py",
            lineNumber=100,
            tool="Bandit"
        ),
        SarifFinding(
            ruleId="001",
            name="SQL Injection",
            severity="Critical",
            description="SQL injection vulnerability",
            location="models.py",
            lineNumber=75,
            tool="Bandit"
        ),
    ]
    
    merged = _merge_sarif_by_rule_id(findings)
    
    # Should have 2 findings (rule 001 and rule 002)
    assert len(merged) == 2
    
    # Find the SQL injection finding
    sql_finding = next(f for f in merged if f["ruleId"] == "001")
    assert sql_finding["name"] == "SQL Injection"
    assert len(sql_finding["locations"]) == 2  # Merged 2 occurrences
    
    # Find the XSS finding
    xss_finding = next(f for f in merged if f["ruleId"] == "002")
    assert xss_finding["name"] == "XSS"
    assert len(xss_finding["locations"]) == 1  # Only 1 occurrence


def test_merge_sarif_deduplicates_locations():
    """Test that duplicate locations are not added twice."""
    findings = [
        SarifFinding(
            ruleId="100",
            name="Test",
            severity="Low",
            description="Test",
            location="file.py",
            lineNumber=10,
            tool="Tool"
        ),
        SarifFinding(
            ruleId="100",
            name="Test",
            severity="Low",
            description="Test",
            location="file.py",
            lineNumber=10,  # Same location as above
            tool="Tool"
        ),
    ]
    
    merged = _merge_sarif_by_rule_id(findings)
    
    assert len(merged) == 1
    # Should only have 1 location, not 2 duplicates
    assert len(merged[0]["locations"]) == 1


def test_merge_sarif_handles_missing_locations():
    """Test that findings without locations are handled gracefully."""
    findings = [
        SarifFinding(
            ruleId="200",
            name="Config Issue",
            severity="Medium",
            description="Config problem",
            location="",  # Empty location
            tool="Linter"
        ),
        SarifFinding(
            ruleId="200",
            name="Config Issue",
            severity="Medium",
            description="Config problem",
            location="file.txt",  # Valid location
            lineNumber=5,
            tool="Linter"
        ),
    ]
    
    merged = _merge_sarif_by_rule_id(findings)
    
    assert len(merged) == 1
    # Should only have 1 location (the valid one, empty string was skipped)
    assert len(merged[0]["locations"]) == 1
    assert merged[0]["locations"][0]["file"] == "file.txt"


def test_parse_sarif_multiple_occurrences_merge():
    """Test parsing SARIF with multiple occurrences of same rule."""
    sarif = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.4.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "MockScanner",
                    "version": "1.0.0",
                    "rules": [{
                        "id": "MOCK-001",
                        "name": "Example Vulnerability",
                        "fullDescription": {
                            "text": "This is an example vulnerability for testing"
                        },
                        "help": {
                            "text": "Fix by updating the code"
                        }
                    }]
                }
            },
            "results": [
                {
                    "ruleId": "MOCK-001",
                    "level": "warning",
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/module1.py"},
                            "region": {"startLine": 10}
                        }
                    }]
                },
                {
                    "ruleId": "MOCK-001",
                    "level": "warning",
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/module2.py"},
                            "region": {"startLine": 25}
                        }
                    }]
                }
            ]
        }]
    }
    
    findings = parse_sarif(json.dumps(sarif))
    
    # Should parse 2 results
    assert len(findings) == 2
    
    # Now merge them
    merged = _merge_sarif_by_rule_id(findings)
    
    # Should merge into 1 finding with 2 locations
    assert len(merged) == 1
    assert merged[0]["ruleId"] == "MOCK-001"
    assert merged[0]["name"] == "Example Vulnerability"
    assert merged[0]["tool"] == "MockScanner"
    assert len(merged[0]["locations"]) == 2
    assert merged[0]["locations"][0]["file"] == "src/module1.py"
    assert merged[0]["locations"][1]["file"] == "src/module2.py"


def test_parse_sarif_cvss_severity_override():
    """Test that CVSS scores override default severity mapping."""
    sarif = {
        "runs": [{
            "tool": {"driver": {"name": "Tool", "rules": [{"id": "CVE", "name": "Critical CVE"}]}},
            "results": [{
                "ruleId": "CVE",
                "level": "warning",  # Would normally be Medium
                "properties": {
                    "cvss_v4_score": 9.8  # Should upgrade to Critical
                }
            }]
        }]
    }
    
    findings = parse_sarif(json.dumps(sarif))
    
    assert len(findings) == 1
    assert findings[0].severity == "Critical"  # Overridden by CVSS


def test_parse_sarif_extracts_cwe():
    """Test CWE extraction from properties and tags."""
    sarif = {
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Tool",
                    "rules": [{
                        "id": "R1",
                        "name": "Test",
                        "tags": ["CWE-79", "security"]
                    }]
                }
            },
            "results": [{
                "ruleId": "R1",
                "properties": {}
            }]
        }]
    }
    
    findings = parse_sarif(json.dumps(sarif))
    
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-79"


def test_parse_sarif_message_as_plain_string():
    """Test that SARIF message field as plain string is handled correctly (MED-27)."""
    sarif = {
        "runs": [{
            "tool": {
                "driver": {
                    "name": "TestTool",
                    "rules": [{
                        "id": "STR-001",
                        "name": "String Message Rule"
                    }]
                }
            },
            "results": [{
                "ruleId": "STR-001",
                "level": "warning",
                "message": "This is a plain string message"  # Plain string, not an object
            }]
        }]
    }
    
    findings = parse_sarif(json.dumps(sarif))
    
    assert len(findings) == 1
    assert findings[0].name == "String Message Rule"
    assert findings[0].description == "This is a plain string message"


def test_parse_sarif_message_as_object():
    """Test that SARIF message field as MultiformatMessageString object is handled correctly."""
    sarif = {
        "runs": [{
            "tool": {
                "driver": {
                    "name": "TestTool",
                    "rules": [{
                        "id": "OBJ-001",
                        "name": "Object Message Rule"
                    }]
                }
            },
            "results": [{
                "ruleId": "OBJ-001",
                "level": "error",
                "message": {"text": "This is a message object with text key"}  # Object format
            }]
        }]
    }
    
    findings = parse_sarif(json.dumps(sarif))
    
    assert len(findings) == 1
    assert findings[0].name == "Object Message Rule"
    assert findings[0].description == "This is a message object with text key"


def test_parse_sarif_message_fallback_to_rule_id():
    """Test that missing message field falls back to rule ID for name."""
    sarif = {
        "runs": [{
            "tool": {
                "driver": {
                    "name": "TestTool",
                    "rules": [{
                        "id": "NO-MSG-001"
                    }]
                }
            },
            "results": [{
                "ruleId": "NO-MSG-001",
                "level": "note"
            }]
        }]
    }
    
    findings = parse_sarif(json.dumps(sarif))
    
    assert len(findings) == 1
    assert findings[0].name == "Rule NO-MSG-001"  # Falls back to rule ID
    assert findings[0].description == ""  # Empty description


def test_parse_sarif_rule_fields_as_plain_strings():
    """Test that SARIF rule fields as plain strings are handled correctly (MED-28)."""
    sarif = {
        "runs": [{
            "tool": {
                "driver": {
                    "name": "TestTool",
                    "rules": [{
                        "id": "STR-RULE-001",
                        "name": "Plain String Name",
                        "shortDescription": "Plain string short description",
                        "fullDescription": "Plain string full description with more detail",
                        "help": "Plain string remediation guidance"
                    }]
                }
            },
            "results": [{
                "ruleId": "STR-RULE-001",
                "level": "error"
            }]
        }]
    }
    
    findings = parse_sarif(json.dumps(sarif))
    
    assert len(findings) == 1
    assert findings[0].name == "Plain String Name"
    assert findings[0].description == "Plain string full description with more detail"
    assert findings[0].remediation == "Plain string remediation guidance"


def test_parse_sarif_rule_fields_as_objects():
    """Test that SARIF rule fields as MultiformatMessageString objects are handled correctly (MED-28)."""
    sarif = {
        "runs": [{
            "tool": {
                "driver": {
                    "name": "TestTool",
                    "rules": [{
                        "id": "OBJ-RULE-001",
                        "name": {"text": "Object Name"},
                        "shortDescription": {"text": "Object short description"},
                        "fullDescription": {"text": "Object full description with more detail"},
                        "help": {"text": "Object remediation guidance"}
                    }]
                }
            },
            "results": [{
                "ruleId": "OBJ-RULE-001",
                "level": "warning"
            }]
        }]
    }
    
    findings = parse_sarif(json.dumps(sarif))
    
    assert len(findings) == 1
    assert findings[0].name == "Object Name"
    assert findings[0].description == "Object full description with more detail"
    assert findings[0].remediation == "Object remediation guidance"


def test_parse_sarif_rule_fields_mixed_formats():
    """Test that SARIF rule fields can be mixed string/object formats (MED-28)."""
    sarif = {
        "runs": [{
            "tool": {
                "driver": {
                    "name": "TestTool",
                    "rules": [{
                        "id": "MIX-001",
                        "name": "Plain String Name",
                        "shortDescription": {"text": "Object short desc"},
                        "fullDescription": "Plain string full desc",
                        "help": {"text": "Object help"}
                    }]
                }
            },
            "results": [{
                "ruleId": "MIX-001",
                "level": "note"
            }]
        }]
    }
    
    findings = parse_sarif(json.dumps(sarif))
    
    assert len(findings) == 1
    assert findings[0].name == "Plain String Name"
    assert findings[0].description == "Plain string full desc"
    assert findings[0].remediation == "Object help"


def test_session_cache_cleared_on_bulk_delete():
    """Test that clearing import sessions after bulk delete allows fresh re-import."""
    from app.db.sql_adapter import SQLAdapter
    from app.api.findings import _create_import_session
    import tempfile
    import os
    
    # Create a temporary DB for this test
    with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tmp:
        db_path = tmp.name
    
    try:
        # Initialize DB
        adapter = SQLAdapter(db_url=f"sqlite:///{db_path}")
        adapter.init()
        
        # Create test organization, client, application, and report
        org = adapter.create_organization("Test Org", "test-org")
        client = adapter.create_client("Test Team", org.id)
        app = adapter.create_application("Test App", type="web", organization_id=org.id)
        report = adapter.create_report("Test Report", organization_id=org.id, client_id=client.id, application_id=app.id)
        
        # Simulate first import - create session with findings
        findings_list = [
            {"ruleId": "TEST-001", "name": "Test Vuln", "severity": "High", "locations": []}
        ]
        content_hash = "abc123hash"
        session1 = _create_import_session(
            findings_list=findings_list,
            file_name="test.sarif",
            content_hash=content_hash,
            report_id=report.id,
            adapter=adapter,
        )
        
        # Verify session was created
        assert session1["session_id"] is not None
        assert session1["total"] == 1
        assert session1["already_imported"] is False
        
        # Simulate re-upload of same file (should find cached session)
        session2 = _create_import_session(
            findings_list=findings_list,
            file_name="test.sarif",
            content_hash=content_hash,  # Same hash
            report_id=report.id,
            adapter=adapter,
        )
        
        # Should return cached session with pending findings
        assert session2["session_id"] == session1["session_id"]
        assert session2["already_imported"] is True
        assert session2["total"] == 1  # Still 1 pending
        
        # Simulate bulk delete - clear import sessions
        deleted_count = adapter.delete_import_sessions_for_report(report.id)
        assert deleted_count == 1
        
        # Re-upload again - should create NEW session now
        session3 = _create_import_session(
            findings_list=findings_list,
            file_name="test.sarif",
            content_hash=content_hash,  # Same hash
            report_id=report.id,
            adapter=adapter,
        )
        
        # Should be a fresh import, not cached
        assert session3["session_id"] != session1["session_id"]
        assert session3["already_imported"] is False
        assert session3["total"] == 1
        
    finally:
        # Clean up temp DB
        if os.path.exists(db_path):
            os.remove(db_path)


def test_reupload_after_cancelled_session_returns_skipped_as_actionable():
    """Re-uploading same file after cancel should not report zero findings."""
    from app.db.sql_adapter import SQLAdapter
    from app.api.findings import _create_import_session
    import tempfile
    import os

    with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tmp:
        db_path = tmp.name

    try:
        adapter = SQLAdapter(db_url=f"sqlite:///{db_path}")
        adapter.init()

        org = adapter.create_organization("Test Org", "test-org-cancel")
        client = adapter.create_client("Test Team", org.id)
        app = adapter.create_application("Test App", type="web", organization_id=org.id)
        report = adapter.create_report(
            "Test Report",
            organization_id=org.id,
            client_id=client.id,
            application_id=app.id,
        )

        findings_list = [{"ruleId": "TEST-001", "name": "Test Vuln", "severity": "High", "locations": []}]
        content_hash = "same-file-hash"
        first = _create_import_session(
            findings_list=findings_list,
            file_name="test.sarif",
            content_hash=content_hash,
            report_id=report.id,
            adapter=adapter,
        )
        assert first["already_imported"] is False
        assert first["total"] == 1

        # Simulate cancel: pending -> skipped
        adapter.update_burp_session_task_status(first["session_id"], 0, "skipped")

        # Re-upload same content hash should resume with actionable skipped task
        resumed = _create_import_session(
            findings_list=findings_list,
            file_name="test.sarif",
            content_hash=content_hash,
            report_id=report.id,
            adapter=adapter,
        )
        assert resumed["already_imported"] is True
        assert resumed["session_id"] == first["session_id"]
        assert resumed["total"] == 1
        assert resumed["pending_count"] == 1
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
