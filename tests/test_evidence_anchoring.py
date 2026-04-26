"""
Comprehensive tests for deterministic evidence anchoring system.

Tests evidence payload building, structured prompts, validation,
clamps, deduplication, and SARIF export - all using synthetic data only.
"""


from app.api.findings import (
    _cap_text,
    _dedupe_preserve_order,
    _has_network_protocol,
    _merge_sarif_by_rule_id,
    _dedupe_by_locations,
)
from app.services.evidence_clamps import (
    clamp_affected_files,
    clamp_severity,
    clamp_threat_model_phrases,
)
from app.services.llm_validation import validate_structured_output


# ============================================================================
# Test 1: Evidence Payload Building
# ============================================================================

def test_cap_text_under_limit():
    """Text under limit is returned unchanged."""
    text = "Short text"
    capped, truncated = _cap_text(text, max_chars=100)
    assert capped == text
    assert truncated is False


def test_cap_text_over_limit():
    """Text over limit is truncated with flag set."""
    text = "x" * 25000
    capped, truncated = _cap_text(text, max_chars=20000)
    assert len(capped) == 20000
    assert truncated is True


def test_cap_text_empty():
    """Empty text returns empty string, not truncated."""
    capped, truncated = _cap_text("", max_chars=100)
    assert capped == ""
    assert truncated is False


def test_dedupe_preserve_order():
    """Deduplication preserves first-seen order."""
    items = ["file1.py", "file2.py", "file1.py", "file3.py", "file2.py"]
    result = _dedupe_preserve_order(items)
    assert result == ["file1.py", "file2.py", "file3.py"]


def test_has_network_protocol_http():
    """Detects http:// protocol."""
    assert _has_network_protocol("Visit http://example.com") is True


def test_has_network_protocol_https():
    """Detects https:// protocol."""
    assert _has_network_protocol("API at https://api.example.com") is True


def test_has_network_protocol_ws():
    """Detects ws:// protocol."""
    assert _has_network_protocol("Connect to ws://socket.example.com") is True


def test_has_network_protocol_wss():
    """Detects wss:// protocol."""
    assert _has_network_protocol("Secure socket wss://secure.example.com") is True


def test_has_network_protocol_false_positive_host():
    """Does NOT match 'host' keyword (false positive prevention)."""
    assert _has_network_protocol("The host system is vulnerable") is False


def test_has_network_protocol_false_positive_url():
    """Does NOT match 'URL' keyword without protocol."""
    assert _has_network_protocol("URL validation is missing") is False


def test_has_network_protocol_empty():
    """Empty text returns False."""
    assert _has_network_protocol("") is False


def test_has_network_protocol_case_insensitive():
    """Protocol detection is case-insensitive."""
    assert _has_network_protocol("Visit HTTP://EXAMPLE.COM") is True


def test_merge_sarif_builds_evidence():
    """Merged SARIF findings include complete evidence_payload."""
    from app.api.findings import SarifFinding
    from app.services.evidence_schema import EvidencePayload
    
    findings = [
        SarifFinding(
            ruleId="TEST-001",
            name="Test Vulnerability",
            severity="High",
            description="This is a test description with http://example.com",
            remediation="Fix by updating dependencies",
            location="src/main.py",
            lineNumber=42,
            codeSnippet="def vulnerable():",
            tool="TestScanner",
            cwe="CWE-79"
        ),
        SarifFinding(
            ruleId="TEST-001",
            name="Test Vulnerability",
            severity="High",
            description="This is a test description with http://example.com",
            remediation="Fix by updating dependencies",
            location="src/utils.py",
            lineNumber=15,
            codeSnippet="def helper():",
            tool="TestScanner",
            cwe="CWE-79"
        ),
    ]
    
    # No patch needed - function will use fallback formatting
    merged = _merge_sarif_by_rule_id(findings)
    
    assert len(merged) == 1
    finding = merged[0]
    
    # Check NEW evidence_payload structure (no more metadata["evidence"])
    assert "evidence_payload" in finding
    payload = EvidencePayload.from_json(finding["evidence_payload"])
    
    assert payload.source.type == "sarif"
    assert payload.source.rule_id == "TEST-001"
    assert payload.source.tool == "TestScanner"
    assert "test description" in payload.verbatim_text.lower()
    assert "http://example.com" in payload.verbatim_text  # Network evidence in verbatim
    
    # Check locations
    assert len(payload.locations) == 2
    assert payload.locations[0].file == "src/main.py"
    assert payload.locations[0].line == 42
    assert payload.locations[0].snippet == "def vulnerable():"
    assert payload.locations[1].file == "src/utils.py"
    assert payload.locations[1].line == 15
    
    # Verify raw SARIF result preserved in artifacts
    assert payload.artifacts is not None
    assert "raw_sarif_result" in payload.artifacts


def test_merge_sarif_no_network_evidence():
    """Evidence without protocols is stored correctly in evidence_payload."""
    from app.api.findings import SarifFinding
    from app.services.evidence_schema import EvidencePayload
    
    findings = [
        SarifFinding(
            ruleId="TEST-002",
            name="Local File Issue",
            severity="Medium",
            description="File permissions are too permissive",
            remediation="Restrict file permissions",
            location="config.yaml",
            tool="FileScan"
        )
    ]
    
    # No patch needed
    merged = _merge_sarif_by_rule_id(findings)
    
    # Check evidence_payload (no more metadata["evidence"])
    payload = EvidencePayload.from_json(merged[0]["evidence_payload"])
    assert payload.source.type == "sarif"
    assert payload.source.rule_id == "TEST-002"
    
    # Verify no network protocols in verbatim text
    assert "http://" not in payload.verbatim_text.lower()
    assert "https://" not in payload.verbatim_text.lower()


# ============================================================================
# Test 2: Deduplication
# ============================================================================

def test_dedupe_by_locations_identical():
    """Findings with identical locations and similar titles are deduplicated."""
    from app.services.evidence_schema import EvidencePayload, EvidenceSource, EvidenceLocation
    
    # Build evidence_payload for both findings
    payload1 = EvidencePayload(
        schema_version="v1",
        source=EvidenceSource(type="sarif", tool="test"),
        verbatim_text="test",
        locations=[EvidenceLocation(file="app.py", line=10)]
    )
    
    payload2 = EvidencePayload(
        schema_version="v1",
        source=EvidenceSource(type="sarif", tool="test"),
        verbatim_text="test",
        locations=[EvidenceLocation(file="app.py", line=10)]
    )
    
    findings = [
        {
            "name": "SQL Injection Vulnerability",
            "evidence_payload": payload1.to_json(),
            "metadata": {}
        },
        {
            "name": "sqlinjectionvulnerability",  # Similar title, will normalize
            "evidence_payload": payload2.to_json(),
            "metadata": {}
        }
    ]
    
    result = _dedupe_by_locations(findings)
    assert len(result) == 1
    assert result[0]["metadata"]["duplicate_count"] == 2


def test_dedupe_by_locations_different_locations():
    """Findings with different locations are kept separate."""
    findings = [
        {
            "name": "Test Issue",
            "metadata": {
                "evidence": {
                    "title": "Test Issue",
                    "locations": [{"file": "file1.py", "line": 1}]
                }
            }
        },
        {
            "name": "Test Issue",
            "metadata": {
                "evidence": {
                    "title": "Test Issue",
                    "locations": [{"file": "file2.py", "line": 1}]
                }
            }
        }
    ]
    
    result = _dedupe_by_locations(findings)
    assert len(result) == 2


def test_dedupe_preserves_findings_without_locations():
    """Findings without locations are preserved."""
    findings = [
        {
            "name": "No Location Finding",
            "metadata": {
                "evidence": {
                    "title": "No Location Finding",
                    "locations": []
                }
            }
        }
    ]
    
    result = _dedupe_by_locations(findings)
    assert len(result) == 1


# ============================================================================
# Test 3: Validation
# ============================================================================

def test_validation_missing_required_key():
    """Validation fails when required key is missing."""
    structured = {
        "Vulnerability Summary": "Test",
        "Severity": "High"
    }
    required_keys = ["Vulnerability Summary", "Severity", "Remediation"]
    
    is_valid, issues = validate_structured_output(structured, required_keys)
    assert is_valid is False
    assert any("Remediation" in issue for issue in issues)


def test_validation_system_owned_key_not_required():
    """System-owned keys are not validated as required."""
    structured = {
        "Vulnerability Summary": "Test",
        "Severity": "High"
    }
    required_keys = ["Vulnerability Summary", "Severity", "Affected Files"]
    system_owned = ["Affected Files"]
    
    is_valid, issues = validate_structured_output(
        structured, required_keys, system_owned
    )
    assert is_valid is True


def test_validation_non_string_value():
    """Validation fails when value is not a string."""
    structured = {
        "Vulnerability Summary": {"nested": "object"},
        "Severity": "High"
    }
    
    is_valid, issues = validate_structured_output(structured, [])
    assert is_valid is False
    assert any("not a string" in issue for issue in issues)


def test_validation_embedded_json():
    """Validation fails when string contains embedded JSON."""
    structured = {
        "Vulnerability Summary": '{"title": "Bad", "severity": "High"}',
        "Severity": "High"
    }
    
    is_valid, issues = validate_structured_output(structured, [])
    assert is_valid is False
    assert any("embedded JSON" in issue for issue in issues)


def test_validation_code_fences():
    """Validation fails when string contains code fences."""
    structured = {
        "Vulnerability Summary": "```json\n{\"test\": \"bad\"}\n```",
        "Severity": "High"
    }
    
    is_valid, issues = validate_structured_output(structured, [])
    assert is_valid is False
    assert any("code fences" in issue for issue in issues)


# ============================================================================
# Test 4: Affected Files Clamp
# ============================================================================

def test_clamp_affected_files_sets_from_evidence():
    """Affected Files is always set from evidence."""
    structured = {
        "Vulnerability Summary": "Test",
        "Affected Files": "wrong_file.py"  # Should be overwritten
    }
    evidence = {
        "affected_files": ["src/main.py:10", "src/utils.py:20"]
    }
    
    result = clamp_affected_files(structured, evidence)
    assert result["Affected Files"] == "src/main.py:10\nsrc/utils.py:20"
    assert "affected_files_set_from_evidence" in result["_clamp_flags"]


def test_clamp_affected_files_creates_field():
    """Affected Files field is created if not in template."""
    structured = {
        "Vulnerability Summary": "Test"
    }
    evidence = {
        "affected_files": ["file.py"]
    }
    
    result = clamp_affected_files(structured, evidence)
    assert "Affected Files" in result
    assert result["Affected Files"] == "file.py"


def test_clamp_affected_files_empty_evidence():
    """Empty evidence.affected_files sets empty string."""
    structured = {
        "Affected Files": "something"
    }
    evidence = {
        "affected_files": []
    }
    
    result = clamp_affected_files(structured, evidence)
    assert result["Affected Files"] == ""


# ============================================================================
# Test 5: Threat Model Phrase Clamp
# ============================================================================

def test_clamp_phrases_no_network_evidence():
    """Phrases are replaced when network evidence is absent."""
    structured = {
        "Vulnerability Summary": "A remote attacker can exploit this via unauthenticated attacker methods.",
        "Attack Vector": "The system is internet-facing and vulnerable."
    }
    evidence = {
        "has_network_evidence": False
    }
    
    result = clamp_threat_model_phrases(structured, evidence)
    assert "remote attacker" not in result["Vulnerability Summary"].lower()
    assert "attacker can exploit" in result["Vulnerability Summary"]
    assert "unauthenticated attacker" not in result["Vulnerability Summary"].lower()
    # Note: "via [phrase] methods" -> "via attacker methods" after replacement
    assert "internet-facing" not in result["Attack Vector"].lower()
    assert "exposed" in result["Attack Vector"]
    
    assert len(result["_clamp_flags"]) > 0


def test_clamp_phrases_with_network_evidence():
    """Phrases are preserved when network evidence present."""
    structured = {
        "Vulnerability Summary": "A remote attacker can exploit this vulnerability."
    }
    evidence = {
        "has_network_evidence": True
    }
    
    result = clamp_threat_model_phrases(structured, evidence)
    assert "remote attacker" in result["Vulnerability Summary"].lower()
    assert "_clamp_flags" not in result or len(result["_clamp_flags"]) == 0


def test_clamp_phrases_case_insensitive():
    """Phrase replacement is case-insensitive."""
    structured = {
        "Summary": "A REMOTE ATTACKER can exploit."
    }
    evidence = {
        "has_network_evidence": False
    }
    
    result = clamp_threat_model_phrases(structured, evidence)
    assert "remote attacker" not in result["Summary"].lower()


# ============================================================================
# Test 6: SARIF Export
# ============================================================================

def test_sarif_export_uses_evidence_locations():
    """SARIF export uses evidence_payload.locations only."""
    from app.db.models import Finding
    from app.services.sarif import findings_to_sarif
    from app.services.evidence_schema import EvidencePayload, EvidenceSource, EvidenceLocation
    
    # Build evidence_payload with locations
    payload = EvidencePayload(
        schema_version="v1",
        source=EvidenceSource(type="sarif", tool="test"),
        verbatim_text="test",
        locations=[
            EvidenceLocation(file="src/main.py", line=42),
            EvidenceLocation(file="src/utils.py", line=10)
        ]
    )
    
    finding = Finding(
        id="test123",
        organization_id="org1",
        report_id="report1",
        title="Test Finding",
        content_json='{"Severity": "High", "Affected Files": "wrong_file.py"}',
        evidence_payload=payload.to_json(),
        metadata_json="{}",
        notes="",
        template=""
    )
    
    sarif = findings_to_sarif([finding])
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    
    locations = results[0]["locations"]
    assert len(locations) == 2
    assert locations[0]["physicalLocation"]["artifactLocation"]["uri"] == "src/main.py"
    assert locations[0]["physicalLocation"]["region"]["startLine"] == 42
    assert locations[1]["physicalLocation"]["artifactLocation"]["uri"] == "src/utils.py"


def test_sarif_export_no_evidence_empty_locations():
    """SARIF export with no evidence has empty locations."""
    from app.db.models import Finding
    from app.services.sarif import findings_to_sarif
    
    finding = Finding(
        id="test124",
        organization_id="org1",
        report_id="report1",
        title="Test Finding",
        content_json='{"Severity": "High", "Affected Files": "this_should_be_ignored.py"}',
        metadata_json='{}',
        notes="",
        template=""
    )
    
    sarif = findings_to_sarif([finding])
    results = sarif["runs"][0]["results"]
    locations = results[0]["locations"]
    # Should be empty - no fallback parsing of Affected Files
    assert len(locations) == 0


def test_sarif_export_malformed_metadata():
    """SARIF export handles malformed metadata gracefully."""
    from app.db.models import Finding
    from app.services.sarif import findings_to_sarif
    
    finding = Finding(
        id="test125",
        organization_id="org1",
        report_id="report1",
        title="Test Finding",
        content_json='{"Severity": "Medium"}',
        metadata_json='invalid json{',
        notes="",
        template=""
    )
    
    # Should not crash
    sarif = findings_to_sarif([finding])
    assert sarif is not None


# ============================================================================
# Test 7: Severity Clamp
# ============================================================================

def test_clamp_severity_invalid_to_rubric():
    """Invalid severity is clamped to rubric-allowed value."""
    from app.services.severity_rubric import SeverityRubric
    
    structured = {
        "Severity": "VeryBad",  # Invalid
        "Vulnerability Summary": "Test"
    }
    rubric = SeverityRubric(
        allowed_labels=["Critical", "High", "Medium", "Low", "Informational"],
        definitions={},
        source="test"
    )
    
    result = clamp_severity(structured, rubric, "")
    # Should clamp to lowest allowed (Informational)
    assert result["Severity"] in rubric.allowed_labels


def test_clamp_severity_case_insensitive():
    """Severity clamping handles case variations."""
    from app.services.severity_rubric import SeverityRubric
    
    structured = {
        "Severity": "high",  # Lowercase
        "Summary": "Test"
    }
    rubric = SeverityRubric(
        allowed_labels=["Critical", "High", "Medium", "Low", "Informational"],
        definitions={},
        source="test"
    )
    
    result = clamp_severity(structured, rubric, "")
    # Should normalize to canonical casing
    assert result["Severity"] == "High"


# ============================================================================
# Test Artifact Severity Capping
# ============================================================================

class TestSeverityTestArtifactCapping:
    """Tests for test artifact detection and severity capping."""
    
    def test_jmeter_jmx_caps_to_low(self):
        """JMeter JMX file (score 4) caps High → Low."""
        from app.services.evidence_clamps import (
            classify_artifact_context,
            clamp_severity_for_test_artifacts
        )
        
        evidence = {
            "locations": [{"file": "loadtest.jmx", "line": 1}],
            "raw_tool_output": "JMeter test plan content",
            "tool": "JMeter"
        }
        
        classification = classify_artifact_context(evidence)
        assert classification["is_test"] is True
        assert classification["score"] >= 4
        assert "jmeter_jmx_file" in classification["signals"]
        
        structured = {"Severity": "High"}
        result = clamp_severity_for_test_artifacts(structured, evidence)
        
        assert result["Severity"] == "Low"
        assert any("severity_capped:High->Low" in flag for flag in result.get("_severity_flags", []))
        assert any("test_signal:jmeter_jmx_file" in flag for flag in result.get("_severity_flags", []))
    
    def test_jmeter_internal_only_caps_to_info(self):
        """JMX + internal IP only → cap to Informational."""
        from app.services.evidence_clamps import clamp_severity_for_test_artifacts
        
        evidence = {
            "locations": [{"file": "test.jmx", "line": 1}],
            "raw_tool_output": "JMeter test targeting http://10.0.0.5:8080",
            "tool": "JMeter"
        }
        
        structured = {"Severity": "Critical"}
        result = clamp_severity_for_test_artifacts(structured, evidence)
        
        assert result["Severity"] == "Informational"
        assert any("test_artifact_internal_only" in flag for flag in result.get("_severity_flags", []))
        assert any("internal_dest:RFC1918_10" in flag for flag in result.get("_severity_flags", []))
    
    def test_jmeter_with_external_caps_to_low(self):
        """JMX + external URL → cap to Low (not Informational)."""
        from app.services.evidence_clamps import clamp_severity_for_test_artifacts
        
        evidence = {
            "locations": [{"file": "api-test.jmx", "line": 1}],
            "raw_tool_output": "JMeter test targeting https://api.example.com",
            "tool": "JMeter"
        }
        
        structured = {"Severity": "High"}
        result = clamp_severity_for_test_artifacts(structured, evidence)
        
        assert result["Severity"] == "Low"
        assert any("test_artifact" in flag and "internal_only" not in flag 
                   for flag in result.get("_severity_flags", []))
    
    def test_filename_test_pattern_below_threshold(self):
        """Test filename alone (score 2) is below threshold, no cap."""
        from app.services.evidence_clamps import (
            classify_artifact_context,
            clamp_severity_for_test_artifacts
        )
        
        evidence = {
            "locations": [{"file": "FooTest.java", "line": 10}],
            "raw_tool_output": "Some generic content without test markers"
        }
        
        classification = classify_artifact_context(evidence)
        assert classification["score"] == 2  # Filename only
        assert classification["is_test"] is False  # Below threshold
        
        structured = {"Severity": "Critical"}
        result = clamp_severity_for_test_artifacts(structured, evidence)
        
        assert result["Severity"] == "Critical"  # No cap
    
    def test_filename_plus_content_caps(self):
        """Test filename (2) + @Test marker (2) = 4 → caps."""
        from app.services.evidence_clamps import clamp_severity_for_test_artifacts
        
        evidence = {
            "locations": [{"file": "ApiTest.java", "line": 50}],
            "raw_tool_output": "@Test public void testLogin() { ... }",
            "tool": "SonarQube"
        }
        
        structured = {"Severity": "High"}
        result = clamp_severity_for_test_artifacts(structured, evidence)
        
        assert result["Severity"] == "Low"
        assert any("test_signal:filename_ApiTest.java" in flag for flag in result.get("_severity_flags", []))
        assert any("test_signal:content_@Test" in flag for flag in result.get("_severity_flags", []))
    
    def test_non_test_with_internal_ip_no_cap(self):
        """Internal IP without test signals → no cap."""
        from app.services.evidence_clamps import clamp_severity_for_test_artifacts
        
        evidence = {
            "locations": [{"file": "api/login.php", "line": 20}],
            "raw_tool_output": "SQL injection found at http://192.168.1.10/login",
            "tool": "Burp Suite"
        }
        
        structured = {"Severity": "Critical"}
        result = clamp_severity_for_test_artifacts(structured, evidence)
        
        assert result["Severity"] == "Critical"  # No cap, not a test
    
    def test_already_low_no_downgrade(self):
        """Test artifact with Informational → no change."""
        from app.services.evidence_clamps import clamp_severity_for_test_artifacts
        
        evidence = {
            "locations": [{"file": "test.jmx", "line": 1}],
            "raw_tool_output": "JMeter test",
            "tool": "JMeter"
        }
        
        structured = {"Severity": "Informational"}
        result = clamp_severity_for_test_artifacts(structured, evidence)
        
        assert result["Severity"] == "Informational"  # Already at/below cap
    
    def test_signals_tracked_in_flags(self):
        """Verify all signals are tracked in _severity_flags."""
        from app.services.evidence_clamps import clamp_severity_for_test_artifacts
        
        evidence = {
            "locations": [
                {"file": "IntegrationTests.java", "line": 30, "snippet": "@Test void test() {}"}
            ],
            "raw_tool_output": "org.junit.jupiter detected in test file",
            "tool": "SpotBugs",
            "rule_id": "integration-test-rule"
        }
        
        structured = {"Severity": "Medium"}
        result = clamp_severity_for_test_artifacts(structured, evidence)
        
        # Should cap Medium → Low
        assert result["Severity"] == "Low"
        
        flags = result.get("_severity_flags", [])
        # Should have: capped, filename signal, content signals
        assert any("severity_capped" in flag for flag in flags)
        assert any("test_signal:filename" in flag for flag in flags)
        assert any("test_signal:content" in flag for flag in flags)
    
    def test_llm_generated_text_not_scanned(self):
        """Internal IP in description (LLM-authored) should NOT trigger internal_only."""
        from app.services.evidence_clamps import (
            classify_artifact_context,
            clamp_severity_for_test_artifacts
        )
        
        evidence = {
            "locations": [{"file": "test.jmx", "line": 1}],
            "raw_tool_output": "JMeter test with no IPs in verbatim content",
            "description": "This finding affects the internal server at 10.0.0.5",  # LLM-authored
            "remediation": "Contact localhost:8080 to verify",  # LLM-authored
            "tool": "JMeter"
        }
        
        classification = classify_artifact_context(evidence)
        assert classification["is_test"] is True
        # Should NOT detect internal destinations from description/remediation
        assert classification["internal_only"] is False
        
        structured = {"Severity": "High"}
        result = clamp_severity_for_test_artifacts(structured, evidence)
        
        # Should cap to Low (not Informational, because no internal in verbatim)
        assert result["Severity"] == "Low"
        assert not any("internal_dest" in flag for flag in result.get("_severity_flags", []))


# ============================================================================
# Summary
# ============================================================================

def test_full_evidence_pipeline():
    """Integration test: SARIF → evidence_payload → structured → export."""
    from app.api.findings import SarifFinding
    from app.services.evidence_schema import EvidencePayload
    
    # 1. Parse SARIF
    findings = [
        SarifFinding(
            ruleId="INT-001",
            name="Integration Test",
            severity="High",
            description="Test with https://api.example.com endpoint",
            remediation="Fix the issue",
            location="src/app.py",
            lineNumber=100,
            tool="IntegrationScanner"
        )
    ]
    
    # No patch needed
    merged = _merge_sarif_by_rule_id(findings)
    deduped = _dedupe_by_locations(merged)
    
    # 2. Verify evidence_payload
    assert len(deduped) == 1
    evidence_payload_json = deduped[0]["evidence_payload"]
    assert evidence_payload_json  # Not empty
    
    # Parse evidence_payload
    payload = EvidencePayload.from_json(evidence_payload_json)
    assert payload.source.rule_id == "INT-001"
    assert payload.source.tool == "IntegrationScanner"
    assert len(payload.locations) == 1
    assert payload.locations[0].file == "src/app.py"
    assert payload.locations[0].line == 100
    
    # Verify network evidence detection (https:// in description)
    assert "https://api.example.com" in payload.verbatim_text or any(
        "https://api.example.com" in str(v) for v in (payload.artifacts or {}).values()
    )
    
    # 3. Verify integrity
    assert payload.hash  # Hash present
    assert payload.verify_integrity()  # Hash valid
    
    print("\n✓ All evidence anchoring tests passed!")
