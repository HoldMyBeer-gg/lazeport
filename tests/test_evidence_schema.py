"""
Unit tests for evidence_schema.py

Tests canonical EvidencePayload schema, builders, hash integrity,
serialization, and iter_verbatim_text_parts() helper.
"""
import json
from app.services.evidence_schema import (
    EvidencePayload,
    EvidenceSource,
    EvidenceLocation,
    build_payload_from_sarif,
    build_payload_from_burp,
    build_payload_from_notes,
    iter_verbatim_text_parts,
    EVIDENCE_SCHEMA_VERSION,
)
from app.api.findings import parse_burp_xml


class TestEvidencePayloadBasics:
    """Test core EvidencePayload functionality."""
    
    def test_payload_creation_and_hash(self):
        """Test creating payload and computing hash."""
        payload = EvidencePayload(
            schema_version=EVIDENCE_SCHEMA_VERSION,
            source=EvidenceSource(
                type="notes",
                tool="Manual",
                rule_id=None,
                original_severity=None,
                imported_at="2026-02-10T12:00:00Z"
            ),
            verbatim_text="Test finding in app.py line 123",
            locations=[
                EvidenceLocation(file="app.py", line=123, snippet="print('hello')")
            ],
            artifacts=None
        )
        
        # Hash should be computed
        hash_value = payload.compute_hash()
        assert len(hash_value) == 64  # Full SHA256 hex digest
        assert hash_value.isalnum()  # Hex string
    
    def test_hash_integrity_verification(self):
        """Test hash verification detects tampering."""
        payload = EvidencePayload(
            schema_version=EVIDENCE_SCHEMA_VERSION,
            source=EvidenceSource(type="notes", tool="Manual"),
            verbatim_text="Original text",
            locations=[]
        )
        
        # Compute and set hash
        payload.hash = payload.compute_hash()
        assert payload.verify_integrity() is True
        
        # Tamper with payload
        payload.verbatim_text = "Tampered text"
        assert payload.verify_integrity() is False  # Hash mismatch detected
    
    def test_serialization_roundtrip(self):
        """Test to_json() and from_json() roundtrip."""
        original = EvidencePayload(
            schema_version=EVIDENCE_SCHEMA_VERSION,
            source=EvidenceSource(
                type="sarif",
                tool="Semgrep",
                rule_id="CWE-79",
                original_severity="high",
                imported_at="2026-02-10T12:00:00Z"
            ),
            verbatim_text="XSS detected in input handler",
            locations=[
                EvidenceLocation(file="src/handler.py", line=45, snippet="input = request.GET['user']")
            ],
            artifacts={"raw_sarif_result": {"ruleId": "CWE-79", "level": "error"}}
        )
        
        # Serialize
        json_str = original.to_json()
        assert isinstance(json_str, str)
        assert original.hash is not None  # Hash computed during to_json()
        
        # Deserialize
        restored = EvidencePayload.from_json(json_str)
        
        # Verify fields match
        assert restored.schema_version == original.schema_version
        assert restored.source.type == original.source.type
        assert restored.source.tool == original.source.tool
        assert restored.source.rule_id == original.source.rule_id
        assert restored.verbatim_text == original.verbatim_text
        assert len(restored.locations) == 1
        assert restored.locations[0].file == "src/handler.py"
        assert restored.locations[0].line == 45
        assert restored.artifacts["raw_sarif_result"]["ruleId"] == "CWE-79"
        assert restored.hash == original.hash

    def test_from_json_rejects_malformed_structure(self):
        """LOW-9: from_json validates structure and raises clear ValueError."""
        import pytest

        # Invalid JSON
        with pytest.raises(ValueError, match="invalid JSON"):
            EvidencePayload.from_json("not json")

        # Missing required fields
        with pytest.raises(ValueError, match="missing required field"):
            EvidencePayload.from_json('{"schema_version": "v1"}')

        # source not a dict
        with pytest.raises(ValueError, match="'source' must be an object"):
            EvidencePayload.from_json(
                '{"schema_version":"v1","source":"string","verbatim_text":"","locations":[]}'
            )

        # source missing type/tool
        with pytest.raises(ValueError, match="'source' missing required"):
            EvidencePayload.from_json(
                '{"schema_version":"v1","source":{},"verbatim_text":"","locations":[]}'
            )

        # locations not a list
        with pytest.raises(ValueError, match="'locations' must be an array"):
            EvidencePayload.from_json(
                '{"schema_version":"v1","source":{"type":"sarif","tool":"X"},"verbatim_text":"","locations":"not-list"}'
            )

        # Wrong schema version (LOW-8)
        with pytest.raises(ValueError, match="not supported"):
            EvidencePayload.from_json(
                '{"schema_version":"v2","source":{"type":"sarif","tool":"X"},"verbatim_text":"","locations":[]}'
            )


class TestBuildPayloadFromSARIF:
    """Test build_payload_from_sarif() builder."""
    
    def test_preserves_raw_sarif_result(self):
        """Test that raw SARIF result is stored EXACTLY as parsed."""
        sarif_result = {
            "ruleId": "semgrep.python.sql-injection",
            "message": {"text": "Potential SQL injection detected"},
            "level": "error",
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "app/db.py"},
                        "region": {
                            "startLine": 42,
                            "snippet": {"text": "cursor.execute(query)"}
                        }
                    }
                }
            ],
            "properties": {
                "cvss": "7.5",
                "cwe": "CWE-89",
                "precision": "high"
            }
        }
        
        payload = build_payload_from_sarif(sarif_result, "Semgrep")
        
        # Verify source metadata
        assert payload.source.type == "sarif"
        assert payload.source.tool == "Semgrep"
        assert payload.source.rule_id == "semgrep.python.sql-injection"
        assert payload.source.original_severity == "error"
        
        # Verify verbatim text
        assert payload.verbatim_text == "Potential SQL injection detected"
        
        # Verify locations extracted correctly
        assert len(payload.locations) == 1
        assert payload.locations[0].file == "app/db.py"
        assert payload.locations[0].line == 42
        assert payload.locations[0].snippet == "cursor.execute(query)"
        
        # CRITICAL: Verify raw SARIF result stored EXACTLY
        assert payload.artifacts is not None
        assert "raw_sarif_result" in payload.artifacts
        assert payload.artifacts["raw_sarif_result"] == sarif_result  # Exact match
        assert payload.artifacts["raw_sarif_result"]["properties"]["cvss"] == "7.5"
    
    def test_handles_missing_optional_fields(self):
        """Test SARIF builder handles missing optional fields gracefully."""
        minimal_sarif = {
            "ruleId": "test-rule",
            "message": {"text": "Test message"}
        }
        
        payload = build_payload_from_sarif(minimal_sarif, "TestTool")
        
        assert payload.source.type == "sarif"
        assert payload.source.tool == "TestTool"
        assert payload.verbatim_text == "Test message"
        assert len(payload.locations) == 0  # No locations in input
        assert payload.artifacts["raw_sarif_result"] == minimal_sarif


class TestBuildPayloadFromBurp:
    """Test build_payload_from_burp() builder."""
    
    def test_includes_all_artifacts(self):
        """Test that Burp builder stores raw XML, HTTP request, and response."""
        issue_dict = {
            "name": "SQL Injection",
            "host": "https://api.example.com",
            "path": "/login",
            "severity": "High",
            "type": "1234567",
            "issueDetail": "Parameter 'username' appears vulnerable...",
            "issueBackground": "SQL injection is a common attack...",
            "remediationDetail": "Use prepared statements",
            "requestresponse": {
                "request": "POST /login HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 45\r\n\r\nusername=admin&password=test",
                "response": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Welcome</html>"
            }
        }
        issue_xml_string = "<issue><name>SQL Injection</name><severity>High</severity></issue>"
        
        payload = build_payload_from_burp(issue_dict, issue_xml_string, "Burp Suite")
        
        # Verify source metadata
        assert payload.source.type == "burp_xml"
        assert payload.source.tool == "Burp Suite"
        assert payload.source.rule_id == "1234567"
        assert payload.source.original_severity == "High"
        
        # Verify verbatim text assembled from issue details
        assert "SQL Injection" in payload.verbatim_text
        assert "Parameter 'username' appears vulnerable" in payload.verbatim_text
        assert "SQL injection is a common attack" in payload.verbatim_text
        
        # Verify location extracted from host+path
        assert len(payload.locations) == 1
        assert payload.locations[0].file == "https://api.example.com/login"
        assert payload.locations[0].line is None
        
        # CRITICAL: Verify all artifacts stored verbatim
        assert payload.artifacts is not None
        assert payload.artifacts["burp_xml_issue"] == issue_xml_string
        assert payload.artifacts["http_request"] == issue_dict["requestresponse"]["request"]
        assert payload.artifacts["http_response"] == issue_dict["requestresponse"]["response"]
    
    def test_handles_missing_request_response(self):
        """Test Burp builder handles missing HTTP artifacts gracefully."""
        issue_dict = {
            "name": "Information Disclosure",
            "host": "https://example.com",
            "path": "/",
            "severity": "Low",
        }
        issue_xml = "<issue><name>Info</name></issue>"
        
        payload = build_payload_from_burp(issue_dict, issue_xml, "Burp Suite")
        
        assert payload.artifacts["burp_xml_issue"] == issue_xml
        assert payload.artifacts["http_request"] == ""  # Empty, not None
        assert payload.artifacts["http_response"] == ""


class TestParseBurpXml:
    """Test parse_burp_xml() XML parsing and request/response extraction."""
    
    def test_extracts_requestresponse_from_xml(self):
        """Test MED-29: parse_burp_xml extracts <requestresponse> elements."""
        xml_content = """<?xml version="1.0"?>
<issues burpVersion="2024.1.1">
  <issue>
    <serialNumber>12345</serialNumber>
    <type>1048576</type>
    <name>SQL Injection</name>
    <host ip="192.168.1.100">https://api.example.com</host>
    <path><![CDATA[/api/login]]></path>
    <location><![CDATA[https://api.example.com/api/login]]></location>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueBackground>SQL injection attacks occur when...</issueBackground>
    <remediationBackground>Use parameterized queries...</remediationBackground>
    <issueDetail>The username parameter is vulnerable...</issueDetail>
    <remediationDetail>Replace string concatenation with prepared statements</remediationDetail>
    <requestresponse>
      <request base64="true">UE9TVCAvYXBpL2xvZ2luIEhUVFAvMS4xDQpIb3N0OiBhcGkuZXhhbXBsZS5jb20NCkNvbnRlbnQtTGVuZ3RoOiAzMA0KDQp1c2VybmFtZT1hZG1pbiZwYXNzd29yZD10ZXN0</request>
      <response base64="true">SFRUUC8xLjEgMjAwIE9LDQpDb250ZW50LVR5cGU6IHRleHQvaHRtbA0KDQo8aHRtbD5XZWxjb21lPC9odG1sPg==</response>
    </requestresponse>
  </issue>
</issues>"""
        
        findings = parse_burp_xml(xml_content)
        
        assert len(findings) == 1
        finding = findings[0]
        
        assert finding.name == "SQL Injection"
        assert finding.severity == "High"
        assert finding.serialNumber == "12345"
        
        # MED-29: Verify requestresponse data was extracted
        assert finding.requestresponse is not None
        assert finding.requestresponse["request"] == "UE9TVCAvYXBpL2xvZ2luIEhUVFAvMS4xDQpIb3N0OiBhcGkuZXhhbXBsZS5jb20NCkNvbnRlbnQtTGVuZ3RoOiAzMA0KDQp1c2VybmFtZT1hZG1pbiZwYXNzd29yZD10ZXN0"
        assert finding.requestresponse["response"] == "SFRUUC8xLjEgMjAwIE9LDQpDb250ZW50LVR5cGU6IHRleHQvaHRtbA0KDQo8aHRtbD5XZWxjb21lPC9odG1sPg=="
    
    def test_handles_missing_requestresponse(self):
        """Test parse_burp_xml handles missing requestresponse gracefully."""
        xml_content = """<?xml version="1.0"?>
<issues burpVersion="2024.1.1">
  <issue>
    <serialNumber>99999</serialNumber>
    <type>2097152</type>
    <name>Information Disclosure</name>
    <host>https://example.com</host>
    <path>/</path>
    <location>https://example.com/</location>
    <severity>Low</severity>
    <confidence>Firm</confidence>
  </issue>
</issues>"""
        
        findings = parse_burp_xml(xml_content)
        
        assert len(findings) == 1
        assert findings[0].requestresponse is None
    
    def test_handles_partial_requestresponse(self):
        """Test parse_burp_xml handles requestresponse with only request or only response."""
        xml_content = """<?xml version="1.0"?>
<issues>
  <issue>
    <serialNumber>11111</serialNumber>
    <type>123</type>
    <name>Test Issue</name>
    <host>https://test.com</host>
    <severity>Medium</severity>
    <confidence>Certain</confidence>
    <requestresponse>
      <request>GET / HTTP/1.1</request>
    </requestresponse>
  </issue>
</issues>"""
        
        findings = parse_burp_xml(xml_content)
        
        assert len(findings) == 1
        assert findings[0].requestresponse is not None
        assert findings[0].requestresponse["request"] == "GET / HTTP/1.1"
        assert findings[0].requestresponse["response"] == ""

    def test_extracts_nested_content_from_issue_detail(self):
        """Test LOW-27: parse_burp_xml extracts full text from nested HTML in issueDetail."""
        xml_content = """<?xml version="1.0"?>
<issues>
  <issue>
    <serialNumber>77777</serialNumber>
    <type>1</type>
    <name>XSS</name>
    <host>https://example.com</host>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueDetail><p>Paragraph one</p><p>Paragraph two</p><ul><li>Item A</li><li>Item B</li></ul></issueDetail>
  </issue>
</issues>"""
        findings = parse_burp_xml(xml_content)
        assert len(findings) == 1
        # elem.text would miss nested content; itertext captures all
        assert "Paragraph one" in findings[0].issueDetail
        assert "Paragraph two" in findings[0].issueDetail
        assert "Item A" in findings[0].issueDetail
        assert "Item B" in findings[0].issueDetail


class TestBuildPayloadFromNotes:
    """Test build_payload_from_notes() builder."""
    
    def test_extracts_locations_from_notes(self):
        """Test location extraction from various note formats."""
        notes = """
SQL injection found in app/db.py:123

The login handler at src/auth.py line 45 is vulnerable.

Another issue in config.yaml (line 10).
"""
        
        payload = build_payload_from_notes(notes)
        
        # Verify source metadata
        assert payload.source.type == "notes"
        assert payload.source.tool == "Manual"
        assert payload.source.rule_id is None
        
        # Verify verbatim text is notes snapshot (capped)
        assert payload.verbatim_text == notes  # Should be exact for short notes
        
        # Verify locations extracted via regex
        assert len(payload.locations) >= 3
        
        # Check specific extracted locations (order may vary)
        files = {loc.file: loc.line for loc in payload.locations}
        assert files.get("app/db.py") == 123
        assert files.get("src/auth.py") == 45
        assert files.get("config.yaml") == 10
        
        # Verify no artifacts for notes-only findings
        assert payload.artifacts is None
    
    def test_caps_notes_snapshot_at_50k(self):
        """Test that notes are capped to prevent bloat."""
        long_notes = "A" * 60000  # 60k chars
        
        payload = build_payload_from_notes(long_notes)
        
        assert len(payload.verbatim_text) == 50000  # Capped
        assert payload.verbatim_text == long_notes[:50000]


class TestIterVerbatimTextParts:
    """Test iter_verbatim_text_parts() helper for policy scanning."""
    
    def test_returns_all_blobs_sarif(self):
        """Test that helper returns ALL verbatim parts for SARIF payload."""
        sarif_result = {
            "ruleId": "test-rule",
            "message": {"text": "Primary message"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "file1.py"},
                        "region": {
                            "startLine": 10,
                            "snippet": {"text": "snippet1 = code"}
                        }
                    }
                },
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "file2.py"},
                        "region": {
                            "startLine": 20,
                            "snippet": {"text": "snippet2 = more_code"}
                        }
                    }
                }
            ],
            "properties": {"internal_host": "192.168.1.1"}
        }
        
        payload = build_payload_from_sarif(sarif_result, "TestTool")
        parts = iter_verbatim_text_parts(payload)
        
        # Should return: verbatim_text + 2 snippets + raw_sarif_result (JSON)
        assert len(parts) >= 4
        
        # Verify verbatim_text included
        assert "Primary message" in parts
        
        # Verify snippets included
        assert "snippet1 = code" in parts
        assert "snippet2 = more_code" in parts
        
        # Verify raw_sarif_result included (as JSON string)
        combined = " ".join(parts)
        assert "192.168.1.1" in combined  # From properties in raw_sarif_result
        assert '"ruleId"' in combined or 'ruleId' in combined  # JSON structure present
    
    def test_returns_all_blobs_burp(self):
        """Test that helper returns ALL verbatim parts for Burp payload."""
        issue_dict = {
            "name": "Test Issue",
            "host": "https://test.com",
            "path": "/api",
            "issueDetail": "Detail text with 10.0.0.5",
            "requestresponse": {
                "request": "POST /api HTTP/1.1\r\nHost: test.com\r\nInternal-IP: 192.168.1.100",
                "response": "HTTP/1.1 200 OK\r\nServer: nginx\r\nlocalhost reference"
            }
        }
        issue_xml = "<issue><host>https://test.com</host><path>/api</path></issue>"
        
        payload = build_payload_from_burp(issue_dict, issue_xml, "Burp Suite")
        parts = iter_verbatim_text_parts(payload)
        
        # Should return: verbatim_text + http_request + http_response + burp_xml_issue
        assert len(parts) == 4
        
        combined = " ".join(parts)
        
        # Verify all parts included
        assert "Test Issue" in combined
        assert "10.0.0.5" in combined  # From issueDetail
        assert "192.168.1.100" in combined  # From HTTP request
        assert "localhost reference" in combined  # From HTTP response
        assert "<host>https://test.com</host>" in combined  # From raw XML
    
    def test_returns_all_blobs_notes(self):
        """Test that helper returns verbatim_text for notes payload."""
        notes = "Finding in src/app.py:123\nInternal host 10.0.1.5"
        payload = build_payload_from_notes(notes)
        parts = iter_verbatim_text_parts(payload)
        
        # Should return: verbatim_text + extracted snippet (if any)
        assert len(parts) >= 1
        
        combined = " ".join(parts)
        assert "Internal host 10.0.1.5" in combined
        assert "src/app.py" in combined
    
    def test_json_serializes_non_string_artifacts(self):
        """Test that non-string artifacts are JSON-serialized for scanning."""
        payload = EvidencePayload(
            schema_version=EVIDENCE_SCHEMA_VERSION,
            source=EvidenceSource(type="test", tool="TestTool"),
            verbatim_text="Test",
            locations=[],
            artifacts={
                "string_artifact": "plain text",
                "dict_artifact": {"key": "value", "internal_ip": "192.168.1.1"},
                "list_artifact": ["item1", "10.0.0.1", "item2"]
            }
        )
        
        parts = iter_verbatim_text_parts(payload)
        combined = " ".join(parts)
        
        # String artifact should be included directly
        assert "plain text" in combined
        
        # Non-string artifacts should be JSON-serialized
        assert "192.168.1.1" in combined  # From dict
        assert "10.0.0.1" in combined  # From list
        assert '"key"' in combined or 'key' in combined  # JSON structure


class TestHashComputation:
    """Test hash computation and integrity."""
    
    def test_hash_is_full_64_chars(self):
        """Test that hash is full 64-character SHA256 hex digest."""
        payload = EvidencePayload(
            schema_version=EVIDENCE_SCHEMA_VERSION,
            source=EvidenceSource(type="notes", tool="Manual"),
            verbatim_text="Test",
            locations=[]
        )
        
        hash_value = payload.compute_hash()
        assert len(hash_value) == 64
        assert all(c in '0123456789abcdef' for c in hash_value)
    
    def test_hash_excludes_hash_field(self):
        """Test that hash computation excludes the hash field itself."""
        payload1 = EvidencePayload(
            schema_version=EVIDENCE_SCHEMA_VERSION,
            source=EvidenceSource(type="notes", tool="Manual"),
            verbatim_text="Test",
            locations=[],
            hash="old_hash_value"
        )
        
        payload2 = EvidencePayload(
            schema_version=EVIDENCE_SCHEMA_VERSION,
            source=EvidenceSource(type="notes", tool="Manual"),
            verbatim_text="Test",
            locations=[],
            hash="different_hash_value"
        )
        
        # Both should compute to same hash since hash field is excluded
        assert payload1.compute_hash() == payload2.compute_hash()
    
    def test_hash_changes_when_content_changes(self):
        """Test that hash changes when payload content changes."""
        base_payload = EvidencePayload(
            schema_version=EVIDENCE_SCHEMA_VERSION,
            source=EvidenceSource(type="notes", tool="Manual"),
            verbatim_text="Original",
            locations=[]
        )
        
        modified_payload = EvidencePayload(
            schema_version=EVIDENCE_SCHEMA_VERSION,
            source=EvidenceSource(type="notes", tool="Manual"),
            verbatim_text="Modified",  # Changed
            locations=[]
        )
        
        assert base_payload.compute_hash() != modified_payload.compute_hash()
    
    def test_to_json_automatically_computes_hash(self):
        """Test that to_json() computes hash if not present."""
        payload = EvidencePayload(
            schema_version=EVIDENCE_SCHEMA_VERSION,
            source=EvidenceSource(type="notes", tool="Manual"),
            verbatim_text="Test",
            locations=[]
        )
        
        assert payload.hash is None  # No hash yet
        
        json_str = payload.to_json()
        
        assert payload.hash is not None  # Hash computed
        assert len(payload.hash) == 64
        
        # Verify hash is in serialized JSON
        data = json.loads(json_str)
        assert data["hash"] == payload.hash


class TestPolicyScanningWithPayload:
    """Test that policy functions use iter_verbatim_text_parts correctly."""
    
    def test_policy_scanning_fallback_without_payload_object(self):
        """Test that policy functions fall back gracefully without _payload_object."""
        from app.services.evidence_clamps import _detect_internal_destinations
        
        # Evidence dict without _payload_object should use fallback (legacy behavior)
        evidence_without_payload = {
            "rule_id": "test",
            "tool": "TestTool",
            "verbatim_text": "Connection to 192.168.1.1",
            "locations": [{"file": "test.py", "line": 1, "snippet": "internal IP"}]
        }
        
        # Should work via fallback, detecting the internal IP
        matched, found = _detect_internal_destinations(evidence_without_payload)
        assert found  # Should detect internal IP even without _payload_object
    
    def test_policy_scans_all_verbatim_parts(self):
        """Test that policy functions scan ALL parts via iter_verbatim_text_parts."""
        from app.services.evidence_clamps import _detect_internal_destinations
        
        # Create payload with internal IP in different locations
        payload = EvidencePayload(
            schema_version=EVIDENCE_SCHEMA_VERSION,
            source=EvidenceSource(type="burp_xml", tool="Burp Suite"),
            verbatim_text="No IP here",
            locations=[
                EvidenceLocation(
                    file="test.py",
                    line=1,
                    snippet="connection to 192.168.1.100"  # Internal IP in snippet
                )
            ],
            artifacts={
                "http_request": "GET / HTTP/1.1\r\nHost: 10.0.0.5",  # Internal IP in request
                "http_response": "HTTP/1.1 200 OK",
                "burp_xml_issue": "<host>localhost</host>"  # localhost in XML
            }
        )
        
        evidence = {
            "rule_id": "",
            "tool": "Burp Suite",
            "verbatim_text": payload.verbatim_text,
            "locations": [{"file": loc.file, "line": loc.line, "snippet": loc.snippet} for loc in payload.locations],
            "_payload_object": payload
        }
        
        matched, found = _detect_internal_destinations(evidence)
        
        # Should detect internal IPs from ALL parts (snippet, http_request, burp_xml)
        assert found is True
        assert len(matched) >= 3  # RFC1918_192.168, RFC1918_10, localhost
        assert "RFC1918_192.168" in matched
        assert "RFC1918_10" in matched
        assert "localhost" in matched


class TestImmutability:
    """Test evidence immutability contract."""
    
    def test_payload_hash_unchanged_on_regeneration(self):
        """Test that hash remains constant across serialization."""
        payload = EvidencePayload(
            schema_version=EVIDENCE_SCHEMA_VERSION,
            source=EvidenceSource(type="notes", tool="Manual", imported_at="2026-02-10T12:00:00Z"),
            verbatim_text="Original notes",
            locations=[]
        )
        
        # Serialize
        json1 = payload.to_json()
        hash1 = payload.hash
        
        # Deserialize
        restored = EvidencePayload.from_json(json1)
        
        # Serialize again
        json2 = restored.to_json()
        hash2 = restored.hash
        
        # Hash should be identical
        assert hash1 == hash2
        assert json1 == json2


class TestLocationExtraction:
    """Test _extract_locations_from_text() helper."""
    
    def test_extracts_file_colon_line(self):
        """Test extraction of file:line pattern."""
        from app.services.evidence_schema import _extract_locations_from_text
        
        text = "Found in src/app.py:123 and config/settings.yml:456"
        locations = _extract_locations_from_text(text)
        
        assert len(locations) == 2
        assert any(loc.file == "src/app.py" and loc.line == 123 for loc in locations)
        assert any(loc.file == "config/settings.yml" and loc.line == 456 for loc in locations)
    
    def test_extracts_file_line_keyword(self):
        """Test extraction of 'file line N' pattern."""
        from app.services.evidence_schema import _extract_locations_from_text
        
        text = "Vulnerability in handler.js line 78"
        locations = _extract_locations_from_text(text)
        
        assert len(locations) == 1
        assert locations[0].file == "handler.js"
        assert locations[0].line == 78
    
    def test_deduplicates_locations(self):
        """Test that duplicate locations are removed."""
        from app.services.evidence_schema import _extract_locations_from_text
        
        text = "app.py:10 and app.py:10 and app.py:10"
        locations = _extract_locations_from_text(text)
        
        assert len(locations) == 1  # Deduplicated
    
    def test_caps_at_20_locations(self):
        """Test that location extraction is capped to prevent bloat."""
        from app.services.evidence_schema import _extract_locations_from_text
        
        # Generate 30 unique file:line patterns
        text = " ".join([f"file{i}.py:{i}" for i in range(30)])
        locations = _extract_locations_from_text(text)
        
        assert len(locations) == 20  # Capped
