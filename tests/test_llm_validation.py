"""
Unit tests for LLM output validation and SARIF export resilience.

All test data uses synthetic/fake content only. No real assessment data.
"""

import json
import pytest
from datetime import datetime

from app.services.llm_validation import validate_structured_output, get_strict_retry_instructions
from app.services.sarif import findings_to_sarif, _looks_like_file_path
from app.services.evidence_schema import EvidencePayload, EvidenceSource, EvidenceLocation
from app.db.models import Finding


class TestLLMOutputValidation:
    """Test validation of LLM-generated structured output."""
    
    def test_valid_output_passes(self):
        """Test that properly formatted output passes validation."""
        structured = {
            "Vulnerability Summary": "The application uses weak MD5 hashing.",
            "Severity": "High",
            "Remediation": "Replace MD5 with SHA-256 or better.",
            "Affected Files": "src/crypto/hash.py:42"
        }
        is_valid, issues = validate_structured_output(structured)
        assert is_valid
        assert len(issues) == 0
    
    def test_non_string_value_fails(self):
        """Test that non-string field values fail validation."""
        structured = {
            "Vulnerability Summary": "Some text",
            "Severity": {"value": "High", "score": 7.5},  # Dict instead of string
        }
        is_valid, issues = validate_structured_output(structured)
        assert not is_valid
        assert any("not a string" in issue for issue in issues)
    
    def test_embedded_json_object_fails(self):
        """Test that JSON object in string field fails validation."""
        structured = {
            "Vulnerability Summary": '{"title": "Weak Crypto", "severity": "High", "impact": "Data exposure"}',
        }
        is_valid, issues = validate_structured_output(structured)
        assert not is_valid
        assert any("embedded JSON" in issue for issue in issues)
    
    def test_embedded_json_array_fails(self):
        """Test that JSON array in string field fails validation."""
        structured = {
            "Affected Files": '["app/Main.kt", "src/crypto.py", "lib/hash.js"]',
        }
        is_valid, issues = validate_structured_output(structured)
        assert not is_valid
        assert any("embedded JSON" in issue for issue in issues)
    
    def test_code_fences_fail(self):
        """Test that code fences in field fail validation."""
        structured = {
            "Evidence": "The following code was found:\n```python\nimport md5\n```",
        }
        is_valid, issues = validate_structured_output(structured)
        assert not is_valid
        assert any("code fences" in issue for issue in issues)
    
    def test_schema_dump_fails(self):
        """Test that schema dump in one field fails validation."""
        structured = {
            "Vulnerability Summary": (
                "Title: Weak Crypto\n"
                "Severity: High\n"
                "Root Cause: MD5 usage\n"
                "Remediation: Use SHA-256\n"
                "Impact: Data exposure"
            ),
        }
        is_valid, issues = validate_structured_output(structured)
        assert not is_valid
        assert any("schema dump" in issue for issue in issues)
    
    def test_stringified_json_fails(self):
        """Test that stringified JSON (key-value pairs) fails validation."""
        structured = {
            "Summary": '"title": "Weak Crypto", "severity": "High", "impact": "Bad", "remediation": "Fix it"',
        }
        is_valid, issues = validate_structured_output(structured)
        assert not is_valid
        assert any("stringified JSON" in issue for issue in issues)
    
    def test_internal_keys_ignored(self):
        """Test that internal keys (starting with _) are ignored."""
        structured = {
            "Summary": "Valid text",
            "_guardrail_flags": ["removed: remote attacker"],  # Should be ignored
            "_internal_data": {"some": "dict"},  # Should be ignored
        }
        is_valid, issues = validate_structured_output(structured)
        assert is_valid
        assert len(issues) == 0
    
    def test_empty_fields_allowed(self):
        """Test that empty string fields are allowed."""
        structured = {
            "Summary": "Valid text",
            "Details": "",
            "Notes": "   ",  # Whitespace only
        }
        is_valid, issues = validate_structured_output(structured)
        assert is_valid
    
    def test_strict_retry_instructions_exist(self):
        """Test that strict retry instructions are non-empty."""
        instructions = get_strict_retry_instructions()
        assert len(instructions) > 100
        assert "JSON object" in instructions
        assert "string values" in instructions
        assert "code fences" in instructions


class TestSarifFilePathValidation:
    """Test SARIF export resilience to malformed Affected Files."""
    
    def test_valid_file_paths_accepted(self):
        """Test that real file paths are accepted."""
        assert _looks_like_file_path("app/Main.kt")
        assert _looks_like_file_path("src/crypto.py:42")
        assert _looks_like_file_path("C:\\repo\\app\\Main.kt:47")
        assert _looks_like_file_path("lib/hash.js")
        assert _looks_like_file_path("config.yaml")
        assert _looks_like_file_path("README.md:10")
        assert _looks_like_file_path("./local/file.txt")
        assert _looks_like_file_path("../parent/dir/file.py")
        assert _looks_like_file_path("src/auth/login.py:15")
        assert _looks_like_file_path("D:\\Windows\\Path\\file.java:100")
    
    def test_json_syntax_rejected(self):
        """Test that JSON syntax is rejected."""
        assert not _looks_like_file_path('{"file": "app/Main.kt"}')
        assert not _looks_like_file_path('["app/Main.kt", "src/crypto.py"]')
        assert not _looks_like_file_path('"app/Main.kt"')
    
    def test_schema_keywords_rejected(self):
        """Test that schema keywords are rejected."""
        assert not _looks_like_file_path("Title: Weak Cryptography")
        assert not _looks_like_file_path("Root Cause: MD5 usage")
        assert not _looks_like_file_path("Remediation: Use SHA-256")
        assert not _looks_like_file_path("Vulnerability Summary: Bad crypto")
        assert not _looks_like_file_path("Severity: High")
    
    def test_list_markers_rejected(self):
        """Test that list markers are rejected."""
        assert not _looks_like_file_path("- app/Main.kt")
        assert not _looks_like_file_path("* src/crypto.py")
        assert not _looks_like_file_path("• lib/hash.js")
    
    def test_prose_rejected(self):
        """Test that prose/narrative text is rejected."""
        assert not _looks_like_file_path("The application uses weak MD5 hashing in several locations")
        assert not _looks_like_file_path("This finding affects multiple files, including the main module")
    
    def test_quoted_strings_rejected(self):
        """Test that quoted strings are rejected."""
        assert not _looks_like_file_path('"file": "app/Main.kt", "line": 42')
        assert not _looks_like_file_path('"Severity": "High", "Impact": "Bad"')
    
    def test_empty_lines_rejected(self):
        """Test that empty lines are rejected."""
        assert not _looks_like_file_path("")
        assert not _looks_like_file_path("   ")
        assert not _looks_like_file_path("\n")
    
    def test_json_characters_rejected(self):
        """Test that JSON-specific characters are strictly rejected."""
        # Curly braces
        assert not _looks_like_file_path("app/{file}.kt")
        assert not _looks_like_file_path("{\"file\": \"app/Main.kt\"}")
        
        # Key-value separator
        assert not _looks_like_file_path("\"file\": \"app/Main.kt\"")
        assert not _looks_like_file_path("path: \"src/file.py\"")
        
        # Common JSON keys
        assert not _looks_like_file_path("\"title\": \"Vulnerability\"")
        assert not _looks_like_file_path("\"Vulnerability Summary\": \"text\"")
        assert not _looks_like_file_path("\"severity\": \"High\"")
        assert not _looks_like_file_path("\"impact\": \"Critical\"")
        
        # Escaped characters (JSON strings)
        assert not _looks_like_file_path("line with \\n newline")
        assert not _looks_like_file_path("unicode \\u0041 char")
        
        # ZIP header
        assert not _looks_like_file_path("PK\x03\x04binary data")
    
    def test_paths_without_extensions_rejected(self):
        """Test that paths without clear structure are rejected."""
        # No extension, no path separators
        assert not _looks_like_file_path("justfilename")
        assert not _looks_like_file_path("SomeRandomText")
    
    def test_relative_paths_accepted(self):
        """Test that relative paths with proper structure are accepted."""
        assert _looks_like_file_path("./config.yaml")
        assert _looks_like_file_path("../lib/utils.js")
        assert _looks_like_file_path("../../parent/file.py:25")


class TestSarifExportResilience:
    """Test SARIF export with malformed Affected Files data."""
    
    def test_sarif_export_rejects_json_blob_corruption(self):
        """
        Test that SARIF export uses evidence.locations only, immune to Affected Files corruption.
        Even if Affected Files contains JSON blobs, SARIF locations come from evidence_payload only.
        """
        # Finding with corrupted Affected Files but proper evidence_payload
        payload = EvidencePayload(
            schema_version="v1",
            source=EvidenceSource(type="sarif", tool="test"),
            verbatim_text="test",
            locations=[
                EvidenceLocation(file="app/real_file.py", line=42)
            ]
        )
        
        finding = Finding(
            id="test-json-corruption",
            organization_id="org-1",
            report_id="report-1",
            title="Corrupted Finding",
            content_json=json.dumps({
                "Severity": "High",
                "Affected Files": '{"title": "JSON blob that should be ignored"}'
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
        
        # Should use evidence_payload.locations, not corrupted Affected Files
        assert len(locations) == 1
        assert locations[0]["physicalLocation"]["artifactLocation"]["uri"] == "app/real_file.py"
        assert locations[0]["physicalLocation"]["region"]["startLine"] == 42
    
    def test_sarif_export_clean_file_paths_only(self):
        """Test that SARIF export uses clean evidence_payload.locations only."""
        payload = EvidencePayload(
            schema_version="v1",
            source=EvidenceSource(type="sarif", tool="test"),
            verbatim_text="test",
            locations=[
                EvidenceLocation(file="app/Main.kt", line=12),
                EvidenceLocation(file="src/crypto.py", line=25),
                EvidenceLocation(file="lib/hash.java")
            ]
        )
        
        finding = Finding(
            id="test-finding-1",
            organization_id="org-1",
            report_id="report-1",
            title="Test Finding",
            content_json=json.dumps({
                "Severity": "High",
                "Affected Files": "This field is ignored by SARIF export"
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
        
        # Should have exactly 3 valid locations from evidence_payload
        assert len(locations) == 3
        
        uris = [loc["physicalLocation"]["artifactLocation"]["uri"] for loc in locations]
        assert "app/Main.kt" in uris
        assert "src/crypto.py" in uris
        assert "lib/hash.java" in uris
    
    def test_sarif_export_windows_paths_preserved(self):
        """Test that Windows paths from evidence_payload are preserved correctly."""
        payload = EvidencePayload(
            schema_version="v1",
            source=EvidenceSource(type="sarif", tool="test"),
            verbatim_text="test",
            locations=[
                EvidenceLocation(file="C:\\repo\\app\\MainActivity.kt", line=47)
            ]
        )
        
        finding = Finding(
            id="test-finding-win",
            organization_id="org-1",
            report_id="report-1",
            title="Windows Path Test",
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
        
        assert len(locations) == 1
        assert locations[0]["physicalLocation"]["artifactLocation"]["uri"] == "C:\\repo\\app\\MainActivity.kt"
        assert locations[0]["physicalLocation"]["region"]["startLine"] == 47
    
    def test_sarif_export_empty_when_all_malformed(self):
        """Test that locations is empty when all lines are malformed."""
        finding = Finding(
            id="test-finding-bad",
            organization_id="org-1",
            report_id="report-1",
            title="All Malformed",
            content_json=json.dumps({
                "Severity": "Low",
                "Affected Files": (
                    '{"file": "bad.json"}\n'
                    "Title: Schema Dump\n"
                    "- list marker\n"
                    "This is prose text with spaces"
                )
            }),
            notes="",
            template="",
            created_at=datetime.utcnow(),
        )
        
        sarif = findings_to_sarif([finding])
        results = sarif["runs"][0]["results"]
        locations = results[0]["locations"]
        
        # Should have no locations (all were malformed)
        assert len(locations) == 0
    
    def test_sarif_export_mixed_valid_and_malformed(self):
        """Test that SARIF export ignores narrative Affected Files, uses evidence_payload only."""
        payload = EvidencePayload(
            schema_version="v1",
            source=EvidenceSource(type="sarif", tool="test"),
            verbatim_text="test",
            locations=[
                EvidenceLocation(file="src/auth/login.py", line=15),
                EvidenceLocation(file="src/auth/session.py"),
                EvidenceLocation(file="lib/crypto.js", line=100)
            ]
        )
        
        finding = Finding(
            id="test-finding-mixed",
            organization_id="org-1",
            report_id="report-1",
            title="Mixed Content",
            content_json=json.dumps({
                "Severity": "Critical",
                "Affected Files": "This prose text is ignored by SARIF export"
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
        
        # Should have exactly 3 valid locations from evidence_payload
        assert len(locations) == 3
        
        uris = [loc["physicalLocation"]["artifactLocation"]["uri"] for loc in locations]
        assert "src/auth/login.py" in uris
        assert "src/auth/session.py" in uris
        assert "lib/crypto.js" in uris


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
