"""Tests for app.services.evidence_structurer (structure_from_evidence, Raw HTTP injection)."""
from unittest.mock import patch

import pytest

from app.services.evidence_schema import (
    EvidencePayload,
    EvidenceSource,
    EvidenceLocation,
)
from app.services.evidence_structurer import structure_from_evidence


# Minimal template that includes Raw HTTP Request / Raw HTTP Response table (second table)
TEMPLATE_WITH_RAW_TABLE = """
<b>Vulnerability Summary</b>
<b>Severity</b>
<b>Justification</b>
<table><tr><td>Severity</td><td>x</td></tr><tr><td>Affected Files</td><td>y</td></tr></table>
<b>Rationale</b>
<table class="raw_code">
<tr><td>Raw HTTP Request</td><td><pre><code></code></pre></td></tr>
<tr><td>Raw HTTP Response</td><td><pre><code></code></pre></td></tr>
</table>
"""


class TestRawHttpRequestResponseInjection:
    """Raw HTTP Request/Response from Burp (evidence artifacts) are injected as system-owned fields."""

    @pytest.fixture
    def evidence_with_http_artifacts(self):
        payload = EvidencePayload(
            schema_version="v1",
            source=EvidenceSource(type="burp_xml", tool="Burp Suite", rule_id="x"),
            verbatim_text="Test finding",
            locations=[],
            artifacts={
                "http_request": "POST /api/login HTTP/1.1\r\nHost: api.example.com\r\n\r\nuser=admin",
                "http_response": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nWelcome",
            },
        )
        return {
            "rule_id": "x",
            "tool": "Burp Suite",
            "title": "Test",
            "description": "Desc",
            "remediation": "Fix it",
            "locations": [],
            "source_type": "burp_xml",
            "_payload_object": payload,
        }

    @patch("app.services.llm.is_llm_available", return_value=True)
    @patch("app.services.llm.chat_completion")
    def test_injects_raw_http_request_and_response_from_artifacts(
        self, mock_chat, _mock_available, evidence_with_http_artifacts
    ):
        # LLM returns minimal valid output (no Raw HTTP keys - they are system-owned)
        mock_chat.return_value = """{
            "Vulnerability Summary": "A summary.",
            "Severity": "Medium",
            "Justification": "Because.",
            "Rationale": "Rationale."
        }"""
        structured, _ = structure_from_evidence(
            notes="",
            evidence=evidence_with_http_artifacts,
            template_markdown=TEMPLATE_WITH_RAW_TABLE,
        )
        assert structured.get("Raw HTTP Request") == (
            "POST /api/login HTTP/1.1\r\nHost: api.example.com\r\n\r\nuser=admin"
        )
        assert structured.get("Raw HTTP Response") == (
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nWelcome"
        )

    @patch("app.services.llm.is_llm_available", return_value=True)
    @patch("app.services.llm.chat_completion")
    def test_no_injection_when_artifacts_empty(self, mock_chat, _mock_available):
        payload = EvidencePayload(
            schema_version="v1",
            source=EvidenceSource(type="burp_xml", tool="Burp Suite"),
            verbatim_text="Test",
            locations=[],
            artifacts={"http_request": "", "http_response": ""},
        )
        evidence = {
            "rule_id": "x",
            "tool": "Burp",
            "title": "T",
            "description": "D",
            "remediation": "R",
            "locations": [],
            "source_type": "burp_xml",
            "_payload_object": payload,
        }
        mock_chat.return_value = '{"Vulnerability Summary": "S", "Severity": "Low", "Justification": "J", "Rationale": "R"}'
        structured, _ = structure_from_evidence(
            notes="",
            evidence=evidence,
            template_markdown=TEMPLATE_WITH_RAW_TABLE,
        )
        # Empty artifacts: do not overwrite with empty string (we only set when strip() is truthy)
        assert structured.get("Raw HTTP Request") is None or structured.get("Raw HTTP Request") == ""
        assert structured.get("Raw HTTP Response") is None or structured.get("Raw HTTP Response") == ""
