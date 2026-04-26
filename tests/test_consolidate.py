"""Tests for two-phase consolidate_findings endpoint."""
import json
from unittest.mock import call, patch

import pytest
from fastapi.testclient import TestClient

from app.db import get_adapter
from app.main import app

client = TestClient(app)

LLM_MODULE = "app.services.llm.chat_completion"


def _setup_report_with_findings(n=4, similar_titles=None):
    """Create a client, report, and n findings. Returns (report_id, finding_ids)."""
    adapter = get_adapter()

    org = adapter.create_organization(name="TestOrg", slug="test-org-cons")
    client_obj = adapter.create_client(name="TestClient", organization_id=org.id)
    report = adapter.create_report(
        name="Test Report",
        client_id=client_obj.id,
        organization_id=org.id,
    )

    finding_ids = []
    for i in range(n):
        title = (similar_titles[i] if similar_titles and i < len(similar_titles)
                 else f"Finding {i + 1}")
        f = adapter.create_finding(
            report_id=report.id,
            title=title,
            content_json=json.dumps({
                "Finding Title": title,
                "Severity": "High",
                "Vulnerability Summary": f"Summary for finding {i + 1}",
            }),
            notes="",
            template="",
        )
        finding_ids.append(str(f.id))

    return str(report.id), finding_ids


def _consolidate_payload(report_id):
    return {
        "report_id": report_id,
        "llm_provider": "ollama",
        "llm_model": "llama3",
    }


class TestConsolidatePhase1TitlesOnly:
    """Phase 1 call must contain only IDs and titles — no content_json bodies."""

    def test_phase1_prompt_contains_only_titles(self, monkeypatch):
        pass  # ollama provider needs no API key
        report_id, finding_ids = _setup_report_with_findings(3)

        phase1_ids = [[finding_ids[0], finding_ids[1]]]
        phase2_merged = {
            "Finding Title": "Merged XSS",
            "Severity": "High",
            "Vulnerability Summary": "Combined summary",
            "Justification": "",
            "Rationale": "",
            "Root Cause": "",
            "Details": "",
            "Remediation": "",
            "Additional Notes": "",
            "References": "",
            "CVSS v3.1": "",
            "CWE": "",
            "OWASP": "",
            "Affected Roles": "",
        }

        call_count = 0
        phase1_prompt_captured = None

        def mock_chat_completion(messages, **kwargs):
            nonlocal call_count, phase1_prompt_captured
            call_count += 1
            if call_count == 1:
                # Phase 1
                phase1_prompt_captured = messages[0]["content"]
                return json.dumps(phase1_ids)
            else:
                # Phase 2
                return json.dumps(phase2_merged)

        with patch(LLM_MODULE, side_effect=mock_chat_completion):
            resp = client.post("/api/generate/consolidate",
                               json=_consolidate_payload(report_id))

        assert resp.status_code == 200
        # Phase 1 prompt must NOT contain "content_json" or "Vulnerability Summary"
        assert "content_json" not in phase1_prompt_captured
        assert "Vulnerability Summary" not in phase1_prompt_captured
        # Phase 1 prompt MUST contain the finding IDs
        for fid in finding_ids:
            assert fid in phase1_prompt_captured


class TestConsolidatePhase2PerGroup:
    """One Phase 2 LLM call per group returned by Phase 1."""

    def test_two_groups_two_phase2_calls(self, monkeypatch):
        pass  # ollama provider needs no API key
        report_id, finding_ids = _setup_report_with_findings(4)

        # Phase 1 returns two groups
        phase1_groups = [
            [finding_ids[0], finding_ids[1]],
            [finding_ids[2], finding_ids[3]],
        ]

        def merged_finding(title):
            return {
                "Finding Title": title,
                "Severity": "High",
                "Vulnerability Summary": "Merged",
                "Justification": "",
                "Rationale": "",
                "Root Cause": "",
                "Details": "",
                "Remediation": "",
                "Additional Notes": "",
                "References": "",
                "CVSS v3.1": "",
                "CWE": "",
                "OWASP": "",
                "Affected Roles": "",
            }

        call_count = 0

        def mock_chat_completion(messages, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return json.dumps(phase1_groups)
            return json.dumps(merged_finding(f"Merged {call_count}"))

        with patch(LLM_MODULE, side_effect=mock_chat_completion):
            resp = client.post("/api/generate/consolidate",
                               json=_consolidate_payload(report_id))

        assert resp.status_code == 200
        # 1 phase-1 call + 2 phase-2 calls = 3 total
        assert call_count == 3
        data = resp.json()
        assert data["merged_count"] == 2  # one deleted per group


class TestConsolidateNoGroups:
    """When Phase 1 returns [], skip Phase 2 entirely and return merged_count 0."""

    def test_no_similar_findings(self, monkeypatch):
        pass  # ollama provider needs no API key
        report_id, _ = _setup_report_with_findings(3)

        call_count = 0

        def mock_chat_completion(messages, **kwargs):
            nonlocal call_count
            call_count += 1
            return "[]"

        with patch(LLM_MODULE, side_effect=mock_chat_completion):
            resp = client.post("/api/generate/consolidate",
                               json=_consolidate_payload(report_id))

        assert resp.status_code == 200
        # Only Phase 1 was called — no Phase 2
        assert call_count == 1
        assert resp.json()["merged_count"] == 0


class TestConsolidatePhase1Failure:
    """Phase 1 returning garbage JSON → HTTP 400."""

    def test_phase1_garbage_returns_400(self, monkeypatch):
        pass  # ollama provider needs no API key
        report_id, _ = _setup_report_with_findings(3)

        with patch(LLM_MODULE, return_value="not valid json at all %%%"):
            resp = client.post("/api/generate/consolidate",
                               json=_consolidate_payload(report_id))

        assert resp.status_code == 400
        detail = resp.json()["detail"]
        detail_str = detail if isinstance(detail, str) else str(detail)
        assert "invalid response" in detail_str.lower()

    def test_phase1_non_array_returns_400(self, monkeypatch):
        pass  # ollama provider needs no API key
        report_id, _ = _setup_report_with_findings(3)

        # Returns a dict instead of an array
        with patch(LLM_MODULE, return_value='{"error": "oops"}'):
            resp = client.post("/api/generate/consolidate",
                               json=_consolidate_payload(report_id))

        assert resp.status_code == 400


class TestConsolidatePhase2Failure:
    """Phase 2 failure for one group must not crash the whole operation."""

    def test_bad_group_skipped_others_merged(self, monkeypatch):
        pass  # ollama provider needs no API key
        report_id, finding_ids = _setup_report_with_findings(4)

        phase1_groups = [
            [finding_ids[0], finding_ids[1]],  # will fail phase 2
            [finding_ids[2], finding_ids[3]],  # will succeed
        ]

        good_merged = {
            "Finding Title": "Good Merged",
            "Severity": "Medium",
            "Vulnerability Summary": "Merged ok",
            "Justification": "",
            "Rationale": "",
            "Root Cause": "",
            "Details": "",
            "Remediation": "",
            "Additional Notes": "",
            "References": "",
            "CVSS v3.1": "",
            "CWE": "",
            "OWASP": "",
            "Affected Roles": "",
        }

        call_count = 0

        def mock_chat_completion(messages, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return json.dumps(phase1_groups)
            if call_count == 2:
                # First phase-2 group: return garbage
                return "GARBAGE NOT JSON"
            # Second phase-2 group: return valid merged finding
            return json.dumps(good_merged)

        with patch(LLM_MODULE, side_effect=mock_chat_completion):
            resp = client.post("/api/generate/consolidate",
                               json=_consolidate_payload(report_id))

        assert resp.status_code == 200
        data = resp.json()
        # Only the second group merged successfully (1 finding deleted)
        assert data["merged_count"] == 1
