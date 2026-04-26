"""
Tests for CSV import functionality.

Covers parsing, column normalization, severity mapping, merge by title,
evidence_payload generation, and the upload endpoint.
"""
import io
import json
import pytest
from fastapi.testclient import TestClient

from app.api.findings import parse_csv, _merge_csv_by_title, CsvFinding, _normalize_severity


# ── Parser unit tests ──────────────────────────────────────────────────────────

def test_parse_csv_basic():
    """Parse a well-formed CSV with canonical column names."""
    csv_text = (
        "Title,Severity,Description,Remediation,URL,CWE\n"
        "SQL Injection,High,User input not sanitized,Use parameterized queries,https://example.com/login,CWE-89\n"
    )
    findings = parse_csv(csv_text)
    assert len(findings) == 1
    f = findings[0]
    assert f.name == "SQL Injection"
    assert f.severity == "High"
    assert f.description == "User input not sanitized"
    assert f.remediation == "Use parameterized queries"
    assert f.url == "https://example.com/login"
    assert f.cwe == "CWE-89"


def test_parse_csv_flexible_column_names():
    """Accept common column-name variants from different scanners."""
    csv_text = (
        "Vulnerability Name,Risk Level,Details,Solution,Endpoint\n"
        "XSS,Medium,Reflected XSS found,Encode output,/search\n"
    )
    findings = parse_csv(csv_text)
    assert len(findings) == 1
    f = findings[0]
    assert f.name == "XSS"
    assert f.severity == "Medium"
    assert f.description == "Reflected XSS found"
    assert f.remediation == "Encode output"
    assert f.url == "/search"


def test_parse_csv_severity_normalization():
    """Severity variants map to canonical labels."""
    cases = [
        ("critical", "Critical"),
        ("CRITICAL", "Critical"),
        ("High", "High"),
        ("h", "High"),
        ("med", "Medium"),
        ("moderate", "Medium"),
        ("low", "Low"),
        ("l", "Low"),
        ("info", "Informational"),
        ("information", "Informational"),
        ("note", "Informational"),
    ]
    for raw, expected in cases:
        result = _normalize_severity(raw)
        assert result == expected, f"{raw!r} should normalize to {expected!r}, got {result!r}"


def test_parse_csv_skips_blank_name_rows():
    """Rows with empty name are silently skipped."""
    csv_text = (
        "Name,Severity\n"
        "SQL Injection,High\n"
        ",Low\n"
        "XSS,Medium\n"
    )
    findings = parse_csv(csv_text)
    assert len(findings) == 2
    assert findings[0].name == "SQL Injection"
    assert findings[1].name == "XSS"


def test_parse_csv_no_name_column_raises():
    """CSV without any recognizable name column raises 400."""
    from fastapi import HTTPException
    csv_text = "Score,Tool\n9.8,Nessus\n"
    with pytest.raises(HTTPException) as exc:
        parse_csv(csv_text)
    assert exc.value.status_code == 400
    assert "name" in exc.value.detail.lower()


def test_parse_csv_bom_handling():
    """Endpoint strips UTF-8 BOM before passing to parser; parser sees clean CSV."""
    # The endpoint decodes with utf-8-sig, so parse_csv always receives BOM-free text.
    # Simulate what the endpoint delivers to parse_csv after BOM stripping.
    raw_bytes = "\ufeffName,Severity\nSSRF,High\n".encode("utf-8")
    csv_text = raw_bytes.decode("utf-8-sig")  # BOM stripped by utf-8-sig codec
    findings = parse_csv(csv_text)
    assert len(findings) == 1
    assert findings[0].name == "SSRF"


# ── Merge tests ────────────────────────────────────────────────────────────────

def test_merge_csv_by_title_single_row():
    """Single finding merges to one dict with evidence_payload."""
    findings = [CsvFinding(name="XSS", severity="High", url="/page")]
    merged = _merge_csv_by_title(findings)
    assert len(merged) == 1
    m = merged[0]
    assert m["name"] == "XSS"
    assert m["severity"] == "High"
    assert m["csv_source"] is True
    assert "evidence_payload" in m
    # evidence_payload should be valid JSON with expected schema
    ep = json.loads(m["evidence_payload"])
    assert ep["source"]["type"] == "csv"
    assert ep["locations"][0]["file"] == "/page"


def test_merge_csv_by_title_combines_urls():
    """Findings with the same name but different URLs have URLs merged."""
    findings = [
        CsvFinding(name="SQLi", severity="High", url="/login"),
        CsvFinding(name="SQLi", severity="High", url="/search"),
    ]
    merged = _merge_csv_by_title(findings)
    assert len(merged) == 1
    assert "/login" in merged[0]["url"]
    assert "/search" in merged[0]["url"]


def test_merge_csv_by_title_dedupes_same_url():
    """Duplicate URLs for same title are not repeated."""
    findings = [
        CsvFinding(name="SQLi", severity="High", url="/login"),
        CsvFinding(name="SQLi", severity="High", url="/login"),
    ]
    merged = _merge_csv_by_title(findings)
    assert merged[0]["url"].count("/login") == 1


def test_merge_csv_by_title_multiple_unique():
    """Different titles produce separate findings."""
    findings = [
        CsvFinding(name="SQLi", severity="High"),
        CsvFinding(name="XSS", severity="Medium"),
    ]
    merged = _merge_csv_by_title(findings)
    assert len(merged) == 2


# ── Format-as-notes tests ──────────────────────────────────────────────────────

def test_format_finding_as_notes_csv():
    """CSV finding formats into readable notes for the LLM."""
    from app.tasks.burp_import import _format_finding_as_notes
    finding = {
        "name": "SSRF",
        "severity": "High",
        "url": "https://target.com/fetch",
        "cwe": "CWE-918",
        "description": "Server-side request forgery via user-controlled URL.",
        "remediation": "Validate and whitelist allowed URLs.",
        "csv_source": True,
    }
    notes = _format_finding_as_notes(finding)
    assert "SSRF" in notes
    assert "High" in notes
    assert "https://target.com/fetch" in notes
    assert "CWE-918" in notes
    assert "Server-side request forgery" in notes
    assert "Validate and whitelist" in notes


# ── Endpoint tests ─────────────────────────────────────────────────────────────

import os
os.environ.setdefault("AUTH_DISABLED", "1")
from app.main import app

_client = TestClient(app)


def _make_csv_upload(content: str, filename: str = "findings.csv") -> dict:
    return {"file": (filename, io.BytesIO(content.encode()), "text/csv")}


def test_upload_csv_no_report_id():
    """Upload CSV without report_id returns parsed findings list."""
    csv_text = "Name,Severity,Description\nSQL Injection,High,User input not sanitized\n"
    resp = _client.post(
        "/api/admin/findings/upload-csv",
        files=_make_csv_upload(csv_text),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["findings"][0]["name"] == "SQL Injection"


def test_upload_csv_wrong_extension():
    """Non-CSV file extension returns 400."""
    resp = _client.post(
        "/api/admin/findings/upload-csv",
        files={"file": ("scan.xml", io.BytesIO(b"data"), "text/plain")},
    )
    assert resp.status_code == 400


def test_upload_csv_missing_name_column():
    """CSV with no recognizable name column returns 400."""
    csv_text = "Score,CVSS\n9.8,AV:N\n"
    resp = _client.post(
        "/api/admin/findings/upload-csv",
        files=_make_csv_upload(csv_text),
    )
    assert resp.status_code == 400


def test_upload_csv_multiple_findings():
    """Multiple unique findings are all returned."""
    csv_text = (
        "Vulnerability,Severity\n"
        "SQL Injection,High\n"
        "XSS,Medium\n"
        "CSRF,Low\n"
    )
    resp = _client.post(
        "/api/admin/findings/upload-csv",
        files=_make_csv_upload(csv_text),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 3


def test_upload_csv_with_report_id_creates_session():
    """Upload with report_id creates an import session."""
    from app.db import get_adapter

    adapter = get_adapter()
    org = adapter.create_organization(name="CsvTestOrg", slug="csv-test-org")
    client_obj = adapter.create_client(name="CsvClient", organization_id=org.id)
    report = adapter.create_report(
        name="CSV Test Report",
        client_id=client_obj.id,
        organization_id=org.id,
    )

    csv_text = "Name,Severity\nSQL Injection,High\n"
    resp = _client.post(
        f"/api/admin/findings/upload-csv?report_id={report.id}",
        files=_make_csv_upload(csv_text),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "session_id" in data
    assert data["total"] == 1
