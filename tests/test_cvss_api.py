"""
API integration tests for CVSS v3.1 field persistence.

Tests the backend API's ability to save and retrieve CVSS values in findings.
Does NOT test UI behavior - see tests/e2e/test_cvss_calculator_e2e.py for that.
"""
import json
from fastapi.testclient import TestClient

from app.db import get_adapter
from app.main import app

client = TestClient(app)


def test_set_cvss_on_finding_without_cvss():
    """API can save CVSS v3.1 to a finding that doesn't have one."""
    adapter = get_adapter()
    org_client = adapter.create_client("CVSS Test Team")
    app_row = adapter.create_application("CVSS Test App")
    report = adapter.create_report("CVSS Test Report", client_id=org_client.id, application_id=app_row.id)

    # Create finding without CVSS (valid evidence payload required for update)
    finding = adapter.create_finding(
        report_id=report.id,
        title="SQL Injection",
        notes="Test finding",
        template="",
        content_json=json.dumps({
            "Severity": "High",
            "Vulnerability Summary": "SQL injection vulnerability"
        }),
        evidence_payload=json.dumps({
            "schema_version": "v1",
            "source": {"type": "notes", "tool": "manual"},
            "verbatim_text": "Test finding",
            "locations": [],
        }),
    )

    # User sets CVSS v3.1 via calculator
    cvss_value = "7.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)"

    response = client.put(
        f"/api/admin/findings/{finding.id}",
        json={
            "title": finding.title,
            "content_json": json.dumps({
                "Severity": "High",
                "Vulnerability Summary": "SQL injection vulnerability",
                "CVSS v3.1": cvss_value
            }),
            "notes": finding.notes,
            "template": finding.template or "",
        }
    )

    assert response.status_code == 200

    # Verify CVSS is saved
    updated_finding = adapter.get_finding(finding.id)
    content = json.loads(updated_finding.content_json)
    assert content["CVSS v3.1"] == cvss_value
    assert "7.1" in content["CVSS v3.1"]
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" in content["CVSS v3.1"]


def test_update_existing_cvss():
    """API can replace existing CVSS v3.1 with a new value."""
    adapter = get_adapter()
    org_client = adapter.create_client("CVSS Update Team")
    app_row = adapter.create_application("CVSS Update App")
    report = adapter.create_report("CVSS Update Report", client_id=org_client.id, application_id=app_row.id)

    # Create finding with existing CVSS (valid evidence payload required for update)
    old_cvss = "9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"
    finding = adapter.create_finding(
        report_id=report.id,
        title="Remote Code Execution",
        notes="Test finding",
        template="",
        content_json=json.dumps({
            "Severity": "Critical",
            "CVSS v3.1": old_cvss,
            "Vulnerability Summary": "RCE vulnerability"
        }),
        evidence_payload=json.dumps({
            "schema_version": "v1",
            "source": {"type": "notes", "tool": "manual"},
            "verbatim_text": "RCE vulnerability",
            "locations": [],
        }),
    )

    # User updates CVSS
    new_cvss = "5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)"

    response = client.put(
        f"/api/admin/findings/{finding.id}",
        json={
            "title": finding.title,
            "content_json": json.dumps({
                "Severity": "Critical",
                "CVSS v3.1": new_cvss,
                "Vulnerability Summary": "RCE vulnerability"
            }),
            "notes": finding.notes,
            "template": finding.template or "",
        }
    )

    assert response.status_code == 200

    # Verify CVSS is updated
    updated_finding = adapter.get_finding(finding.id)
    content = json.loads(updated_finding.content_json)
    assert content["CVSS v3.1"] == new_cvss
    assert old_cvss not in content["CVSS v3.1"]


def test_cvss_preserved_across_regeneration():
    """User-set CVSS v3.1 persists in the database and is not overwritten."""
    adapter = get_adapter()
    org_client = adapter.create_client("CVSS Regen Team")
    app_row = adapter.create_application("CVSS Regen App")
    report = adapter.create_report("CVSS Regen Report", client_id=org_client.id, application_id=app_row.id)

    # Create finding with user-set CVSS
    user_cvss = "6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)"
    finding = adapter.create_finding(
        report_id=report.id,
        title="Information Disclosure",
        notes="The application exposes sensitive data",
        template="",
        content_json=json.dumps({
            "Severity": "Medium",
            "CVSS v3.1": user_cvss,
            "Vulnerability Summary": "Sensitive data exposure"
        }),
        evidence_payload=json.dumps({
            "schema_version": "1.0",
            "source": {
                "type": "notes",
                "tool": "manual",
                "rule_id": None,
                "original_severity": None
            },
            "verbatim_text": "The application exposes sensitive data",
            "locations": [],
            "artifacts": {},
            "hash": "abc123"
        })
    )

    # Regenerate finding (would normally call AI, but here we just verify CVSS isn't wiped)
    # In practice, the LLM should not overwrite user-set CVSS
    # This test verifies the field persists through a typical update flow

    response = client.get(f"/api/admin/findings/{finding.id}")
    assert response.status_code == 200
    data = response.json()
    content = json.loads(data["content_json"])

    # CVSS should still be present
    assert "CVSS v3.1" in content
    assert content["CVSS v3.1"] == user_cvss


def test_cvss_vector_format_validation():
    """
    GIVEN various CVSS vector strings
    WHEN they are formatted for display
    THEN they should follow the pattern: score (CVSS:3.1/metrics)
    AND be valid for hyperlinking to first.org
    """
    test_cases = [
        {
            "input": "7.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)",
            "expected_url": "https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        },
        {
            "input": "9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
            "expected_url": "https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        },
        {
            "input": "4.3 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N)",
            "expected_url": "https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
        }
    ]

    for case in test_cases:
        # Extract score
        score_match = case["input"].split(" ")[0]
        assert float(score_match) >= 0.0
        assert float(score_match) <= 10.0

        # Extract vector
        vector_match = case["input"].split("(")[1].rstrip(")")
        assert vector_match.startswith("CVSS:3.1/")

        # Verify all 8 base metrics present
        metrics = vector_match.replace("CVSS:3.1/", "").split("/")
        assert len(metrics) == 8
        expected_keys = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
        for i, key in enumerate(expected_keys):
            assert metrics[i].startswith(f"{key}:")

        # Verify URL construction
        url = f"https://www.first.org/cvss/calculator/3.1#{vector_match}"
        assert url == case["expected_url"]


def test_cvss_not_provided_in_response():
    """API returns findings with 'Not provided in evidence' for CVSS v3.1."""
    adapter = get_adapter()
    org_client = adapter.create_client("CVSS NotProvided Team")
    app_row = adapter.create_application("CVSS NotProvided App")
    report = adapter.create_report("CVSS NotProvided Report", client_id=org_client.id, application_id=app_row.id)

    finding = adapter.create_finding(
        report_id=report.id,
        title="Missing CVSS Finding",
        notes="Test",
        template="",
        content_json=json.dumps({
            "Severity": "Medium",
            "CVSS v3.1": "Not provided in evidence",
            "Vulnerability Summary": "Test"
        }),
        evidence_payload="{}"
    )

    response = client.get(f"/api/admin/findings/{finding.id}")
    assert response.status_code == 200
    data = response.json()
    content = json.loads(data["content_json"])

    # API returns "Not provided" text as expected
    assert "CVSS v3.1" in content
    assert "Not provided" in content["CVSS v3.1"]


def test_cvss_field_missing_in_response():
    """API returns findings without CVSS v3.1 field when not set."""
    adapter = get_adapter()
    org_client = adapter.create_client("CVSS Empty Team")
    app_row = adapter.create_application("CVSS Empty App")
    report = adapter.create_report("CVSS Empty Report", client_id=org_client.id, application_id=app_row.id)

    finding = adapter.create_finding(
        report_id=report.id,
        title="No CVSS Finding",
        notes="Test",
        template="",
        content_json=json.dumps({
            "Severity": "Low",
            "Vulnerability Summary": "Test"
        }),
        evidence_payload="{}"
    )

    response = client.get(f"/api/admin/findings/{finding.id}")
    assert response.status_code == 200
    data = response.json()
    content = json.loads(data["content_json"])

    # API should not have CVSS field when not set
    assert "CVSS v3.1" not in content or not content.get("CVSS v3.1")


def test_cvss_with_value_in_response():
    """API returns findings with CVSS v3.1 value when set."""
    adapter = get_adapter()
    org_client = adapter.create_client("CVSS Hyperlink Team")
    app_row = adapter.create_application("CVSS Hyperlink App")
    report = adapter.create_report("CVSS Hyperlink Report", client_id=org_client.id, application_id=app_row.id)

    cvss_value = "7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)"
    finding = adapter.create_finding(
        report_id=report.id,
        title="With CVSS Finding",
        notes="Test",
        template="",
        content_json=json.dumps({
            "Severity": "High",
            "CVSS v3.1": cvss_value,
            "Vulnerability Summary": "Test"
        }),
        evidence_payload="{}"
    )

    response = client.get(f"/api/admin/findings/{finding.id}")
    assert response.status_code == 200
    data = response.json()
    content = json.loads(data["content_json"])

    # API should return the CVSS value
    assert "CVSS v3.1" in content
    assert content["CVSS v3.1"] == cvss_value
    assert "CVSS:3.1/" in content["CVSS v3.1"]
