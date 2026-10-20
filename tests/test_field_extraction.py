"""Tests for app.services.field_extraction.derive_table_values: Affected Roles/Users defaults."""
from app.services.field_extraction import derive_table_values


def test_missing_affected_uses_placeholder():
    values = derive_table_values({"Severity": "High"}, notes="")
    assert values["Affected Roles"] == "Not provided in evidence"
    assert values["Affected Users"] == "Not provided in evidence"


def test_stated_affected_roles_kept():
    values = derive_table_values({"Severity": "High", "Affected Roles": "Admins"}, notes="")
    assert values["Affected Roles"] == "Admins"
    assert values["Affected Users"] == "Admins"


def test_override_wins():
    values = derive_table_values({}, notes="", overrides={"Affected Roles": "Guests"})
    assert values["Affected Roles"] == "Guests"


# CVSS v3.1: never invent a score or vector (see structurer prompt: "do NOT infer CVSS").

def test_missing_cvss_uses_placeholder_not_default_vector():
    values = derive_table_values({"Severity": "High", "Details": "SQL injection in login form."}, notes="")
    assert values["CVSS v3.1"] == "Not provided in evidence"
    assert "AV:N" not in values["CVSS v3.1"]


def test_cvss_score_and_vector_in_evidence_are_combined():
    notes = "CVSS 8.1 CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
    values = derive_table_values({"Severity": "High"}, notes=notes)
    assert values["CVSS v3.1"] == "8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)"


def test_shorthand_vector_gets_prefix():
    notes = "Score 5.3, vector AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    values = derive_table_values({}, notes=notes)
    assert values["CVSS v3.1"] == "5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)"


def test_stated_cvss_without_vector_kept_verbatim():
    values = derive_table_values({"Severity": "High", "CVSS v3.1": "7.5"}, notes="")
    assert values["CVSS v3.1"] == "7.5"


def test_cvss_override_wins():
    values = derive_table_values({}, notes="", overrides={"CVSS v3.1": "9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"})
    assert values["CVSS v3.1"].startswith("9.8")
