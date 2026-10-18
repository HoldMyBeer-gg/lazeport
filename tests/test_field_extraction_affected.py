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
