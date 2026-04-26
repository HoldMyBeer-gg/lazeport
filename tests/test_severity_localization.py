"""Tests for app.services.severity_localization."""
from app.services.severity_localization import (
    canonicalize_severity,
    localize_severity_label,
)


def test_canonicalize_severity_standard():
    """Standard severities are canonicalized correctly."""
    assert canonicalize_severity("Critical") == "Critical"
    assert canonicalize_severity("High") == "High"
    assert canonicalize_severity("Medium") == "Medium"
    assert canonicalize_severity("Low") == "Low"
    assert canonicalize_severity("Informational") == "Informational"


def test_canonicalize_severity_case_insensitive():
    """Case variations are normalized."""
    assert canonicalize_severity("critical") == "Critical"
    assert canonicalize_severity("HIGH") == "High"
    assert canonicalize_severity("informational") == "Informational"


def test_canonicalize_severity_information_synonym():
    """'Information' is mapped to 'Informational'."""
    assert canonicalize_severity("Information") == "Informational"
    assert canonicalize_severity("information") == "Informational"


def test_canonicalize_severity_empty_or_none():
    """Empty or None returns empty string."""
    assert canonicalize_severity("") == ""
    assert canonicalize_severity(None) == ""
    assert canonicalize_severity("   ") == ""


def test_localize_severity_label_english():
    """English locale returns localized label from frontend i18n."""
    result = localize_severity_label("High", "en")
    assert result != ""
    assert isinstance(result, str)


def test_localize_severity_label_fallback_to_canonical():
    """Unknown locale or missing mapping falls back to canonical."""
    result = localize_severity_label("High", "xx")
    assert result == "High"


def test_localize_severity_label_empty_severity():
    """Empty severity returns empty string."""
    assert localize_severity_label("", "en") == ""
    assert localize_severity_label(None, "en") == ""


def test_localize_severity_label_locale_candidates():
    """Locale with region (e.g. en-US) tries base locale then en."""
    result = localize_severity_label("Critical", "en-US")
    assert result != ""
    assert isinstance(result, str)
