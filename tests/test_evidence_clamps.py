"""Tests for app.services.evidence_clamps."""
from app.services.evidence_clamps import (
    clamp_affected_files,
    clamp_severity_for_test_artifacts,
    clamp_threat_model_phrases,
    classify_artifact_context,
)


def test_clamp_affected_files_sets_from_evidence():
    """clamp_affected_files sets Affected Files from evidence, not LLM."""
    structured = {"Severity": "High", "Summary": "Test"}
    evidence = {"affected_files": ["src/main.py", "src/utils.py"]}
    result = clamp_affected_files(structured, evidence)
    assert result["Affected Files"] == "src/main.py\nsrc/utils.py"
    assert "affected_files_set_from_evidence" in result.get("_clamp_flags", [])


def test_clamp_affected_files_empty_evidence():
    """clamp_affected_files with empty affected_files produces empty string."""
    structured = {"Severity": "Medium"}
    evidence = {"affected_files": []}
    result = clamp_affected_files(structured, evidence)
    assert result["Affected Files"] == ""


def test_classify_artifact_context_jmeter():
    """JMeter .jmx file scores high (is_test=True)."""
    evidence = {
        "locations": [{"file": "LoadTest.jmx", "snippet": ""}],
        "verbatim_text": "",
    }
    result = classify_artifact_context(evidence)
    assert result["is_test"] is True
    assert result["score"] >= 4
    assert any("jmeter" in s.lower() for s in result["signals"])


def test_classify_artifact_context_test_filename():
    """Test filename pattern (e.g. foo_test.py) contributes to score."""
    evidence = {
        "locations": [{"file": "tests/test_auth.py", "snippet": ""}],
        "verbatim_text": "def test_login(): pass",
    }
    result = classify_artifact_context(evidence)
    assert result["score"] >= 2
    assert any("test" in s.lower() or "filename" in s.lower() for s in result["signals"])


def test_classify_artifact_context_non_test():
    """Production file with no test signals is not classified as test."""
    evidence = {
        "locations": [{"file": "src/auth.py", "snippet": "def authenticate(): pass"}],
        "verbatim_text": "authentication logic",
    }
    result = classify_artifact_context(evidence)
    assert result["is_test"] is False
    assert result["score"] < 4


def test_clamp_severity_for_test_artifacts_caps_to_low():
    """Test artifact with High severity gets capped to Low."""
    structured = {"Severity": "High", "Summary": "XSS in test"}
    evidence = {
        "locations": [{"file": "LoadTest.jmx", "snippet": ""}],
        "verbatim_text": "",
    }
    result = clamp_severity_for_test_artifacts(structured, evidence)
    assert result["Severity"] == "Low"
    assert any("severity_capped" in f for f in result.get("_severity_flags", []))


def test_clamp_severity_for_test_artifacts_non_test_unchanged():
    """Non-test artifact severity is not capped."""
    structured = {"Severity": "Critical", "Summary": "RCE"}
    evidence = {
        "locations": [{"file": "src/main.py", "snippet": ""}],
        "verbatim_text": "",
    }
    result = clamp_severity_for_test_artifacts(structured, evidence)
    assert result["Severity"] == "Critical"
    assert "_severity_flags" not in result or "severity_capped" not in str(result.get("_severity_flags", []))


def test_clamp_threat_model_phrases_without_network_evidence():
    """Phrases like 'remote attacker' are replaced when has_network_evidence is False."""
    structured = {
        "Attack Vector": "A remote attacker can exploit this.",
        "Summary": "Vulnerability",
    }
    evidence = {"has_network_evidence": False}
    result = clamp_threat_model_phrases(structured, evidence)
    assert "remote attacker" not in result["Attack Vector"].lower()
    assert "attacker" in result["Attack Vector"].lower()
    assert any("replaced" in f for f in result.get("_clamp_flags", []))


def test_clamp_threat_model_phrases_with_network_evidence():
    """Phrases are NOT replaced when has_network_evidence is True."""
    structured = {
        "Attack Vector": "A remote attacker can exploit this.",
    }
    evidence = {"has_network_evidence": True}
    result = clamp_threat_model_phrases(structured, evidence)
    assert "remote attacker" in result["Attack Vector"].lower()
