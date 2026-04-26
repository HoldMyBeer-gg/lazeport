"""
Deterministic clamping logic for evidence-based finding generation.

Applies post-LLM corrections to ensure output matches evidence:
- Affected Files: system-owned, always set from evidence
- Severity: clamped to rubric-allowed values
- Test artifacts: severity capped based on multi-signal classification
- Threat model phrases: replaced when network evidence absent
"""

import re
import logging
from typing import Dict, Any, List, Tuple, Optional

log = logging.getLogger(__name__)

# Fixed canonical severity order for test artifact capping
# (Independent of rubric - used for comparison only)
CANONICAL_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]

# Test filename patterns (generic, no folder paths)
TEST_FILENAME_PATTERNS = [
    r'Test\.[^/]+$',           # SomethingTest.java, FooTest.cs
    r'Tests\.[^/]+$',          # IntegrationTests.java
    r'IT\.[^/]+$',             # FooIT.java (integration test)
    r'E2E\.[^/]+$',            # E2E.spec.ts
    r'\.test\.',               # foo.test.js
    r'\.spec\.',               # foo.spec.ts
    r'_test\.[^/]+$',          # foo_test.py
    r'test_[^/]+\.[^/]+$',     # test_foo.py
]

# Test directory patterns (directories that might contain tests)
# Used in combination with filename patterns for detection
TEST_DIRECTORY_PATTERNS = [
    r'/tests?/',               # /test/ or /tests/
    r'/specs?/',               # /spec/ or /specs/
]

# Obvious test-only directories where ALL files are tests
# (e.g., Jest's __tests__/ convention)
OBVIOUS_TEST_ONLY_DIRS = [
    r'/__tests__/',            # Jest test directory
    r'/__mocks__/',            # Jest mocks
    r'/__fixtures__/',         # Test fixtures
]

# Test framework markers
TEST_FRAMEWORK_MARKERS = [
    # Java
    "@Test", "org.junit", "testng", "org.testng",
    # Python
    "pytest", "def test_", "import unittest",
    # JavaScript/TypeScript
    "describe(", "it(", "test(", "expect(", "jest",
    # C#
    "[Test]", "[Fact]", "[Theory]", "NUnit", "xUnit",
    # Ruby
    "RSpec.describe", "describe ", "context ",
    # E2E/Browser
    "cy.", "page.", "browser.", "playwright",
]

# SARIF metadata test keywords
TEST_KEYWORDS = [
    "test", "integration", "e2e", "harness", "example",
    "mock", "sample", "demo", "local", "emulation"
]


def _find_key(structured: dict, key_name: str) -> str | None:
    """
    Find the actual key matching key_name (case-insensitive, trimmed).
    Returns the actual key from structured dict, or None if not found.
    """
    key_name = key_name.strip().lower()
    for k in structured.keys():
        if k.strip().lower() == key_name:
            return k
    return None


def clamp_affected_files(structured: dict, evidence: dict) -> dict:
    """
    SYSTEM-OWNED FIELD: Always set Affected Files from evidence, never from LLM.
    This field is not model-generated and must not be validated as model output.
    
    Args:
        structured: LLM-generated structured dict
        evidence: Evidence dict with affected_files list
        
    Returns:
        Modified structured dict with Affected Files set from evidence
    """
    affected_files_key = _find_key(structured, "Affected Files")
    if not affected_files_key:
        # Create the field if template doesn't have it
        affected_files_key = "Affected Files"
    
    # Format as newline-separated list matching current schema
    # Evidence.affected_files is already deduped and in stable order
    structured[affected_files_key] = "\n".join(
        evidence.get("affected_files", [])
    )
    
    structured["_clamp_flags"] = structured.get("_clamp_flags", [])
    structured["_clamp_flags"].append("affected_files_set_from_evidence")
    return structured


def clamp_severity(structured: dict, severity_rubric, notes: str = "") -> dict:
    """
    Enforce severity is in rubric's allowed_labels.
    Reuse existing _canonicalize_severity + enforce_severity_label logic.
    
    Args:
        structured: LLM-generated structured dict
        severity_rubric: SeverityRubric object with allowed labels
        notes: Original notes (for inference if needed)
        
    Returns:
        Modified structured dict with severity clamped to allowed values
    """
    if not severity_rubric:
        return structured
    
    from app.services.severity_rubric import enforce_severity_label
    return enforce_severity_label(structured, severity_rubric, notes)


def _detect_jmeter(evidence: dict) -> Tuple[bool, Optional[str]]:
    """
    Detect JMeter test artifacts (high confidence, +4 points).
    
    Prefers evidence_payload if available, falls back to legacy evidence dict.
    
    Returns:
        (is_jmeter, signal_name or None)
    """
    from app.services.evidence_schema import iter_verbatim_text_parts
    
    # Try new evidence_payload method
    payload = evidence.get("_payload_object")
    if payload:
        # Check filenames in locations
        for loc in payload.locations:
            file = loc.file
            if file.lower().endswith(".jmx"):
                return True, "jmeter_jmx_file"
        
        # Check tool name
        tool = payload.source.tool.lower()
        if "jmeter" in tool:
            return True, "jmeter_tool"
        
        # Check ALL verbatim content for JMeter XML root
        verbatim_parts = iter_verbatim_text_parts(payload)
        combined_text = " ".join(verbatim_parts)
    else:
        # Fallback: scan legacy evidence dict
        combined_text = evidence.get("verbatim_text", "") or evidence.get("raw_tool_output", "")
        for loc in evidence.get("locations", []):
            if loc.get("snippet"):
                combined_text += " " + loc["snippet"]
            file = loc.get("file", "")
            if file.lower().endswith(".jmx"):
                return True, "jmeter_jmx_file"
        
        tool = (evidence.get("tool") or "").lower()
        if "jmeter" in tool:
            return True, "jmeter_tool"
    
    if "<jmeterTestPlan" in combined_text or "jMeterTestPlan" in combined_text:
        return True, "jmeter_xml_content"
    
    return False, None


def _detect_test_filename(evidence: dict) -> Tuple[bool, Optional[str]]:
    """
    Detect test files by filename and directory patterns (+2 points).
    
    Detection logic:
    1. Obvious test-only directories (e.g., __tests__/) → Always flag
    2. Test directory + test filename → Flag
    3. Test filename alone → Flag
    4. Test directory without test filename → Don't flag (might be prod code)
    
    Returns:
        (is_test_file, signal_name or None)
    """
    for loc in evidence.get("locations", []):
        file = loc.get("file", "")
        if not file:
            continue
        
        # Check for obvious test-only directories (e.g., __tests__/)
        for pattern in OBVIOUS_TEST_ONLY_DIRS:
            if re.search(pattern, file):
                return True, f"test_dir_{file.split('/')[-1]}"
        
        # Extract basename for filename pattern matching
        basename = file.split("/")[-1]
        has_test_filename = False
        
        for pattern in TEST_FILENAME_PATTERNS:
            if re.search(pattern, basename, re.IGNORECASE):
                has_test_filename = True
                break
        
        if has_test_filename:
            # Check if also in a test directory (stronger signal)
            for dir_pattern in TEST_DIRECTORY_PATTERNS:
                if re.search(dir_pattern, file, re.IGNORECASE):
                    return True, f"test_dir_and_file_{basename}"
            # Test filename alone is enough
            return True, f"filename_{basename}"
    
    return False, None


def _detect_test_content(evidence: dict) -> Tuple[bool, List[str]]:
    """
    Detect test framework markers in verbatim content (+2 points).
    
    Prefers evidence_payload if available, falls back to legacy evidence dict.
    
    Returns:
        (has_markers, list of matched markers)
    """
    from app.services.evidence_schema import iter_verbatim_text_parts
    
    # Try new evidence_payload method
    payload = evidence.get("_payload_object")
    if payload:
        # Scan ALL verbatim parts
        verbatim_parts = iter_verbatim_text_parts(payload)
        combined_text = " ".join(verbatim_parts)
    else:
        # Fallback: scan legacy evidence dict
        combined_text = evidence.get("verbatim_text", "") or evidence.get("raw_tool_output", "")
        for loc in evidence.get("locations", []):
            if loc.get("snippet"):
                combined_text += " " + loc["snippet"]
    
    matched = []
    for marker in TEST_FRAMEWORK_MARKERS:
        if marker in combined_text:
            matched.append(marker)
    
    return len(matched) > 0, matched


def _detect_test_metadata(evidence: dict) -> Tuple[bool, List[str]]:
    """
    Detect test-related keywords in SARIF metadata (+1 point).
    
    Only scans verbatim scanner metadata (rule_id, title).
    Does NOT scan LLM-authored fields (description, remediation).
    
    Returns:
        (has_keywords, list of matched keywords)
    """
    # Scan only verbatim scanner metadata
    text_to_scan = " ".join([
        evidence.get("rule_id", ""),
        evidence.get("title", ""),
    ]).lower()
    
    matched = []
    for keyword in TEST_KEYWORDS:
        if keyword in text_to_scan:
            matched.append(keyword)
    
    return len(matched) > 0, matched


def _detect_internal_destinations(evidence: dict) -> Tuple[List[str], bool]:
    """
    Detect RFC1918, localhost, link-local IPs in ALL verbatim evidence parts.
    
    CRITICAL: Scans ALL verbatim blobs via iter_verbatim_text_parts().
    Does NOT scan LLM-authored fields (evidence dict doesn't include those).
    
    Prefers evidence_payload if available, falls back to legacy evidence dict.
    
    Returns:
        (matched_internal_labels, found_any_internal)
    """
    from app.services.evidence_schema import iter_verbatim_text_parts
    
    internal_patterns = {
        r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b': 'RFC1918_10',
        r'\b192\.168\.\d{1,3}\.\d{1,3}\b': 'RFC1918_192.168',
        r'\b172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b': 'RFC1918_172.16',
        r'\b127\.0\.0\.1\b': 'loopback',
        r'\blocalhost\b': 'localhost',
        r'\b169\.254\.\d{1,3}\.\d{1,3}\b': 'link_local',
    }
    
    # Try new evidence_payload method
    payload = evidence.get("_payload_object")
    if payload:
        # Scan ALL verbatim parts
        verbatim_parts = iter_verbatim_text_parts(payload)
        text_to_scan = " ".join(verbatim_parts)
    else:
        # Fallback: scan legacy evidence dict
        text_to_scan = evidence.get("verbatim_text", "") or evidence.get("raw_tool_output", "")
        for loc in evidence.get("locations", []):
            if loc.get("snippet"):
                text_to_scan += " " + loc["snippet"]
    
    # Find internal destinations
    matched = []
    for pattern, label in internal_patterns.items():
        if re.search(pattern, text_to_scan, re.IGNORECASE):
            if label not in matched:
                matched.append(label)
    
    return matched, len(matched) > 0


def _detect_external_destinations(evidence: dict) -> bool:
    """
    Detect external (non-private) destinations in ALL verbatim evidence parts.
    
    Prefers evidence_payload if available, falls back to legacy evidence dict.
    
    Returns True if any external URL or non-RFC1918 IP found.
    """
    from app.services.evidence_schema import iter_verbatim_text_parts
    
    # Try new evidence_payload method
    payload = evidence.get("_payload_object")
    if payload:
        # Scan ALL verbatim parts
        verbatim_parts = iter_verbatim_text_parts(payload)
        text_to_scan = " ".join(verbatim_parts)
    else:
        # Fallback: scan legacy evidence dict
        text_to_scan = evidence.get("verbatim_text", "") or evidence.get("raw_tool_output", "")
        for loc in evidence.get("locations", []):
            if loc.get("snippet"):
                text_to_scan += " " + loc["snippet"]
    
    # External URL patterns (non-localhost, non-private)
    # Match http://example.com but not http://localhost or http://192.168.x.x
    external_url_pattern = r'https?://(?!localhost\b)(?!127\.)(?!10\.)(?!192\.168\.)(?!172\.(1[6-9]|2[0-9]|3[0-1])\.)[\w\.-]+'
    
    # Non-private IP pattern (crude but effective)
    # Match IPs that don't start with private ranges
    non_private_ip_pattern = r'\b(?!10\.)(?!192\.168\.)(?!172\.(1[6-9]|2[0-9]|3[0-1])\.)(?!127\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    
    if re.search(external_url_pattern, text_to_scan, re.IGNORECASE):
        return True
    
    if re.search(non_private_ip_pattern, text_to_scan):
        return True
    
    return False


def classify_artifact_context(evidence: dict) -> Dict[str, Any]:
    """
    Classify evidence as test artifact using multi-signal scoring.
    
    Signals:
    - JMeter/JMX: +4 points (high confidence alone)
    - Test filename: +2 points
    - Test framework markers: +2 points
    - SARIF test keywords: +1 point
    
    Threshold: is_test = True if score >= 4
    
    Args:
        evidence: Evidence dict with locations, raw_tool_output, etc.
        
    Returns:
        {
            "is_test": bool,
            "score": int,
            "signals": list[str],
            "internal_only": bool,
            "internal_dests": list[str]
        }
    """
    score = 0
    signals = []
    
    # Signal A: JMeter/JMX (+4)
    is_jmeter, jmeter_signal = _detect_jmeter(evidence)
    if is_jmeter:
        score += 4
        signals.append(jmeter_signal)
    
    # Signal B: Test filename (+2)
    is_test_file, filename_signal = _detect_test_filename(evidence)
    if is_test_file:
        score += 2
        signals.append(filename_signal)
    
    # Signal C: Test framework markers (+2)
    has_markers, markers = _detect_test_content(evidence)
    if has_markers:
        score += 2
        # Track first few markers only
        for marker in markers[:3]:
            signals.append(f"content_{marker}")
    
    # Signal D: SARIF test keywords (+1)
    has_keywords, keywords = _detect_test_metadata(evidence)
    if has_keywords:
        score += 1
        for keyword in keywords[:2]:
            signals.append(f"sarif_keyword_{keyword}")
    
    # Determine if test artifact (threshold)
    is_test = score >= 4
    
    # Detect internal/external destinations (verbatim fields only)
    internal_dests, has_internal = _detect_internal_destinations(evidence)
    has_external = _detect_external_destinations(evidence)
    
    # internal_only = found internal AND no external
    internal_only = has_internal and not has_external
    
    return {
        "is_test": is_test,
        "score": score,
        "signals": signals,
        "internal_only": internal_only,
        "internal_dests": internal_dests,
    }


def _find_severity_value(structured: dict) -> str:
    """Extract current severity value from structured dict (case-insensitive)."""
    for key in structured.keys():
        if key.strip().lower() == "severity":
            return structured[key]
    return ""


def _set_severity_value(structured: dict, new_value: str):
    """Set severity value in structured dict (case-insensitive key match)."""
    for key in structured.keys():
        if key.strip().lower() == "severity":
            structured[key] = new_value
            return
    # If not found, add it
    structured["Severity"] = new_value


def _severity_index(label: str, order: List[str]) -> int:
    """
    Get index of severity label in order list (lower index = higher severity).
    Returns large number if not found (treats as lowest severity).
    """
    label_cap = label.strip().capitalize()
    for i, allowed in enumerate(order):
        if allowed.capitalize() == label_cap:
            return i
    return 999  # Unknown label treated as lowest


def clamp_severity_for_test_artifacts(
    structured: dict,
    evidence: dict,
    severity_rubric = None
) -> dict:
    """
    Post-LLM safety net: Cap severity for test artifacts.
    
    Policy:
    - Test artifact (score >= 4): max severity = Low
    - Test artifact + internal destinations only: max severity = Informational
    - Non-test artifacts: no cap
    
    This runs AFTER clamp_severity (rubric normalization) and acts as a
    backstop for cases where pre-LLM prompt injection was insufficient.
    
    Args:
        structured: LLM-generated structured dict
        evidence: Evidence dict
        severity_rubric: Optional rubric (not used for ordering, only for validation)
        
    Returns:
        Modified structured dict with severity capped if needed
    """
    classification = classify_artifact_context(evidence)
    
    if not classification["is_test"]:
        return structured  # No cap
    
    # Determine cap level
    if classification["internal_only"]:
        max_severity = "Informational"
        reason = "test_artifact_internal_only"
    else:
        max_severity = "Low"
        reason = "test_artifact"
    
    current_severity = _find_severity_value(structured)
    if not current_severity:
        return structured  # No severity field to cap
    
    # Apply cap if current exceeds max (using fixed canonical order)
    current_idx = _severity_index(current_severity, CANONICAL_SEVERITY_ORDER)
    max_idx = _severity_index(max_severity, CANONICAL_SEVERITY_ORDER)
    
    if current_idx < max_idx:  # Current is higher severity than allowed
        _set_severity_value(structured, max_severity)
        
        # Track all signals and cap decision
        flags = structured.setdefault("_severity_flags", [])
        flags.append(f"severity_capped:{current_severity}->{max_severity}:{reason}")
        
        for signal in classification["signals"]:
            flags.append(f"test_signal:{signal}")
        
        for dest in classification["internal_dests"]:
            flags.append(f"internal_dest:{dest}")
        
        log.info(f"Capped test artifact severity: {current_severity} -> {max_severity} (signals: {classification['signals']})")
    
    return structured


def clamp_threat_model_phrases(structured: dict, evidence: dict) -> dict:
    """
    Deterministic phrase replacement when network evidence is absent.
    
    When evidence.has_network_evidence is False, replace network-related
    attack vector phrases with neutral alternatives.
    
    Args:
        structured: LLM-generated structured dict
        evidence: Evidence dict with has_network_evidence boolean
        
    Returns:
        Modified structured dict with phrases replaced if needed
    """
    if evidence.get("has_network_evidence"):
        return structured  # Allow network-related phrases
    
    # Define disallowed -> allowed mappings for non-network findings
    PHRASE_MAP = {
        r'\bremote attacker\b': 'attacker',
        r'\bunauthenticated attacker\b': 'attacker',
        r'\banonymous attacker\b': 'attacker',
        r'\binternet-facing\b': 'exposed',
        r'\bremotely exploitable\b': 'exploitable',
    }
    
    flags = []
    for key, value in structured.items():
        if key.startswith("_") or not isinstance(value, str):
            continue
        original = value
        for pattern, replacement in PHRASE_MAP.items():
            value, count = re.subn(pattern, replacement, value, flags=re.IGNORECASE)
            if count > 0:
                # Track which phrase was replaced in which field
                pattern_name = pattern.strip('\\b').replace('\\', '')
                flags.append(f"replaced_{pattern_name}_in_{key}")
        if value != original:
            structured[key] = value
    
    if flags:
        structured["_clamp_flags"] = structured.get("_clamp_flags", []) + flags
        log.info(f"Applied threat model phrase clamps: {flags}")
    
    return structured
