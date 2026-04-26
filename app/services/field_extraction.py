"""
Shared field extraction helpers for vulnerability findings.
Used by generate API, Burp import tasks, and vision API.
"""
from __future__ import annotations

import logging
import re
from typing import Dict, Optional

from app.db.adapter import StorageAdapter

log = logging.getLogger(__name__)

# Regexes for extracting CVE/CWE/OWASP/CVSS from text
CVSS_VECTOR_RE = re.compile(
    r"(CVSS:3\.1/[A-Za-z0-9:/]+|AV:[A-Z]/AC:[A-Z]/PR:[A-Z]/UI:[A-Z]/S:[A-Z]/C:[A-Z]/I:[A-Z]/A:[A-Z])"
)
CWE_RE = re.compile(r"\bCWE-\d{1,5}\b", re.IGNORECASE)
OWASP_RE = re.compile(r"\bA\d{1,2}(?::20\d{2})?\b", re.IGNORECASE)
SCORE_RE = re.compile(r"\b([0-9]\.[0-9])\b")
SEVERITY_RE = re.compile(r"\b(Critical|High|Medium|Low|Informational|Information)\b", re.IGNORECASE)

DEFAULT_XSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
SEVERITY_TO_CVSS_SCORE = {
    "Critical": "9.8",
    "High": "7.5",
    "Medium": "5.3",
    "Low": "3.1",
    "Informational": "0.0",
}
DEFAULT_CVSS_SCORE = "6.1"
CANONICAL_SEVERITIES = {"Critical", "High", "Medium", "Low", "Informational"}

def validate_cwe(cwe_str: str) -> str | None:
    """Return the CWE string if it matches CWE-NNN format, else None."""
    m = re.search(r"(\d+)", cwe_str)
    if not m:
        return None
    return cwe_str


def canonicalize_severity_value(value: str) -> str:
    """Canonical backend severity storage value."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    m = SEVERITY_RE.search(raw)
    if not m:
        return "Informational"
    sev = m.group(1).capitalize()
    if sev == "Information":
        sev = "Informational"
    return sev if sev in CANONICAL_SEVERITIES else "Informational"


def derive_table_values(
    structured: Dict[str, str],
    notes: str,
    overrides: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """
    Derive table values (Severity, CWE, OWASP, CVSS, Affected Roles/Users) from structured content and notes.
    overrides: optional dict to override extracted values (e.g. from request params).
    """
    overrides = overrides or {}
    text = "\n".join(str(v) for v in structured.values() if isinstance(v, str)) + "\n" + (notes or "")
    values: Dict[str, str] = {}

    severity = canonicalize_severity_value(str(structured.get("Severity", "")).strip())
    if severity:
        values["Severity"] = severity
    if overrides.get("Severity"):
        values["Severity"] = overrides["Severity"]

    if overrides.get("CWE"):
        values["CWE"] = overrides["CWE"]
    else:
        m = CWE_RE.search(text)
        if m:
            validated = validate_cwe(m.group(0))
            if validated:
                values["CWE"] = validated.upper()

    if overrides.get("OWASP"):
        values["OWASP"] = overrides["OWASP"]
    else:
        m = OWASP_RE.search(text)
        if m:
            values["OWASP"] = m.group(0).upper()

    if overrides.get("CVSS v3.1"):
        values["CVSS v3.1"] = overrides["CVSS v3.1"]
    else:
        score = SCORE_RE.search(text)
        vector = CVSS_VECTOR_RE.search(text)
        if score and vector:
            vec = vector.group(1)
            if not vec.startswith("CVSS:3.1/"):
                vec = f"CVSS:3.1/{vec}"
            values["CVSS v3.1"] = f"{score.group(1)} ({vec})"
        else:
            default_score = SEVERITY_TO_CVSS_SCORE.get(severity.strip()) if severity else DEFAULT_CVSS_SCORE
            if not default_score:
                default_score = DEFAULT_CVSS_SCORE
            values["CVSS v3.1"] = f"{default_score} ({DEFAULT_XSS_VECTOR})"

    affected = structured.get("Affected Roles") or structured.get("Affected Users") or ""
    default_affected = "All Users"
    if overrides.get("Affected Roles"):
        values["Affected Roles"] = overrides["Affected Roles"]
    elif affected:
        values["Affected Roles"] = str(affected).strip()
    else:
        values["Affected Roles"] = default_affected

    if overrides.get("Affected Users"):
        values["Affected Users"] = overrides["Affected Users"]
    elif structured.get("Affected Users"):
        values["Affected Users"] = str(structured.get("Affected Users")).strip()
    elif affected:
        values["Affected Users"] = str(affected).strip()
    else:
        values["Affected Users"] = default_affected

    return values


def user_api_key_for_provider(
    user,
    adapter: StorageAdapter,
    provider_override: str | None,
) -> str | None:
    """
    Return the stored user API key only when it matches the selected provider.
    Prevents cross-provider key use (e.g. DeepSeek key sent to OpenAI).
    """
    effective_provider = str(provider_override or "openai").strip().lower()
    if getattr(adapter, "get_user_provider_api_key", None):
        return adapter.get_user_provider_api_key(user.id, effective_provider)
    key = (
        adapter.get_user_openai_api_key(user.id)
        if getattr(adapter, "get_user_openai_api_key", None)
        else None
    )
    return key if effective_provider == "openai" else None
