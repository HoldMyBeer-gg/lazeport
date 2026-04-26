"""
SARIF (Static Analysis Results Interchange Format) export for findings.

Produces valid SARIF v2.1.0 JSON from the internal finding model.
"""
import json
import re
from typing import Any, Dict, List

from app.db import models

SARIF_SCHEMA = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"
SARIF_VERSION = "2.1.0"

# Strip HTML tags that may leak from Burp's original issue descriptions
_HTML_TAG_RE = re.compile(r"<[^>]+>")

# Keys whose values represent prose content worth including in the SARIF message
_PROSE_KEYS = [
    "Vulnerability Summary", "Summary", "Description",
    "Root Cause", "Details", "Impact", "Evidence",
    "Remediation", "References",
]

# Fallback lowercase variants if the structured keys above aren't present
_PROSE_KEYS_LOWER = {k.lower().replace(" ", "_") for k in _PROSE_KEYS}

# Keys that provide location hints (URL, host, endpoint)
_LOCATION_KEYS = ["URL", "Host", "Target", "Location", "Endpoint", "Affected URL"]


def _strip_html(text: str) -> str:
    """Remove HTML tags and collapse whitespace, returning plain text."""
    text = _HTML_TAG_RE.sub("", text)
    # Collapse runs of whitespace (but keep single newlines)
    text = re.sub(r"[ \t]+", " ", text)
    return text.strip()


def _to_plain(value: Any) -> str:
    """Coerce a value to a clean plain-text string for SARIF."""
    s = str(value) if value else ""
    return _strip_html(s)


def _looks_like_file_path(line: str) -> bool:
    r"""
    STRICT validation: Check if a line is a valid file path.
    
    Uses explicit allow-list patterns to prevent JSON blobs from sneaking through.
    
    Rejects any line containing JSON-related characters or patterns.
    Accepts only lines matching specific file path patterns.
    
    Returns True for patterns like:
    - app/Main.kt
    - src/crypto/hash.py:42
    - C:\repo\app\Main.kt:47
    - ../lib/utils.js
    - config.yaml
    """
    line = line.strip()
    if not line:
        return False
    
    # HARD REJECT: JSON-related characters and patterns
    # These should NEVER appear in legitimate file paths
    json_indicators = [
        '{', '}',           # JSON object syntax
        '": "',             # JSON key-value separator
        '"title"',          # Common JSON keys
        '"Vulnerability',
        '"severity"',
        '"impact"',
        '\\n',              # Escaped newline (JSON string)
        '\\u',              # Unicode escape (JSON string)
        'PK\x03\x04',       # ZIP file header
    ]
    
    for indicator in json_indicators:
        if indicator in line:
            return False
    
    # Reject if starts with quote (JSON string)
    if line.startswith('"'):
        return False
    
    # Reject schema keywords at start
    schema_prefixes = [
        'Title:', 'Root Cause:', 'Remediation:', 'Vulnerability Summary:',
        'Attack Vector:', 'Impact:', 'Justification:', 'Severity:', 'Description:',
        'Summary:', 'Details:', 'Evidence:', 'References:',
    ]
    for prefix in schema_prefixes:
        if line.startswith(prefix):
            return False
    
    # Reject list markers
    if line.startswith(('-', '*', '•', '·', '+')):
        return False
    
    # PATTERN 1: Unix-like paths (absolute or relative)
    # Examples: app/Main.kt, src/crypto/hash.py:42, ./config.yaml, ../lib/utils.js
    # Pattern: alphanumeric/dots/dashes/underscores, then MUST have at least one slash, optional :digits
    # Single-component paths without slashes are handled by PATTERN 3 (requires extension)
    unix_pattern = r'^\.{0,2}/?[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+(?::\d+)?$'
    if re.match(unix_pattern, line):
        return True
    
    # PATTERN 2: Windows paths
    # Examples: C:\repo\app\Main.kt:47, D:\Projects\src\file.py
    # Pattern: drive letter, colon, backslash, then valid Windows path components
    # Windows disallows: \ / : * ? " < > |
    windows_pattern = r'^[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]+(?::\d+)?$'
    if re.match(windows_pattern, line):
        return True
    
    # PATTERN 3: Simple filename with extension (no directory)
    # Examples: config.yaml, README.md, app.py:10
    # Must have extension and be reasonably short to avoid prose
    simple_file_pattern = r'^[A-Za-z0-9._-]{1,64}\.[A-Za-z0-9]{1,8}(?::\d+)?$'
    if re.match(simple_file_pattern, line):
        return True
    
    # If none of the patterns match, reject
    return False


def map_severity_to_sarif_level(severity: str) -> str:
    """Map an internal severity string to a SARIF level."""
    sev = severity.strip().lower()
    # Normalize Burp's "information" to "informational"
    if sev == "information":
        sev = "informational"
    if sev in ("critical", "high"):
        return "error"
    if sev == "medium":
        return "warning"
    if sev in ("low", "informational"):
        return "note"
    return "none"


def findings_to_sarif(
    findings: List[models.Finding],
    report_name: str = "Lazeport Export",
) -> Dict[str, Any]:
    """Convert a list of findings to SARIF v2.1.0 JSON."""
    results: list[dict] = []
    rules: list[dict] = []
    rule_ids: set[str] = set()

    for finding in findings:
        try:
            content: dict = json.loads(finding.content_json)
        except (json.JSONDecodeError, TypeError):
            content = {}

        # ── Severity ─────────────────────────────────────────────────
        severity = "Informational"
        for k, v in content.items():
            if k.lower() in ("severity", "risk level"):
                severity = str(v)
                break
        level = map_severity_to_sarif_level(severity)

        # ── Rule (one per unique finding) ────────────────────────────
        rule_id = f"LAZE_{finding.id[:8]}"

        if rule_id not in rule_ids:
            title = _to_plain(finding.title) or "Vulnerability Finding"

            # Pick the best description for the rule
            description = title
            for k in ("Vulnerability Summary", "Summary", "Description", "vulnerability_summary"):
                if k in content and content[k]:
                    description = _to_plain(content[k])
                    break

            rules.append({
                "id": rule_id,
                "shortDescription": {"text": title},
                "fullDescription": {"text": description},
            })
            rule_ids.add(rule_id)

        # ── Message body ─────────────────────────────────────────────
        message_parts: list[str] = []
        if finding.title:
            message_parts.append(f"Title: {_to_plain(finding.title)}")

        # Include structured prose sections
        found_body = False
        for k in _PROSE_KEYS:
            val = content.get(k)
            if val:
                message_parts.append(f"{k}: {_to_plain(val)}")
                found_body = True

        # Fallback: try lowercase/underscore variants
        if not found_body:
            for k, v in content.items():
                if k.lower().replace(" ", "_") in _PROSE_KEYS_LOWER and v:
                    message_parts.append(f"{k}: {_to_plain(v)}")

        # Include validation guidance if present (stored as a separate DB field)
        if finding.validation_guidance and finding.validation_guidance.strip():
            message_parts.append(f"Validation Guidance: {_to_plain(finding.validation_guidance)}")

        # ── Locations ────────────────────────────────────────────────
        locations: list[dict] = []
        
        # AUTHORITATIVE SOURCE: Use evidence_payload.locations (REQUIRED field)
        # This preserves the strict one-way flow: SARIF import → evidence_payload → SARIF export
        # Never parse narrative/content_json fields into locations
        try:
            from app.services.evidence_schema import EvidencePayload
            
            if finding.evidence_payload:
                payload = EvidencePayload.from_json(finding.evidence_payload)
                
                # Use payload.locations as ONLY authoritative source
                for loc in payload.locations:
                    if not loc.file:
                        continue  # Skip if no file path
                    
                    location_obj = {
                        "physicalLocation": {
                            "artifactLocation": {"uri": loc.file}
                        }
                    }
                    
                    # Add line number and snippet if present (MED-30 fix)
                    if loc.line or loc.snippet:
                        region = {}
                        if loc.line:
                            region["startLine"] = loc.line
                        if loc.snippet:
                            region["snippet"] = {"text": loc.snippet}
                        location_obj["physicalLocation"]["region"] = region
                    
                    locations.append(location_obj)
            # else: finding.evidence_payload missing → locations=[] (deterministic behavior)
        except Exception as e:
            # If payload parsing fails, locations=[] (deterministic behavior, log error)
            import logging
            log = logging.getLogger(__name__)
            log.error(f"Failed to parse evidence_payload for finding {finding.id}: {e}")
        
        # NO FALLBACK: If evidence_payload is missing or invalid, locations=[]
        # This allows batch export to continue but logs errors for visibility

        # Embed structured content so a Lazeport re-import skips LLM generation.
        # Stored under a namespaced key so external SARIF consumers can ignore it.
        result_properties: dict = {}
        if finding.content_json:
            result_properties["lazeport_content"] = finding.content_json
        if finding.validation_guidance and finding.validation_guidance.strip():
            result_properties["lazeport_validation_guidance"] = finding.validation_guidance.strip()

        result: dict = {
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": "\n".join(message_parts) if message_parts else "No details available",
            },
            "locations": locations,
        }
        if result_properties:
            result["properties"] = result_properties
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Lazeport",
                        "informationUri": "https://github.com/lazeport/lazeport",
                        "version": "1.0.0",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
