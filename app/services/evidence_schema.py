"""
Canonical evidence payload schema for all finding sources.

This module provides a unified structure for storing immutable scanner evidence
from any source (SARIF, Burp XML, manual notes, etc.). The payload serves as
the authoritative source of truth for all policy decisions.
"""
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any
from datetime import datetime
import hashlib
import json
import re

EVIDENCE_SCHEMA_VERSION = "v1"


@dataclass
class EvidenceSource:
    """Metadata about where the evidence came from."""
    type: str  # sarif, burp_xml, notes, other
    tool: str  # Semgrep, Burp Suite, Manual, etc.
    rule_id: Optional[str] = None
    original_severity: Optional[str] = None
    imported_at: Optional[str] = None


@dataclass
class EvidenceLocation:
    """File location with optional line number and code snippet."""
    file: str
    line: Optional[int] = None
    snippet: Optional[str] = None


@dataclass
class EvidencePayload:
    """
    Canonical evidence payload structure.
    
    This is the immutable source of truth for all finding evidence.
    Policy decisions (severity clamping, test detection) MUST scan this payload only,
    never the LLM-generated content or editable notes.
    """
    schema_version: str
    source: EvidenceSource
    verbatim_text: str
    locations: List[EvidenceLocation]
    artifacts: Optional[Dict[str, Any]] = None
    hash: Optional[str] = None  # Computed after construction
    
    def compute_hash(self) -> str:
        """Compute FULL 64-char SHA256 hex digest of entire payload (excluding hash field)."""
        payload_dict = asdict(self)
        payload_dict.pop('hash', None)
        canonical = json.dumps(payload_dict, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()  # Full 64 chars, no truncation
    
    def to_json(self) -> str:
        """Serialize to JSON string for DB storage."""
        if not self.hash:
            self.hash = self.compute_hash()
        return json.dumps(asdict(self), sort_keys=True)
    
    @staticmethod
    def from_json(json_str: str) -> 'EvidencePayload':
        """Deserialize from JSON string. Validates structure (LOW-9)."""
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise ValueError(
                f"Evidence payload is invalid JSON: {e}. "
                "The finding may be corrupted. Please regenerate from source or restore from backup."
            ) from e

        if not isinstance(data, dict):
            raise ValueError(
                "Evidence payload must be a JSON object. "
                "The finding may be corrupted. Please regenerate from source."
            )

        # Validate required fields
        for key in ("schema_version", "source", "verbatim_text"):
            if key not in data:
                raise ValueError(
                    f"Evidence payload missing required field '{key}'. "
                    "The finding may be corrupted. Please regenerate from source."
                )

        # LOW-8: Reject incompatible schema versions
        if data.get("schema_version") != EVIDENCE_SCHEMA_VERSION:
            raise ValueError(
                f"Evidence payload schema version '{data.get('schema_version')}' is not supported. "
                f"Expected '{EVIDENCE_SCHEMA_VERSION}'. Please regenerate the finding from source."
            )

        if not isinstance(data["source"], dict):
            raise ValueError(
                "Evidence payload 'source' must be an object. "
                "The finding may be corrupted. Please regenerate from source."
            )
        for key in ("type", "tool"):
            if key not in data["source"]:
                raise ValueError(
                    f"Evidence payload 'source' missing required field '{key}'. "
                    "The finding may be corrupted. Please regenerate from source."
                )

        if not isinstance(data.get("verbatim_text"), str):
            raise ValueError(
                "Evidence payload 'verbatim_text' must be a string. "
                "The finding may be corrupted. Please regenerate from source."
            )

        locations = data.get("locations", [])
        if not isinstance(locations, list):
            raise ValueError(
                "Evidence payload 'locations' must be an array. "
                "The finding may be corrupted. Please regenerate from source."
            )

        try:
            source = EvidenceSource(**data["source"])
        except (TypeError, ValueError) as e:
            raise ValueError(
                f"Evidence payload 'source' has invalid structure: {e}. "
                "The finding may be corrupted. Please regenerate from source."
            ) from e

        loc_objs = []
        for i, loc in enumerate(locations):
            if not isinstance(loc, dict) or "file" not in loc:
                raise ValueError(
                    f"Evidence payload 'locations[{i}]' must be an object with 'file'. "
                    "The finding may be corrupted. Please regenerate from source."
                )
            try:
                loc_objs.append(EvidenceLocation(**loc))
            except (TypeError, ValueError) as e:
                raise ValueError(
                    f"Evidence payload 'locations[{i}]' invalid: {e}. "
                    "The finding may be corrupted. Please regenerate from source."
                ) from e

        artifacts = data.get("artifacts")
        if artifacts is not None and not isinstance(artifacts, dict):
            raise ValueError(
                "Evidence payload 'artifacts' must be an object or null. "
                "The finding may be corrupted. Please regenerate from source."
            )

        return EvidencePayload(
            schema_version=str(data["schema_version"]),
            source=source,
            verbatim_text=data["verbatim_text"],
            locations=loc_objs,
            artifacts=artifacts,
            hash=data.get("hash"),
        )
    
    def verify_integrity(self) -> bool:
        """Verify hash matches current payload."""
        if not self.hash:
            return False
        expected = self.compute_hash()
        return expected == self.hash


def iter_verbatim_text_parts(payload: EvidencePayload) -> List[str]:
    """
    Yield ALL verbatim text parts from payload for policy scanning.
    
    CRITICAL: Policy logic (test detection, internal IP scanning, severity clamp)
    MUST scan all returned parts, not just payload.verbatim_text.
    
    Returns:
        List of text parts to scan (all verbatim, none LLM-generated)
    """
    parts = []
    
    # Primary verbatim text
    if payload.verbatim_text:
        parts.append(payload.verbatim_text)
    
    # Location snippets (scanner-captured code)
    for loc in payload.locations:
        if loc.snippet:
            parts.append(loc.snippet)
    
    # Artifacts (source-specific verbatim blobs)
    if payload.artifacts:
        # HTTP request/response (Burp)
        if payload.artifacts.get("http_request"):
            parts.append(str(payload.artifacts["http_request"]))
        if payload.artifacts.get("http_response"):
            parts.append(str(payload.artifacts["http_response"]))
        
        # Raw SARIF result (serialize to text for scanning)
        if payload.artifacts.get("raw_sarif_result"):
            parts.append(json.dumps(payload.artifacts["raw_sarif_result"], sort_keys=True))
        
        # Burp XML issue
        if payload.artifacts.get("burp_xml_issue"):
            parts.append(str(payload.artifacts["burp_xml_issue"]))
        
        # Any other artifacts (deterministic JSON serialization for non-strings)
        for key, value in payload.artifacts.items():
            if key not in ["http_request", "http_response", "raw_sarif_result", "burp_xml_issue"]:
                if isinstance(value, str):
                    parts.append(value)
                elif value is not None:
                    # Non-string artifacts: deterministically JSON-serialize for text scanning
                    parts.append(json.dumps(value, sort_keys=True))
    
    return parts


def build_payload_from_sarif(
    sarif_result: dict,
    tool_name: str
) -> EvidencePayload:
    """
    Build canonical payload from SARIF result.
    
    CRITICAL: Store raw SARIF result EXACTLY as parsed, unmodified.
    This preserves all scanner data for policy decisions.
    """
    rule_id = sarif_result.get("ruleId", "unknown")
    message = sarif_result.get("message", {}).get("text", "")
    
    # Extract locations (canonical format)
    locations = []
    for loc_data in sarif_result.get("locations", []):
        phys = loc_data.get("physicalLocation", {})
        artifact = phys.get("artifactLocation", {})
        region = phys.get("region", {})
        
        file_path = artifact.get("uri", "")
        if file_path:
            locations.append(EvidenceLocation(
                file=file_path,
                line=region.get("startLine"),
                snippet=region.get("snippet", {}).get("text", "") if region.get("snippet") else None
            ))
    
    return EvidencePayload(
        schema_version=EVIDENCE_SCHEMA_VERSION,
        source=EvidenceSource(
            type="sarif",
            tool=tool_name,
            rule_id=rule_id,
            original_severity=sarif_result.get("level"),
            imported_at=datetime.utcnow().isoformat()
        ),
        verbatim_text=message,
        locations=locations,
        artifacts={"raw_sarif_result": sarif_result}  # Store EXACT parsed result
    )


def build_payload_from_burp(
    issue_dict: dict,
    issue_xml_string: str,
    tool_name: str = "Burp Suite"
) -> EvidencePayload:
    """
    Build canonical payload from Burp XML issue.
    
    CRITICAL: Store raw XML string and verbatim HTTP request/response unmodified.
    """
    # Build verbatim text from issue details
    verbatim_parts = [issue_dict.get("name", "")]
    if issue_dict.get("issueDetail"):
        verbatim_parts.append(issue_dict["issueDetail"])
    if issue_dict.get("issueBackground"):
        verbatim_parts.append(issue_dict["issueBackground"])
    
    verbatim_text = "\n\n".join(filter(None, verbatim_parts))
    
    # Extract location
    locations = []
    host = issue_dict.get("host", "")
    path = issue_dict.get("path", "")
    if host or path:
        locations.append(EvidenceLocation(
            file=f"{host}{path}",
            line=None,
            snippet=None
        ))
    
    return EvidencePayload(
        schema_version=EVIDENCE_SCHEMA_VERSION,
        source=EvidenceSource(
            type="burp_xml",
            tool=tool_name,
            rule_id=issue_dict.get("type"),
            original_severity=issue_dict.get("severity"),
            imported_at=datetime.utcnow().isoformat()
        ),
        verbatim_text=verbatim_text,
        locations=locations,
        artifacts={
            "burp_xml_issue": issue_xml_string,  # Raw XML string, unmodified
            "http_request": issue_dict.get("requestresponse", {}).get("request", ""),
            "http_response": issue_dict.get("requestresponse", {}).get("response", "")
        }
    )


def build_payload_from_csv(
    row: dict,
    tool_name: str = "CSV Import",
) -> EvidencePayload:
    """
    Build canonical payload from a normalized CSV row.

    ``row`` is expected to have canonical keys produced by parse_csv():
    name, severity, description, remediation, url, cwe, cvss, tool.
    Only what's present is used; all fields are optional.
    """
    name = row.get("name", "")
    description = row.get("description", "")
    url = row.get("url", "")
    severity = row.get("severity", "")
    remediation = row.get("remediation", "")
    cwe = row.get("cwe", "")

    verbatim_parts = [p for p in [name, description] if p]
    verbatim_text = "\n\n".join(verbatim_parts)

    locations = []
    if url:
        locations.append(EvidenceLocation(file=url, line=None, snippet=None))

    return EvidencePayload(
        schema_version=EVIDENCE_SCHEMA_VERSION,
        source=EvidenceSource(
            type="csv",
            tool=row.get("tool") or tool_name,
            rule_id=None,
            original_severity=severity or None,
            imported_at=datetime.utcnow().isoformat(),
        ),
        verbatim_text=verbatim_text,
        locations=locations,
        artifacts={"csv_row": row, "remediation": remediation, "cwe": cwe},
    )


def build_payload_from_notes(
    notes: str,
    finding_metadata: dict = None
) -> EvidencePayload:
    """
    Build canonical payload from manual notes.
    Best-effort extraction of locations from notes text.
    """
    # Attempt to extract file paths (deterministic regex)
    locations = _extract_locations_from_text(notes)
    
    return EvidencePayload(
        schema_version=EVIDENCE_SCHEMA_VERSION,
        source=EvidenceSource(
            type="notes",
            tool="Manual",
            rule_id=None,
            original_severity=None,
            imported_at=datetime.utcnow().isoformat()
        ),
        verbatim_text=notes[:50000],  # Cap notes snapshot
        locations=locations,
        artifacts=None
    )


# File-path capture used by the location patterns below. Written as
# "segments joined by separators" with a token-start lookbehind so the regex
# engine cannot start a match mid-token or re-split the same token many ways;
# the previous `[\w/.-]+\.\w+` form backtracked quadratically on long
# dotted tokens in attacker-controlled notes (CodeQL py/polynomial-redos).
_PATH_RE = r'(?<![\w/.-])([/.]*[\w-]+(?:[/.]+[\w-]+)*\.\w+)'
# Upper bound on notes text scanned for locations; anything beyond this is
# not evidence anyone wrote by hand.
MAX_LOCATION_SCAN_CHARS = 200_000


def _extract_locations_from_text(text: str) -> List[EvidenceLocation]:
    """
    Best-effort extraction of file paths from notes text.
    
    Patterns:
    - /path/to/file.ext
    - path/to/file.ext:123
    - src/component.tsx line 45
    - config.yaml (line 10)
    """
    text = (text or "")[:MAX_LOCATION_SCAN_CHARS]
    locations = []
    
    # Pattern 1: file:line
    pattern1 = _PATH_RE + r':(\d+)'
    for match in re.finditer(pattern1, text):
        locations.append(EvidenceLocation(
            file=match.group(1),
            line=int(match.group(2))
        ))
    
    # Pattern 2: file path with line keyword
    pattern2 = _PATH_RE + r'\s+(?:line|ln)\s+(\d+)'
    for match in re.finditer(pattern2, text, re.IGNORECASE):
        locations.append(EvidenceLocation(
            file=match.group(1),
            line=int(match.group(2))
        ))
    
    # Pattern 3: file (line N)
    pattern3 = _PATH_RE + r'\s*\(\s*(?:line|ln)\s+(\d+)\s*\)'
    for match in re.finditer(pattern3, text, re.IGNORECASE):
        locations.append(EvidenceLocation(
            file=match.group(1),
            line=int(match.group(2))
        ))
    
    # Deduplicate
    seen = set()
    unique = []
    for loc in locations:
        key = f"{loc.file}:{loc.line or 0}"
        if key not in seen:
            seen.add(key)
            unique.append(loc)
    
    return unique[:20]  # Cap at 20 locations
