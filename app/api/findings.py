import hashlib
import json
import logging
import defusedxml.ElementTree as ET
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, File, UploadFile, Query
from pydantic import BaseModel

log = logging.getLogger(__name__)

from ..db import get_adapter
from ..db.adapter import StorageAdapter
from ..services.auth import get_current_user
from ..db.models import User

router = APIRouter(prefix="/api/admin", tags=["findings"])


def _merge_findings_by_title(findings: List["BurpFinding"]) -> List[dict]:
    """Merge findings by name (title); combine hosts, paths, and issueDetail."""
    by_name: dict[str, dict] = {}
    for f in findings:
        name = f.name or "(unnamed)"
        if name not in by_name:
            by_name[name] = {
                "serialNumber": f.serialNumber,
                "type": f.type,
                "name": f.name,
                "host": f.host,
                "path": f.path,
                "location": f.location,
                "severity": f.severity,
                "confidence": f.confidence,
                "issueBackground": f.issueBackground,
                "remediationBackground": f.remediationBackground,
                "references": f.references,
                "vulnerabilityClassifications": f.vulnerabilityClassifications,
                "issueDetail": f.issueDetail or "",
                "remediationDetail": f.remediationDetail,
            }
        else:
            existing = by_name[name]
            if f.host and f.host not in (existing.get("host") or ""):
                existing["host"] = (existing.get("host") or "") + ", " + f.host
            if f.path and f.path not in (existing.get("path") or ""):
                existing["path"] = (existing.get("path") or "") + "; " + f.path
            if f.issueDetail:
                existing["issueDetail"] = (existing.get("issueDetail") or "") + "\n\n" + f.issueDetail
    return [v for v in by_name.values()]


def _cap_text(text: str, max_chars: int = 20000) -> tuple[str, bool]:
    """
    Cap text to max_chars. Returns (capped_text, was_truncated).
    Prevents DB/JSON bloat and accidental prompt re-injection.
    """
    if not text or len(text) <= max_chars:
        return text or "", False
    return text[:max_chars], True


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    """
    Remove duplicates while preserving first-seen order.
    Ensures deterministic, stable output across runs.
    """
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _has_network_protocol(*texts: str) -> bool:
    """
    Deterministic check: True if any text contains network protocol schemes.
    Only checks for explicit protocols, not broad tokens like 'host'.
    """
    protocols = (b'http://', b'https://', b'ws://', b'wss://')
    for text in texts:
        if not text:
            continue
        text_lower = text.lower().encode('utf-8', errors='ignore')
        if any(proto in text_lower for proto in protocols):
            return True
    return False


def _merge_sarif_by_rule_id(findings: List["SarifFinding"]) -> List[dict]:
    """
    Merge SARIF findings by ruleId; combine locations, line numbers, and code snippets.
    Builds canonical evidence_payload for each merged finding.
    """
    from app.services.evidence_schema import build_payload_from_sarif
    
    by_rule: dict[str, dict] = {}
    
    for f in findings:
        key = f.ruleId or "(unknown)"
        
        if key not in by_rule:
            # First occurrence - create entry
            by_rule[key] = {
                "ruleId": f.ruleId,
                "name": f.name,
                "severity": f.severity,
                "description": f.description,
                "remediation": f.remediation,
                "cwe": f.cwe,
                "tool": f.tool,
                "locations": [],  # Will store list of location dicts
                "metadata": {
                    "originalRuleId": f.ruleId,  # Store original scanner rule ID
                    "originalTool": f.tool,
                    "originalSeverity": f.severity,
                    "originalCategory": f.name,
                },
                "lazeport_content": f.lazeport_content,
                "lazeport_validation_guidance": f.lazeport_validation_guidance,
            }
        
        # Add this occurrence's location info
        if f.location:
            location_entry = {
                "file": f.location,
                "line": f.lineNumber,
                "snippet": f.codeSnippet,
            }
            # Avoid duplicate locations
            if location_entry not in by_rule[key]["locations"]:
                by_rule[key]["locations"].append(location_entry)
    
    # Post-merge: build canonical evidence_payload for each finding
    for finding in by_rule.values():
        # Format notes from finding data
        try:
            from app.tasks.burp_import import _format_finding_as_notes
            notes = _format_finding_as_notes(finding)
        except (ImportError, Exception):
            # Fallback if import fails (e.g., during tests)
            notes = f"Tool: {finding.get('tool', 'Unknown')}\nRule: {finding.get('ruleId', '')}\nVulnerability: {finding.get('name', '')}"
        
        # Build SARIF result object for evidence_payload (EXACT structure for artifacts)
        sarif_result = {
            "ruleId": finding.get("ruleId"),
            "message": {"text": notes},
            "level": finding.get("severity"),
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": loc["file"]},
                        "region": {
                            "startLine": loc.get("line"),
                            "snippet": {"text": loc.get("snippet", "")} if loc.get("snippet") else {}
                        }
                    }
                }
                for loc in finding["locations"]
                if loc.get("file")
            ],
            "properties": {
                "description": finding.get("description") or "",
                "remediation": finding.get("remediation") or "",
                "cwe": finding.get("cwe") or "",
                "name": finding.get("name") or ""
            }
        }
        
        # Build canonical evidence_payload using schema builder
        payload = build_payload_from_sarif(
            sarif_result=sarif_result,
            tool_name=finding.get("tool") or "unknown"
        )
        
        # Store evidence_payload as JSON string (goes to Finding.evidence_payload column)
        finding["evidence_payload"] = payload.to_json()
        
        # NO legacy metadata["evidence"] - removed completely
    
    return [v for v in by_rule.values()]


def _dedupe_by_locations(merged_findings: List[dict]) -> List[dict]:
    """
    Merge findings with identical locations and similar titles.
    
    Prevents double-reporting when scanner emits multiple findings
    for the same issue with slight title variations.
    """
    import re
    from app.services.evidence_schema import EvidencePayload
    
    def normalize_title(title: str) -> str:
        """Lowercase, strip punctuation and whitespace for fuzzy matching."""
        # Remove punctuation, lowercase, then remove ALL whitespace
        return re.sub(r'[^\w]', '', title.lower())
    
    def location_signature(locations: list) -> frozenset:
        """Create hashable signature from file:line pairs."""
        return frozenset(
            (loc.file, loc.line)
            for loc in locations
            if loc.file
        )
    
    seen = {}
    unique = []
    
    for finding in merged_findings:
        # Read from evidence_payload (new architecture)
        evidence_payload_json = finding.get('evidence_payload')
        
        if not evidence_payload_json:
            unique.append(finding)  # Keep findings without evidence_payload
            continue
        
        try:
            payload = EvidencePayload.from_json(evidence_payload_json)
            locations = payload.locations
        except Exception:
            unique.append(finding)  # Keep findings with unparseable payload
            continue
        
        if not locations:
            unique.append(finding)  # Keep findings without locations
            continue
        
        sig = location_signature(locations)
        
        # Use finding.name for title (title is in the finding dict, not evidence)
        title = finding.get('name') or ''
        norm_title = normalize_title(title)
        
        # Check if we've seen similar finding at same locations
        key = (sig, norm_title[:50])  # Match on locations + title prefix
        if key in seen:
            # Duplicate found - merge metadata, keep first
            if 'duplicate_count' not in seen[key]['metadata']:
                seen[key]['metadata']['duplicate_count'] = 1
            seen[key]['metadata']['duplicate_count'] += 1
        else:
            seen[key] = finding
            unique.append(finding)
    
    return unique


def _create_import_session(
    findings_list: List[dict],
    file_name: str,
    content_hash: str,
    report_id: str,
    adapter: StorageAdapter,
) -> dict:
    """Generic helper to create or reuse import session for any scan tool."""
    # Check for existing session with same content
    existing = adapter.get_burp_session_by_report_and_hash(report_id, content_hash)
    if existing:
        import json as _json
        tasks = _json.loads(existing.tasks_json) if existing.tasks_json else []
        # Resumable work includes skipped tasks, so users can explicitly
        # re-open a cancelled session and unskip/regenerate remaining findings.
        actionable = [
            t for t in tasks if t.get("status") in ("pending", "failed", "skipped", "generating")
        ]
        
        # IMPORTANT: Return resumable tasks from DB, not the new findings_list.
        # This reflects actual session state for resume behavior.
        actionable_findings = [t.get("finding") for t in actionable if t.get("finding")]
        
        return {
            "findings": actionable_findings,
            "total": len(actionable_findings),
            "total_tasks": len(tasks),  # Total tasks in session for better messaging
            "completed_count": len([t for t in tasks if t.get("status") == "completed"]),
            "session_id": existing.id,
            "file_name": existing.file_name,
            "already_imported": True,
            "pending_count": len(actionable),
            "message": f"Resuming import: {len(actionable)} findings actionable",
        }

    # Create new session
    tasks = [
        {"index": i, "status": "pending", "finding": f}
        for i, f in enumerate(findings_list)
    ]
    import json as _json

    sess = adapter.create_burp_import_session(
        report_id=report_id,
        content_hash=content_hash,
        file_name=file_name,
        tasks_json=_json.dumps(tasks),
    )
    return {
        "findings": findings_list,
        "total": len(findings_list),
        "session_id": sess.id,
        "file_name": sess.file_name,
        "already_imported": False,
        "message": f"Successfully parsed {len(findings_list)} findings",
    }

class BurpFinding(BaseModel):
    serialNumber: str
    type: str
    name: str
    host: str
    path: str
    location: str
    severity: str
    confidence: str
    issueBackground: Optional[str] = None
    remediationBackground: Optional[str] = None
    references: Optional[str] = None
    vulnerabilityClassifications: Optional[str] = None
    issueDetail: Optional[str] = None
    remediationDetail: Optional[str] = None
    requestresponse: Optional[dict] = None

class SarifFinding(BaseModel):
    """Normalized SARIF finding for import workflow"""
    ruleId: str
    name: str
    severity: str
    description: str
    location: str  # file path or URL
    lineNumber: Optional[int] = None
    codeSnippet: Optional[str] = None
    remediation: Optional[str] = None
    cwe: Optional[str] = None
    tool: Optional[str] = None
    # Present only when re-importing a Lazeport-exported SARIF; skips LLM generation.
    lazeport_content: Optional[str] = None
    lazeport_validation_guidance: Optional[str] = None

class CsvFinding(BaseModel):
    """Normalized finding parsed from a CSV row."""
    name: str
    severity: str
    description: Optional[str] = None
    remediation: Optional[str] = None
    url: Optional[str] = None
    cwe: Optional[str] = None
    cvss: Optional[str] = None
    tool: Optional[str] = None


# Flexible column-name normalizer for CSV imports from various scanners
_CSV_COLUMN_MAP: dict[str, str] = {
    # Title / name
    "title": "name", "name": "name", "vulnerability": "name",
    "vulnerability name": "name", "vulnerability_name": "name",
    "finding": "name", "finding name": "name", "finding_name": "name",
    "issue": "name", "issue name": "name", "issue_name": "name",
    "summary": "name", "plugin name": "name", "plugin_name": "name",
    # Severity / risk
    "severity": "severity", "risk": "severity", "risk level": "severity",
    "risk_level": "severity", "criticality": "severity", "priority": "severity",
    "level": "severity",
    # Description / details
    "description": "description", "details": "description", "detail": "description",
    "body": "description", "synopsis": "description", "output": "description",
    # Remediation
    "remediation": "remediation", "fix": "remediation",
    "recommendation": "remediation", "recommendations": "remediation",
    "solution": "remediation", "resolution": "remediation",
    # Location / URL
    "url": "url", "host": "url", "hostname": "url", "path": "url",
    "location": "url", "endpoint": "url",
    "affected url": "url", "affected_url": "url",
    "target": "url", "ip": "url",
    # CWE
    "cwe": "cwe", "cwe id": "cwe", "cwe_id": "cwe",
    "cwe ids": "cwe", "cwe number": "cwe",
    # CVSS
    "cvss": "cvss", "cvss score": "cvss", "cvss_score": "cvss",
    "cvss v3": "cvss", "cvss_v3": "cvss",
    # Tool / scanner
    "tool": "tool", "scanner": "tool", "plugin": "tool",
    "source": "tool",
}

_SEVERITY_NORMALIZE: dict[str, str] = {
    "critical": "Critical", "crit": "Critical",
    "high": "High", "h": "High",
    "medium": "Medium", "med": "Medium", "m": "Medium", "moderate": "Medium",
    "low": "Low", "l": "Low",
    "informational": "Informational", "info": "Informational",
    "information": "Informational", "note": "Informational", "none": "Informational",
}


def _normalize_csv_header(header: str) -> str:
    """Map a raw CSV column header to its canonical key, or return ''."""
    return _CSV_COLUMN_MAP.get(header.strip().lower(), "")


def _normalize_severity(raw: str) -> str:
    """Normalize a raw severity string; falls back to the raw value if unknown."""
    return _SEVERITY_NORMALIZE.get(raw.strip().lower(), raw.strip()) if raw else "Informational"


def parse_csv(csv_content: str) -> List[CsvFinding]:
    """Parse a CSV scanner export and extract findings."""
    import csv as csv_module
    import io

    try:
        # Sniff dialect; fall back to excel
        sample = csv_content[:4096]
        try:
            dialect = csv_module.Sniffer().sniff(sample, delimiters=",\t;|")
        except csv_module.Error:
            dialect = csv_module.excel

        reader = csv_module.DictReader(io.StringIO(csv_content), dialect=dialect)
        if reader.fieldnames is None:
            raise HTTPException(status_code=400, detail="CSV file has no header row")

        # Build a mapping: original_col → canonical_key
        col_map: dict[str, str] = {}
        for col in reader.fieldnames:
            canonical = _normalize_csv_header(col)
            if canonical and canonical not in col_map.values():
                col_map[col] = canonical

        if "name" not in col_map.values():
            raise HTTPException(
                status_code=400,
                detail="CSV must have a column for vulnerability name (e.g. 'Title', 'Name', 'Vulnerability')",
            )

        findings: List[CsvFinding] = []
        for row in reader:
            # Remap columns
            norm: dict[str, str] = {}
            for col, canonical in col_map.items():
                val = (row.get(col) or "").strip()
                if val:
                    norm[canonical] = val

            name = norm.get("name", "").strip()
            if not name:
                continue  # Skip blank rows

            raw_severity = norm.get("severity", "")
            findings.append(
                CsvFinding(
                    name=name,
                    severity=_normalize_severity(raw_severity),
                    description=norm.get("description"),
                    remediation=norm.get("remediation"),
                    url=norm.get("url"),
                    cwe=norm.get("cwe"),
                    cvss=norm.get("cvss"),
                    tool=norm.get("tool"),
                )
            )

        return findings
    except HTTPException:
        raise
    except Exception:
        log.exception("Error parsing CSV")
        raise HTTPException(status_code=500, detail="Failed to parse CSV file")


def _merge_csv_by_title(findings: List[CsvFinding]) -> List[dict]:
    """
    Merge CSV findings by name; combine URLs and descriptions.
    Produces dicts compatible with the Celery import task.
    """
    from app.services.evidence_schema import build_payload_from_csv

    by_name: dict[str, dict] = {}
    for f in findings:
        name = f.name or "(unnamed)"
        if name not in by_name:
            row = {
                "name": f.name,
                "severity": f.severity,
                "description": f.description or "",
                "remediation": f.remediation or "",
                "url": f.url or "",
                "cwe": f.cwe or "",
                "cvss": f.cvss or "",
                "tool": f.tool or "",
                # Sentinel used by _format_finding_as_notes to detect CSV rows
                "csv_source": True,
            }
            by_name[name] = row
        else:
            existing = by_name[name]
            if f.url and f.url not in existing["url"]:
                existing["url"] = (existing["url"] + ", " + f.url).strip(", ")
            if f.description and f.description not in existing["description"]:
                existing["description"] = (
                    existing["description"] + "\n\n" + f.description
                ).strip()

    # Build evidence_payload for each merged finding
    merged = []
    for row in by_name.values():
        payload = build_payload_from_csv(row)
        merged.append({**row, "evidence_payload": payload.to_json()})

    return merged


def parse_sarif(sarif_content: str) -> List[SarifFinding]:
    """Parse SARIF JSON and extract findings."""
    
    def _extract_message_text(field) -> str:
        """Extract text from SARIF message field (handles both string and MultiformatMessageString).
        
        SARIF spec allows message fields to be either:
        - A plain string: "Some text"
        - A MultiformatMessageString object: {"text": "Some text"}
        """
        if isinstance(field, dict):
            return field.get("text", "")
        elif isinstance(field, str):
            return field
        else:
            return ""
    
    try:
        data = json.loads(sarif_content)
        
        # Validate SARIF structure
        if not data.get("runs") or not isinstance(data["runs"], list):
            raise HTTPException(status_code=400, detail="Invalid SARIF: missing 'runs' array")
        
        findings = []
        
        for run in data["runs"]:
            tool_name = run.get("tool", {}).get("driver", {}).get("name", "Unknown Tool")
            
            # Build rules lookup
            rules = {}
            if "rules" in run.get("tool", {}).get("driver", {}):
                rules = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
            
            # Parse results
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "unknown")
                rule = rules.get(rule_id, {})
                
                # Extract name/title (MED-28: handle MultiformatMessageString in rule fields)
                message_text = _extract_message_text(result.get("message"))
                rule_name = _extract_message_text(rule.get("name"))
                short_desc = _extract_message_text(rule.get("shortDescription"))
                
                name = (
                    rule_name or
                    short_desc or
                    message_text[:100] or
                    f"Rule {rule_id}"
                )
                
                # Extract description
                full_desc = _extract_message_text(rule.get("fullDescription"))
                description = (
                    full_desc or
                    short_desc or
                    message_text
                )
                
                # Extract location
                location_str = ""
                line_number = None
                code_snippet = None
                
                if result.get("locations"):
                    phys_location = result["locations"][0].get("physicalLocation", {})
                    artifact = phys_location.get("artifactLocation", {})
                    region = phys_location.get("region", {})
                    
                    location_str = artifact.get("uri", "")
                    line_number = region.get("startLine")
                    code_snippet = region.get("snippet", {}).get("text", "")
                
                # Map SARIF level to severity
                level = result.get("level", "warning")
                severity_map = {
                    "none": "Informational",
                    "note": "Low",
                    "warning": "Medium",
                    "error": "High",
                }
                severity = severity_map.get(level, "Medium")
                
                # Try to get more specific severity from CVSS score
                props = result.get("properties", {})
                if "cvss_v4_score" in props:
                    score = props["cvss_v4_score"]
                    if score >= 9.0:
                        severity = "Critical"
                    elif score >= 7.0:
                        severity = "High"
                    elif score >= 4.0:
                        severity = "Medium"
                    elif score > 0:
                        severity = "Low"
                
                # Extract CWE
                cwe = None
                if "cwe_ids" in props and props["cwe_ids"]:
                    cwe = props["cwe_ids"][0]
                elif "tags" in rule:
                    cwe_tags = [tag for tag in rule.get("tags", []) if tag.startswith("CWE")]
                    if cwe_tags:
                        cwe = cwe_tags[0]
                
                # Extract remediation (MED-28: handle MultiformatMessageString)
                remediation = _extract_message_text(rule.get("help"))
                
                lazeport_content = props.get("lazeport_content") or None
                lazeport_vg = props.get("lazeport_validation_guidance") or None

                finding = SarifFinding(
                    ruleId=rule_id,
                    name=name,
                    severity=severity,
                    description=description,
                    location=location_str,
                    lineNumber=line_number,
                    codeSnippet=code_snippet,
                    remediation=remediation,
                    cwe=cwe,
                    tool=tool_name,
                    lazeport_content=lazeport_content,
                    lazeport_validation_guidance=lazeport_vg,
                )
                findings.append(finding)
        
        return findings
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON format in SARIF file")
    except Exception as e:
        log.exception("Error parsing SARIF")
        raise HTTPException(status_code=500, detail="Failed to parse SARIF file")

def _burp_elem_text(elem) -> str:
    """LOW-27: Extract full text from element including nested content (elem.text only gets direct text)."""
    if elem is None:
        return ""
    return "".join(elem.itertext()).strip() or ""


def parse_burp_xml(xml_content: str) -> List[BurpFinding]:
    """Parse Burp Suite XML export and extract findings."""
    try:
        root = ET.fromstring(xml_content)
        findings = []
        
        for issue in root.findall('issue'):
            # Skip false positives
            severity_elem = issue.find('severity')
            if severity_elem is not None and _burp_elem_text(severity_elem) == 'False Positive':
                continue
                
            # Extract required fields with defaults
            serial_number = issue.find('serialNumber')
            issue_type = issue.find('type')
            name = issue.find('name')
            host = issue.find('host')
            path = issue.find('path')
            location = issue.find('location')
            confidence = issue.find('confidence')
            
            # Skip if missing critical fields
            if not all(elem is not None for elem in [serial_number, name, host, severity_elem]):
                continue
                
            # Extract optional fields
            issue_background = issue.find('issueBackground')
            remediation_background = issue.find('remediationBackground')
            references = issue.find('references')
            vuln_classifications = issue.find('vulnerabilityClassifications')
            issue_detail = issue.find('issueDetail')
            remediation_detail = issue.find('remediationDetail')
            
            # Extract request/response data (MED-29 fix)
            requestresponse_elem = issue.find('requestresponse')
            requestresponse_data = None
            if requestresponse_elem is not None:
                request_elem = requestresponse_elem.find('request')
                response_elem = requestresponse_elem.find('response')
                if request_elem is not None or response_elem is not None:
                    requestresponse_data = {
                        "request": _burp_elem_text(request_elem),
                        "response": _burp_elem_text(response_elem)
                    }
            
            # Normalize Burp's "Information" to "Informational"
            raw_severity = _burp_elem_text(severity_elem)
            if raw_severity.lower() == 'information':
                raw_severity = 'Informational'

            # LOW-27: Use _burp_elem_text for nested content (elem.text misses child elements)
            finding = BurpFinding(
                serialNumber=_burp_elem_text(serial_number),
                type=_burp_elem_text(issue_type),
                name=_burp_elem_text(name),
                host=_burp_elem_text(host),
                path=_burp_elem_text(path),
                location=_burp_elem_text(location),
                severity=raw_severity,
                confidence=_burp_elem_text(confidence),
                issueBackground=_burp_elem_text(issue_background) or None,
                remediationBackground=_burp_elem_text(remediation_background) or None,
                references=_burp_elem_text(references) or None,
                vulnerabilityClassifications=_burp_elem_text(vuln_classifications) or None,
                issueDetail=_burp_elem_text(issue_detail) or None,
                remediationDetail=_burp_elem_text(remediation_detail) or None,
                requestresponse=requestresponse_data
            )
            findings.append(finding)
            
        return findings
    except ET.ParseError:
        raise HTTPException(status_code=400, detail="Invalid XML format in Burp export file")
    except Exception as e:
        log.exception("Error parsing Burp XML")
        raise HTTPException(status_code=500, detail="Failed to parse Burp XML file")

@router.post("/findings/upload-burp")
async def upload_burp_findings(
    file: UploadFile = File(...),
    report_id: Optional[str] = Query(None),
    user: User = Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Upload and parse Burp Suite XML findings export. If report_id is provided, creates
    or reuses an import session so the user can resume later."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="File must be provided")
    fn = file.filename.lower()
    if not (fn.endswith(".xml") or fn.endswith(".burp")):
        raise HTTPException(status_code=400, detail="File must be an XML or .burp file")

    # Read file content (limit to 20 MB to prevent DoS)
    MAX_UPLOAD_BYTES = 20 * 1024 * 1024  # 20 MB
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large (max 20 MB)")
    try:
        xml_content = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File encoding must be UTF-8")

    # Parse and merge by title
    raw_findings = parse_burp_xml(xml_content)
    merged_list = _merge_findings_by_title(raw_findings)

    # When report_id given: create or reuse session for resume support
    if report_id:
        from ..services.rbac import can_edit_report

        report = adapter.get_report(report_id)
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        if not can_edit_report(user, report, adapter):
            raise HTTPException(status_code=403, detail="Insufficient permissions to edit this report")

        content_hash = hashlib.sha256(content).hexdigest()
        return _create_import_session(
            findings_list=merged_list,
            file_name=file.filename or "upload.xml",
            content_hash=content_hash,
            report_id=report_id,
            adapter=adapter,
        )

    return {
        "findings": merged_list,
        "total": len(merged_list),
        "message": f"Successfully parsed {len(merged_list)} findings from Burp export",
    }


@router.post("/findings/upload-sarif")
async def upload_sarif_findings(
    file: UploadFile = File(...),
    report_id: Optional[str] = Query(None),
    user: User = Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Upload and parse SARIF JSON findings. If report_id is provided, creates
    or reuses an import session so the user can resume later."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="File must be provided")
    fn = file.filename.lower()
    if not (fn.endswith(".json") or fn.endswith(".sarif")):
        raise HTTPException(status_code=400, detail="File must be a .json or .sarif file")

    # Read file content (limit to 20 MB to prevent DoS)
    MAX_UPLOAD_BYTES = 20 * 1024 * 1024  # 20 MB
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large (max 20 MB)")
    try:
        json_content = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File encoding must be UTF-8")

    # Parse SARIF and merge by ruleId (one finding per vulnerability class)
    raw_findings = parse_sarif(json_content)
    findings_list = _merge_sarif_by_rule_id(raw_findings)
    
    # Deduplicate findings with identical locations and similar titles
    findings_list = _dedupe_by_locations(findings_list)

    # When report_id given: create or reuse session for resume support
    if report_id:
        from ..services.rbac import can_edit_report

        report = adapter.get_report(report_id)
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        if not can_edit_report(user, report, adapter):
            raise HTTPException(status_code=403, detail="Insufficient permissions to edit this report")

        content_hash = hashlib.sha256(content).hexdigest()
        return _create_import_session(
            findings_list=findings_list,
            file_name=file.filename or "upload.sarif",
            content_hash=content_hash,
            report_id=report_id,
            adapter=adapter,
        )

    return {
        "findings": findings_list,
        "total": len(findings_list),
        "message": f"Successfully parsed {len(findings_list)} findings from SARIF",
    }


@router.post("/findings/upload-csv")
async def upload_csv_findings(
    file: UploadFile = File(...),
    report_id: Optional[str] = Query(None),
    user: User = Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Upload and parse a CSV scanner export. If report_id is provided, creates
    or reuses an import session so the user can resume later."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="File must be provided")
    fn = file.filename.lower()
    if not (fn.endswith(".csv") or fn.endswith(".tsv")):
        raise HTTPException(status_code=400, detail="File must be a .csv or .tsv file")

    MAX_UPLOAD_BYTES = 20 * 1024 * 1024  # 20 MB
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large (max 20 MB)")
    try:
        csv_content = content.decode("utf-8-sig")  # strip BOM if present
    except UnicodeDecodeError:
        try:
            csv_content = content.decode("latin-1")
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="File encoding must be UTF-8 or Latin-1")

    raw_findings = parse_csv(csv_content)
    findings_list = _merge_csv_by_title(raw_findings)

    if report_id:
        from ..services.rbac import can_edit_report

        report = adapter.get_report(report_id)
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        if not can_edit_report(user, report, adapter):
            raise HTTPException(status_code=403, detail="Insufficient permissions to edit this report")

        content_hash = hashlib.sha256(content).hexdigest()
        return _create_import_session(
            findings_list=findings_list,
            file_name=file.filename or "upload.csv",
            content_hash=content_hash,
            report_id=report_id,
            adapter=adapter,
        )

    return {
        "findings": findings_list,
        "total": len(findings_list),
        "message": f"Successfully parsed {len(findings_list)} findings from CSV",
    }


# ── Nessus / OpenVAS XML Import ──────────────────────────────────────────────

_NESSUS_SEVERITY_MAP = {"0": "Informational", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"}
_OPENVAS_THREAT_MAP = {
    "log": "Informational", "debug": "Informational",
    "low": "Low", "medium": "Medium", "high": "High",
    "alarm": "Critical", "critical": "Critical",
}


class NessusFinding(BaseModel):
    """Normalized finding parsed from a .nessus or OpenVAS XML export."""
    pluginID: str
    pluginName: str
    host: str
    port: str
    severity: str
    synopsis: Optional[str] = None
    description: Optional[str] = None
    solution: Optional[str] = None
    plugin_output: Optional[str] = None
    cve: Optional[str] = None
    cwe: Optional[str] = None
    cvss3_base_score: Optional[str] = None
    cvss3_vector: Optional[str] = None
    see_also: Optional[str] = None
    tool: str = "Nessus"


def _nessus_text(elem, tag: str) -> Optional[str]:
    """Safely get text content of a child element."""
    child = elem.find(tag)
    return child.text.strip() if child is not None and child.text else None


def parse_nessus_xml(xml_content: str) -> tuple[list[NessusFinding], str]:
    """
    Parse a .nessus (Nessus) or OpenVAS/Greenbone XML export.
    Returns (findings, tool_name).
    Detects format from root element tag.
    Skips informational/None-severity plugin IDs that are purely host metadata (pluginID 0).
    """
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        raise HTTPException(status_code=400, detail="Invalid XML format in scanner export file")

    tag = root.tag.lower()

    # ── Nessus (.nessus) ─────────────────────────────────────────────────────
    if "nessusclientdata" in tag:
        findings: list[NessusFinding] = []
        report = root.find("Report")
        if report is None:
            raise HTTPException(status_code=400, detail="No Report element found in .nessus file")
        for host_elem in report.findall("ReportHost"):
            host_name = host_elem.get("name", "")
            for item in host_elem.findall("ReportItem"):
                plugin_id = item.get("pluginID", "0")
                # pluginID 0 is Nessus host metadata — skip
                if plugin_id == "0":
                    continue
                sev_int = item.get("severity", "0")
                severity = _NESSUS_SEVERITY_MAP.get(sev_int, "Informational")
                finding = NessusFinding(
                    pluginID=plugin_id,
                    pluginName=item.get("pluginName", ""),
                    host=host_name,
                    port=f"{item.get('port', '')}/{item.get('protocol', 'tcp')}",
                    severity=severity,
                    synopsis=_nessus_text(item, "synopsis"),
                    description=_nessus_text(item, "description"),
                    solution=_nessus_text(item, "solution"),
                    plugin_output=_nessus_text(item, "plugin_output"),
                    cve=_nessus_text(item, "cve"),
                    cwe=_nessus_text(item, "cwe"),
                    cvss3_base_score=_nessus_text(item, "cvss3_base_score"),
                    cvss3_vector=_nessus_text(item, "cvss3_vector"),
                    see_also=_nessus_text(item, "see_also"),
                    tool="Nessus",
                )
                findings.append(finding)
        return findings, "Nessus"

    # ── OpenVAS / Greenbone XML ──────────────────────────────────────────────
    if tag in ("report", "get_reports_response"):
        findings = []
        # OpenVAS nests results under report/report/results or report/results
        results_container = root.find(".//results")
        if results_container is None:
            raise HTTPException(status_code=400, detail="No results element found in OpenVAS report")
        for result in results_container.findall("result"):
            name_elem = result.find("name")
            name = name_elem.text.strip() if name_elem is not None and name_elem.text else ""
            if not name:
                continue
            # Threat maps to severity label; fall back to CVSS float → label
            threat_elem = result.find("threat")
            threat = (threat_elem.text or "").strip().lower() if threat_elem is not None else ""
            severity = _OPENVAS_THREAT_MAP.get(threat, "Informational")
            # Also try nvt/cvss_base for numeric fallback
            nvt = result.find("nvt")
            plugin_id = nvt.get("oid", "") if nvt is not None else ""
            cvss_base = None
            cve = None
            solution = None
            description_nvt = None
            if nvt is not None:
                cvss_base = _nessus_text(nvt, "cvss_base")
                cve_elem = nvt.find("cve")
                cve = cve_elem.text.strip() if cve_elem is not None and cve_elem.text else None
                sol_elem = nvt.find("solution")
                solution = sol_elem.text.strip() if sol_elem is not None and sol_elem.text else None
                desc_elem = nvt.find("description")
                description_nvt = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else None
            host_elem = result.find("host")
            host = host_elem.text.strip() if host_elem is not None and host_elem.text else ""
            port_elem = result.find("port")
            port = port_elem.text.strip() if port_elem is not None and port_elem.text else ""
            desc_elem = result.find("description")
            plugin_output = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else None
            finding = NessusFinding(
                pluginID=plugin_id,
                pluginName=name,
                host=host,
                port=port,
                severity=severity,
                description=description_nvt,
                solution=solution,
                plugin_output=plugin_output,
                cve=cve,
                cvss3_base_score=cvss_base,
                tool="OpenVAS",
            )
            findings.append(finding)
        return findings, "OpenVAS"

    raise HTTPException(
        status_code=400,
        detail="Unrecognised XML format. Expected a .nessus (Nessus) or OpenVAS report.",
    )


def _merge_nessus_by_plugin(findings: list[NessusFinding]) -> list[dict]:
    """
    Merge findings by pluginName. Multiple hosts hit by the same plugin
    are collapsed into one finding with combined host info.
    """
    by_name: dict[str, dict] = {}
    for f in findings:
        key = f.pluginName or "(unnamed)"
        if key not in by_name:
            by_name[key] = {
                "pluginID": f.pluginID,
                "pluginName": f.pluginName,
                "name": f.pluginName,
                "host": f.host,
                "port": f.port,
                "severity": f.severity,
                "synopsis": f.synopsis,
                "description": f.description,
                "solution": f.solution,
                "plugin_output": f.plugin_output or "",
                "cve": f.cve,
                "cwe": f.cwe,
                "cvss3_base_score": f.cvss3_base_score,
                "cvss3_vector": f.cvss3_vector,
                "see_also": f.see_also,
                "tool": f.tool,
                "nessus_source": True,
            }
        else:
            existing = by_name[key]
            if f.host and f.host not in (existing.get("host") or ""):
                existing["host"] = (existing.get("host") or "") + ", " + f.host
            if f.port and f.port not in (existing.get("port") or ""):
                existing["port"] = (existing.get("port") or "") + "; " + f.port
            if f.plugin_output:
                existing["plugin_output"] = (existing.get("plugin_output") or "") + "\n\n" + f.plugin_output
    return list(by_name.values())


@router.post("/findings/upload-nessus")
async def upload_nessus_findings(
    file: UploadFile = File(...),
    report_id: Optional[str] = Query(None),
    user: User = Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Upload and parse a Nessus (.nessus) or OpenVAS XML findings export.
    If report_id is provided, creates or reuses an import session for the
    AI-structuring workflow."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="File must be provided")
    fn = file.filename.lower()
    if not (fn.endswith(".nessus") or fn.endswith(".xml")):
        raise HTTPException(status_code=400, detail="File must be a .nessus or .xml file")

    MAX_UPLOAD_BYTES = 20 * 1024 * 1024  # 20 MB
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large (max 20 MB)")
    try:
        xml_content = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File encoding must be UTF-8")

    raw_findings, tool_name = parse_nessus_xml(xml_content)
    if not raw_findings:
        raise HTTPException(status_code=400, detail=f"No findings found in {tool_name} export")

    findings_list = _merge_nessus_by_plugin(raw_findings)

    if report_id:
        from ..services.rbac import can_edit_report

        report = adapter.get_report(report_id)
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        if not can_edit_report(user, report, adapter):
            raise HTTPException(status_code=403, detail="Insufficient permissions to edit this report")

        content_hash = hashlib.sha256(content).hexdigest()
        return _create_import_session(
            findings_list=findings_list,
            file_name=file.filename or "upload.nessus",
            content_hash=content_hash,
            report_id=report_id,
            adapter=adapter,
        )

    return {
        "findings": findings_list,
        "total": len(findings_list),
        "message": f"Successfully parsed {len(findings_list)} findings from {tool_name} export",
    }