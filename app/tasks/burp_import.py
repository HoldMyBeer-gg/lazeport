"""
Celery task for Burp import finding generation.
Runs on the server so it survives page refresh.
"""
import json
import logging
import time
import re
from pathlib import Path
from typing import Any, Dict, Optional

from app.celery_app import app
from app.config import settings
from app.db import get_adapter
from app.services.structurer import structure_notes_with_context
from app.services.master_docx import extract_severity_criteria_from_bytes
from app.services.severity_rubric import enforce_severity_label
from app.services.llm import PROVIDER_PRESETS, DEFAULT_MODELS
from app.services.field_extraction import derive_table_values

log = logging.getLogger("lazeport.tasks.burp_import")


def _strip_html(html: str) -> str:
    if not html:
        return ""
    text = (
        html.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&quot;", '"')
        .replace("&#39;", "'")
    )
    return re.sub(r"<[^>]*>", "", text).strip()


def _format_finding_as_notes(finding: Dict[str, Any]) -> str:
    """Format finding as notes - supports Burp, SARIF, CSV, and Nessus/OpenVAS findings."""
    # Detect format by presence of format-specific fields
    is_nessus = "nessus_source" in finding or "pluginID" in finding
    is_csv = "csv_source" in finding
    is_sarif = not is_nessus and not is_csv and ("ruleId" in finding or ("tool" in finding and "host" not in finding))
    is_burp = not is_nessus and not is_csv and not is_sarif

    if is_nessus:
        # Nessus / OpenVAS format
        parts = [
            f"Vulnerability: {finding.get('pluginName') or finding.get('name', '')}",
            f"Scanner: {finding.get('tool', 'Nessus')}",
            f"Host: {finding.get('host', '')}",
            f"Port: {finding.get('port', '')}",
            f"Severity: {finding.get('severity', '')}",
        ]
        if finding.get("cvss3_base_score"):
            parts.append(f"CVSS v3 Score: {finding['cvss3_base_score']}")
        if finding.get("cvss3_vector"):
            parts.append(f"CVSS v3 Vector: {finding['cvss3_vector']}")
        if finding.get("cve"):
            parts.append(f"CVE: {finding['cve']}")
        if finding.get("cwe"):
            parts.append(f"CWE: {finding['cwe']}")
        parts.append("")
        if finding.get("synopsis"):
            parts.append(f"Synopsis:\n{finding['synopsis']}\n")
        if finding.get("description"):
            parts.append(f"Description:\n{finding['description']}\n")
        if finding.get("plugin_output"):
            parts.append(f"Plugin Output:\n{finding['plugin_output']}\n")
        if finding.get("solution"):
            parts.append(f"Remediation:\n{finding['solution']}\n")
        if finding.get("see_also"):
            parts.append(f"References:\n{finding['see_also']}\n")
        return "\n".join(parts).strip()

    if is_csv:
        # CSV format (normalized by parse_csv)
        parts = [
            f"Vulnerability: {finding.get('name', '')}",
            f"Severity: {finding.get('severity', '')}",
        ]
        if finding.get("url"):
            parts.append(f"Location: {finding['url']}")
        if finding.get("cwe"):
            parts.append(f"CWE: {finding['cwe']}")
        if finding.get("cvss"):
            parts.append(f"CVSS: {finding['cvss']}")
        if finding.get("tool"):
            parts.append(f"Tool: {finding['tool']}")
        parts.append("")
        if finding.get("description"):
            parts.append(f"Description:\n{finding['description']}\n")
        if finding.get("remediation"):
            parts.append(f"Remediation:\n{finding['remediation']}\n")
        return "\n".join(parts).strip()

    if is_sarif:
        # SARIF format (merged by ruleId)
        parts = [
            f"Tool: {finding.get('tool', 'Unknown')}",
            f"Rule: {finding.get('ruleId', '')}",
            f"Vulnerability: {finding.get('name', '')}",
            f"Severity: {finding.get('severity', '')}",
        ]
        if finding.get("cwe"):
            parts.append(f"CWE: {finding['cwe']}")
        parts.append("")
        
        if finding.get("description"):
            parts.append(f"Description:\n{finding['description']}\n")
        
        # Affected Files/Locations (merged from multiple occurrences)
        locations = finding.get("locations", [])
        if locations:
            parts.append("Affected Files:")
            for loc in locations:
                file_path = loc.get("file", "")
                line_num = loc.get("line")
                snippet = loc.get("snippet", "")
                
                if line_num:
                    parts.append(f"  • {file_path}:{line_num}")
                else:
                    parts.append(f"  • {file_path}")
                
                if snippet:
                    # Indent code snippet
                    indented = "\n".join(f"      {line}" for line in snippet.split("\n"))
                    parts.append(indented)
            parts.append("")
        
        if finding.get("remediation"):
            parts.append(f"Remediation:\n{finding['remediation']}\n")
    else:
        # Burp format
        parts = [
            f"Vulnerability: {finding.get('name', '')}",
            f"Host: {finding.get('host', '')}",
            f"Path: {finding.get('path', '')}",
            f"Severity: {finding.get('severity', '')}",
            f"Confidence: {finding.get('confidence', '')}",
            "",
        ]
        if finding.get("issueDetail"):
            parts.append(f"Details:\n{_strip_html(finding['issueDetail'])}\n")
        if finding.get("issueBackground"):
            parts.append(f"Background:\n{_strip_html(finding['issueBackground'])}\n")
        if finding.get("remediationBackground") or finding.get("remediationDetail"):
            parts.append("Remediation:\n")
            if finding.get("remediationBackground"):
                parts.append(_strip_html(finding["remediationBackground"]))
            if finding.get("remediationDetail"):
                parts.append(_strip_html(finding["remediationDetail"]))
            parts.append("\n")
        if finding.get("references"):
            parts.append(f"References:\n{_strip_html(finding['references'])}\n")
        if finding.get("vulnerabilityClassifications"):
            parts.append(f"Classifications:\n{_strip_html(finding['vulnerabilityClassifications'])}\n")
    
    return "\n".join(parts).strip()


def _load_default_finding_template() -> str:
    """Load the default finding template (templates/default.html) for section structure."""
    root = Path(__file__).resolve().parent.parent.parent
    templates_dir = Path(settings.templates_dir)
    if not templates_dir.is_absolute():
        templates_dir = root / templates_dir
    path = templates_dir / "default.html"
    if path.exists():
        return path.read_text(encoding="utf-8", errors="replace")
    return ""


def _load_severity_criteria(adapter, organization_id: str, template_name: str = "master") -> Optional[Dict[str, str]]:
    """Legacy function - kept for backward compatibility. Use _load_severity_rubric instead."""
    try:
        template = adapter.get_master_template(template_name, organization_id)
        if not template:
            return None
        return extract_severity_criteria_from_bytes(template_name, template.content)
    except Exception as e:
        log.warning("Failed to load severity criteria: %s", e)
        return None


def _load_severity_rubric(adapter, organization_id: str, template_name: str = "master"):
    """Load severity rubric from master template (or return default if extraction fails)."""
    from app.services.severity_rubric import extract_rubric_from_docx_bytes, SeverityRubric
    try:
        template = adapter.get_master_template(template_name, organization_id)
        if not template:
            log.info("No master template found, using default severity rubric")
            return SeverityRubric(
                allowed_labels=["Critical", "High", "Medium", "Low", "Informational"],
                definitions={},
                source="default"
            )
        return extract_rubric_from_docx_bytes(template_name, template.content)
    except Exception as e:
        log.warning(f"Failed to load severity rubric: {e}")
        return SeverityRubric(
            allowed_labels=["Critical", "High", "Medium", "Low", "Informational"],
            definitions={},
            source="default"
        )


@app.task(bind=True)
def generate_burp_finding_task(
    self,
    session_id: str,
    task_index: int,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    llm_base_url: Optional[str] = None,
    llm_api_key: Optional[str] = None,
    llm_timeout: Optional[float] = None,
    sampling_params: Optional[Dict[str, Any]] = None,
    generation_task_id: Optional[str] = None,
):
    """
    Generate a structured finding from a Burp import task and save it.
    Updates the import session task status on success or failure.
    If generation_task_id is set, also updates the GenerationTask for TaskBar progress.
    """
    from app.tasks.llm_generation import _advance, _fail as _gen_fail

    adapter = get_adapter()

    # Claim the GenerationTask (if provided) for TaskBar progress tracking
    if generation_task_id:
        gt = adapter.claim_generation_task(generation_task_id, self.request.id)
        if not gt:
            log.warning("generate_burp_finding_task: GenerationTask %s could not be claimed", generation_task_id)
            generation_task_id = None  # proceed without TaskBar tracking

    sess = adapter.get_burp_import_session(session_id)
    if not sess:
        log.error("Burp import session %s not found", session_id)
        return {"ok": False, "error": "Session not found"}

    report = adapter.get_report(sess.report_id)
    if not report:
        log.error("Report %s not found", sess.report_id)
        return {"ok": False, "error": "Report not found"}

    tasks = json.loads(sess.tasks_json) if sess.tasks_json else []
    if task_index < 0 or task_index >= len(tasks):
        log.error("Task index %s out of range", task_index)
        return {"ok": False, "error": "Task not found"}

    task = tasks[task_index]
    
    # ABORT: Check if task was already completed or skipped
    current_status = task.get("status", "pending")
    if current_status in ("completed", "skipped"):
        log.info(
            "Task %s for session %s already %s, aborting",
            task_index, session_id, current_status
        )
        return {"ok": True, "aborted": True, "reason": f"Task already {current_status}"}
    
    finding_data = task.get("finding")
    if not finding_data:
        log.error("Task %s has no finding data", task_index)
        adapter.update_burp_session_task_status(session_id, task_index, "failed")
        return {"ok": False, "error": "No finding data"}

    # Mark as generating (with timestamp so we can detect stale tasks)
    adapter.update_burp_session_task_status(
        session_id, task_index, "generating",
        extra={"generating_since": int(time.time() * 1000)},
    )

    notes = _format_finding_as_notes(finding_data)
    settings_row = adapter.get_settings()

    provider = (llm_provider or "openai").strip().lower()
    model = llm_model or DEFAULT_MODELS.get(provider, DEFAULT_MODELS["openai"])

    # Step 0: Parsing import data
    if generation_task_id:
        _advance(adapter, generation_task_id, 0, "import_finding", model)

    # Fast path: re-importing a Lazeport-exported SARIF that already has structured
    # content embedded in result.properties. Skip LLM entirely.
    lazeport_content = finding_data.get("lazeport_content")
    if lazeport_content:
        try:
            structured = json.loads(lazeport_content)
            # Ensure Severity is present — older exports may lack it
            sev_present = any(k.lower() == "severity" for k in structured)
            if not sev_present:
                from app.services.field_extraction import canonicalize_severity_value
                raw_sev = finding_data.get("severity") or ""
                structured["Severity"] = canonicalize_severity_value(raw_sev) if raw_sev else "Informational"
                lazeport_content = json.dumps(structured)
                log.info("SARIF re-import: injected missing Severity=%s for task %s", structured["Severity"], task_index)
            title = (
                structured.get("Finding Title")
                or structured.get("title")
                or structured.get("Title")
                or finding_data.get("name")
                or "(untitled)"
            )
            evidence_payload_str = finding_data.get("evidence_payload") or ""
            finding = adapter.create_finding(
                report_id=sess.report_id,
                title=str(title),
                content_json=lazeport_content,
                notes=notes,
                template="",
                organization_id=report.organization_id,
                metadata_json="",
                evidence_payload=evidence_payload_str,
            )
            vg = finding_data.get("lazeport_validation_guidance")
            if vg:
                adapter.update_finding(finding.id, validation_guidance=vg)
            adapter.update_burp_session_task_status_if_generating(
                session_id, task_index, "completed"
            )
            if generation_task_id:
                from datetime import datetime as _dt
                adapter.update_generation_task(
                    generation_task_id, status="completed", finding_id=finding.id,
                    current_step=4, finished_at=_dt.utcnow(),
                    progress_log=json.dumps(["SARIF re-import (skipped LLM)", "Finding saved."]),
                )
            log.info("SARIF re-import: skipped LLM for task %s (lazeport_content present)", task_index)
            return {"ok": True, "finding_id": finding.id, "skipped_llm": True}
        except Exception as e:
            log.warning("lazeport_content present but unusable for task %s: %s — falling through to LLM", task_index, e)

    # CRITICAL: Reuse existing evidence_payload if present (e.g., from SARIF import)
    # Only build from Burp data if missing (true Burp imports)
    evidence_payload_str = finding_data.get("evidence_payload")
    
    if not evidence_payload_str:
        # Build canonical evidence_payload from Burp finding data BEFORE LLM call
        from app.services.evidence_schema import build_payload_from_burp
        
        # Serialize finding_data back to XML-like string for raw artifact storage
        issue_xml_parts = []
        issue_xml_parts.append("<issue>")
        for key, value in finding_data.items():
            if value and key not in ["requestresponse", "evidence_payload"]:  # Skip nested dicts and evidence_payload
                issue_xml_parts.append(f"  <{key}>{value}</{key}>")
        if finding_data.get("requestresponse"):
            issue_xml_parts.append("  <requestresponse>")
            req_resp = finding_data["requestresponse"]
            if req_resp.get("request"):
                issue_xml_parts.append(f"    <request>{req_resp['request']}</request>")
            if req_resp.get("response"):
                issue_xml_parts.append(f"    <response>{req_resp['response']}</response>")
            issue_xml_parts.append("  </requestresponse>")
        issue_xml_parts.append("</issue>")
        issue_xml_string = "\n".join(issue_xml_parts)
        
        evidence_payload = build_payload_from_burp(
            issue_dict=finding_data,
            issue_xml_string=issue_xml_string,
            tool_name="Burp Suite"
        )
        evidence_payload_str = evidence_payload.to_json()
    
    # Load severity rubric from template
    severity_rubric = _load_severity_rubric(adapter, report.organization_id)
    severity_criteria = severity_rubric.definitions if severity_rubric.definitions else None
    
    template_markdown = _load_default_finding_template()
    if provider == "ollama":
        base_url = (llm_base_url or "http://localhost:11434").rstrip("/")
    else:
        base_url = (llm_base_url or PROVIDER_PRESETS.get(provider, PROVIDER_PRESETS["openai"])["base_url"]).rstrip("/")

    # Prepare finding_metadata with evidence_payload
    finding_metadata_with_payload = {
        **finding_data,
        "evidence_payload": evidence_payload_str
    }

    try:
        # Step 1: Calling LLM
        if generation_task_id:
            _advance(adapter, generation_task_id, 1, "import_finding", model)

        structured, metadata_json = structure_notes_with_context(
            notes=notes,
            finding_metadata=finding_metadata_with_payload,
            template_markdown=template_markdown,
            use_ai=True,
            llm_provider=provider,
            llm_model=model,
            llm_base_url=base_url,
            llm_api_key_override=llm_api_key,
            org_context={
                "org_name": settings_row.org_name or "",
                "author_name": "",
                "voice_style": settings_row.voice_style or "",
            },
            self_check=True,
            self_check_rounds=3,
            severity_criteria=severity_criteria,
            severity_rubric=severity_rubric,
            llm_timeout=llm_timeout,
            sampling_params=sampling_params,
        )
        
        # Step 2: Structuring result
        if generation_task_id:
            _advance(adapter, generation_task_id, 2, "import_finding", model)

        # Enforce severity label matches rubric (deterministic, post-generation)
        structured = enforce_severity_label(structured, severity_rubric, notes)
        
        table_values = derive_table_values(structured, notes)
        for k, v in table_values.items():
            if v and not structured.get(k):
                structured[k] = v
        
        # Set Found Date automatically (system-owned field)
        if not structured.get("Found Date"):
            from datetime import datetime
            structured["Found Date"] = datetime.utcnow().strftime("%Y-%m-%d")

        title = (
            structured.get("Finding Title")
            or structured.get("title")
            or structured.get("Title")
            or finding_data.get("name")
            or "(untitled)"
        )
        
        # MED-16: Validate content structure before storing
        # Fail fast if LLM generated invalid structure
        if not isinstance(structured, dict):
            raise ValueError(f"LLM generated non-dict content (type: {type(structured).__name__})")
        
        for key, value in structured.items():
            if not isinstance(key, str):
                raise ValueError(f"LLM generated non-string key: {key} (type: {type(key).__name__})")
            # Skip internal/metadata fields (prefixed with _)
            if key.startswith("_"):
                continue
            # Allow None and string values only (no nested objects, arrays, numbers)
            if value is not None and not isinstance(value, str):
                raise ValueError(
                    f"LLM generated non-string value for field '{key}' "
                    f"(type: {type(value).__name__}, value: {repr(value)[:100]}). "
                    "Content must be a flat dict with string values only."
                )
        # Do not persist internal keys (_severity_flags, rubric_source=..., etc.)
        structured = {k: v for k, v in structured.items() if not (isinstance(k, str) and k.startswith("_"))}
        content_json = json.dumps(structured)

        # Step 3: Saving finding
        if generation_task_id:
            _advance(adapter, generation_task_id, 3, "import_finding", model)

        # Save finding with evidence_payload
        finding = adapter.create_finding(
            report_id=sess.report_id,
            title=str(title),
            content_json=content_json,
            notes=notes,
            template="",
            organization_id=report.organization_id,
            metadata_json=metadata_json,
            evidence_payload=evidence_payload_str,
        )
        
        # Conditional update: only set "completed" if still "generating"
        # This prevents overwriting user-initiated "skipped" status
        updated, _ = adapter.update_burp_session_task_status_if_generating(
            session_id, task_index, "completed"
        )
        if updated:
            log.info("Burp import task %s completed for session %s", task_index, session_id)
        else:
            log.info(
                "Burp import task %s for session %s was skipped/cancelled during execution, "
                "finding created but not marked as completed",
                task_index, session_id
            )
        if generation_task_id:
            from datetime import datetime as _dt
            adapter.update_generation_task(
                generation_task_id, status="completed", finding_id=finding.id,
                current_step=4, finished_at=_dt.utcnow(),
                progress_log=json.dumps(["Finding saved."]),
            )
        return {"ok": True, "finding_id": finding.id}
    except Exception as e:
        log.exception("Burp import task %s failed: %s", task_index, e)
        # Conditional update: only set "failed" if still "generating"
        updated, _ = adapter.update_burp_session_task_status_if_generating(
            session_id, task_index, "failed"
        )
        if generation_task_id:
            _gen_fail(adapter, generation_task_id, "Import generation failed. Check LLM settings.")
        return {"ok": False, "error": str(e), "status_updated": updated}
