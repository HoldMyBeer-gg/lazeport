"""
Celery tasks for background LLM generation.
Tasks survive page refresh, navigation, and browser close.

Rule 11: All exceptions are logged — no silent failures.
Rule 13: Background task + shared DB state — see claim_generation_task for race-condition guard.
"""
import json
import logging
from datetime import datetime
from typing import Any, Dict, Optional

from app.celery_app import app
from app.db import get_adapter
from app.services.llm import PROVIDER_PRESETS, DEFAULT_MODELS

log = logging.getLogger("lazeport.tasks.llm_generation")

# Human-readable progress messages shown in TaskBar (never raw logs or API responses).
_STEPS = {
    "generate_finding": [
        "Parsing notes...",
        "Calling LLM ({model})...",
        "Structuring result...",
        "Saving finding...",
    ],
    "regenerate_finding": [
        "Loading finding...",
        "Calling LLM ({model})...",
        "Structuring result...",
        "Storing result for review...",
    ],
    "generate_summaries": [
        "Generating executive summary ({model})...",
        "Generating technical summary ({model})...",
        "Generating recommendations ({model})...",
        "Validating summaries...",
        "Storing summaries for review...",
    ],
    "vision_extraction": [
        "Decoding image...",
        "Calling vision model ({model})...",
        "Extracting text...",
    ],
    "import_finding": [
        "Parsing import data...",
        "Calling LLM ({model})...",
        "Structuring result...",
        "Saving finding...",
    ],
    "validate_guidance": [
        "Loading finding...",
        "Calling LLM ({model})...",
        "Saving guidance...",
    ],
}

TOTAL_STEPS = {k: len(v) for k, v in _STEPS.items()}


def _step_msg(task_type: str, step_index: int, model: str = "") -> str:
    steps = _STEPS.get(task_type, [])
    if step_index >= len(steps):
        return ""
    return steps[step_index].format(model=model or "LLM")


def _advance(adapter, task_id: str, step: int, task_type: str, model: str = "") -> None:
    """Increment current_step and append a safe progress message."""
    task = adapter.get_generation_task(task_id)
    if not task:
        return
    try:
        log_list = json.loads(task.progress_log or "[]")
    except (json.JSONDecodeError, Exception):
        log_list = []
    msg = _step_msg(task_type, step, model)
    if msg:
        log_list.append(msg)
    adapter.update_generation_task(
        task_id,
        current_step=step + 1,  # 1-based for display
        progress_log=json.dumps(log_list),
    )


def _fail(adapter, task_id: str, error: str) -> None:
    """Mark task as failed with a safe error message."""
    adapter.update_generation_task(
        task_id,
        status="failed",
        error=error,
        finished_at=datetime.utcnow(),
    )


def _resolve_llm(provider: Optional[str], model: Optional[str], base_url: Optional[str]):
    provider = (provider or "openai").strip().lower()
    if provider == "ollama":
        base_url = (base_url or "http://localhost:11434").rstrip("/")
    else:
        base_url = (base_url or PROVIDER_PRESETS.get(provider, PROVIDER_PRESETS["openai"])["base_url"]).rstrip("/")
    model = model or DEFAULT_MODELS.get(provider, DEFAULT_MODELS["openai"])
    return provider, model, base_url


@app.task(bind=True)
def generate_finding_task(
    self,
    generation_task_id: str,
    notes: str,
    template_markdown: str,
    report_id: str,
    organization_id: str,
    user_id: str,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    llm_base_url: Optional[str] = None,
    llm_api_key: Optional[str] = None,
    llm_timeout: Optional[float] = None,
    sampling_params: Optional[Dict[str, Any]] = None,
    org_context: Optional[Dict[str, str]] = None,
    extra_instructions: Optional[str] = None,
    severity_criteria: Optional[Dict[str, str]] = None,
    finding_metadata: Optional[Dict[str, Any]] = None,
    locale: Optional[str] = None,
):
    """Generate a structured finding and auto-save it. New findings have no prior version, so auto-save is safe."""
    from app.services.structurer import structure_notes_with_context
    from app.services.field_extraction import derive_table_values
    from app.services.severity_rubric import SeverityRubric, enforce_severity_label
    from app.services.field_extraction import canonicalize_severity_value

    adapter = get_adapter()

    # Claim: atomic pending → running transition (Rule 13)
    task = adapter.claim_generation_task(generation_task_id, self.request.id)
    if not task:
        log.warning("generate_finding_task: task %s could not be claimed (already running or not found)", generation_task_id)
        return {"ok": False, "reason": "Task already claimed or not found"}

    task_type = "generate_finding"
    provider, model, base_url = _resolve_llm(llm_provider, llm_model, llm_base_url)

    try:
        # Step 0: Parsing notes
        _advance(adapter, generation_task_id, 0, task_type, model)

        settings_row = adapter.get_settings()
        severity_rubric = SeverityRubric(
            allowed_labels=["Critical", "High", "Medium", "Low", "Informational"],
            definitions=severity_criteria or {},
            source="passed",
        )

        # Build evidence_payload from notes if not already present (manual findings path)
        metadata = dict(finding_metadata or {})
        if not metadata.get("evidence_payload"):
            from app.services.evidence_schema import build_payload_from_notes
            ev = build_payload_from_notes(notes, metadata)
            metadata["evidence_payload"] = ev.to_json()

        # Step 1: Calling LLM
        _advance(adapter, generation_task_id, 1, task_type, model)

        structured, metadata_json = structure_notes_with_context(
            notes=notes,
            finding_metadata=metadata,
            template_markdown=template_markdown,
            use_ai=True,
            llm_provider=provider,
            llm_model=model,
            llm_base_url=base_url,
            llm_api_key_override=llm_api_key,
            org_context=org_context or {
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
        _advance(adapter, generation_task_id, 2, task_type, model)

        structured = enforce_severity_label(structured, severity_rubric, notes)
        table_values = derive_table_values(structured, notes)
        for k, v in table_values.items():
            if v and not structured.get(k):
                structured[k] = v
        if not structured.get("Found Date"):
            structured["Found Date"] = datetime.utcnow().strftime("%Y-%m-%d")
        if "Severity" in structured:
            structured["Severity"] = canonicalize_severity_value(str(structured.get("Severity") or ""))

        # Strip internal keys before storage
        structured = {k: v for k, v in structured.items() if not (isinstance(k, str) and k.startswith("_"))}
        title = (
            structured.get("Finding Title")
            or structured.get("title")
            or structured.get("Title")
            or "(untitled)"
        )

        content_json = json.dumps(structured)
        # Cap result_json at ~64KB
        if len(content_json) > 65536:
            log.warning("generate_finding_task: result_json truncated for task %s", generation_task_id)
            content_json = content_json[:65536]

        # Step 3: Saving finding (auto-save — new finding, no data loss risk)
        _advance(adapter, generation_task_id, 3, task_type, model)

        report = adapter.get_report(report_id)
        finding = adapter.create_finding(
            report_id=report_id,
            title=str(title),
            content_json=content_json,
            notes=notes,
            template="",
            organization_id=organization_id,
            metadata_json=metadata_json,
            evidence_payload=metadata.get("evidence_payload", ""),
        )

        # Mark completed
        task_log = json.loads(adapter.get_generation_task(generation_task_id).progress_log or "[]")
        task_log.append("Finding saved.")
        adapter.update_generation_task(
            generation_task_id,
            status="completed",
            finding_id=finding.id,
            result_json=content_json,
            finished_at=datetime.utcnow(),
            progress_log=json.dumps(task_log),
        )
        log.info("generate_finding_task: completed for task %s, finding %s", generation_task_id, finding.id)
        return {"ok": True, "finding_id": finding.id}

    except Exception as e:
        log.exception("generate_finding_task: task %s failed: %s", generation_task_id, e)
        _fail(adapter, generation_task_id, "Generation failed. Please check your LLM settings and try again.")
        return {"ok": False, "error": str(e)}


@app.task(bind=True)
def regenerate_finding_task(
    self,
    generation_task_id: str,
    finding_id: str,
    notes: str,
    template_markdown: str,
    report_id: str,
    organization_id: str,
    user_id: str,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    llm_base_url: Optional[str] = None,
    llm_api_key: Optional[str] = None,
    llm_timeout: Optional[float] = None,
    sampling_params: Optional[Dict[str, Any]] = None,
    org_context: Optional[Dict[str, str]] = None,
    extra_instructions: Optional[str] = None,
    severity_criteria: Optional[Dict[str, str]] = None,
    finding_metadata: Optional[Dict[str, Any]] = None,
    locale: Optional[str] = None,
):
    """
    Regenerate an existing finding. Result stored only — original untouched until user approves.
    No versioning exists: overwriting automatically would destroy the original.
    """
    from app.services.structurer import structure_notes_with_context
    from app.services.field_extraction import derive_table_values
    from app.services.severity_rubric import SeverityRubric, enforce_severity_label
    from app.services.field_extraction import canonicalize_severity_value

    adapter = get_adapter()

    task = adapter.claim_generation_task(generation_task_id, self.request.id)
    if not task:
        log.warning("regenerate_finding_task: task %s could not be claimed", generation_task_id)
        return {"ok": False, "reason": "Task already claimed or not found"}

    task_type = "regenerate_finding"
    provider, model, base_url = _resolve_llm(llm_provider, llm_model, llm_base_url)

    try:
        # Step 0: Loading finding
        _advance(adapter, generation_task_id, 0, task_type, model)

        existing = adapter.get_finding(finding_id)
        if not existing:
            raise ValueError(f"Finding {finding_id} not found")

        settings_row = adapter.get_settings()
        severity_rubric = SeverityRubric(
            allowed_labels=["Critical", "High", "Medium", "Low", "Informational"],
            definitions=severity_criteria or {},
            source="passed",
        )

        # Build finding_metadata with evidence_payload:
        # Prefer the finding's stored evidence_payload (preserves original scanner evidence).
        # Fall back to building from notes for manual findings without stored evidence.
        metadata = dict(finding_metadata or {})
        if not metadata.get("evidence_payload"):
            stored_payload = getattr(existing, "evidence_payload", None)
            if stored_payload:
                metadata["evidence_payload"] = stored_payload
            else:
                from app.services.evidence_schema import build_payload_from_notes
                ev = build_payload_from_notes(notes or existing.notes or "", metadata)
                metadata["evidence_payload"] = ev.to_json()

        # Step 1: Calling LLM
        _advance(adapter, generation_task_id, 1, task_type, model)

        structured, metadata_json = structure_notes_with_context(
            notes=notes,
            finding_metadata=metadata,
            template_markdown=template_markdown,
            use_ai=True,
            llm_provider=provider,
            llm_model=model,
            llm_base_url=base_url,
            llm_api_key_override=llm_api_key,
            org_context=org_context or {
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
        _advance(adapter, generation_task_id, 2, task_type, model)

        structured = enforce_severity_label(structured, severity_rubric, notes)
        table_values = derive_table_values(structured, notes)
        for k, v in table_values.items():
            if v and not structured.get(k):
                structured[k] = v
        if not structured.get("Found Date"):
            structured["Found Date"] = datetime.utcnow().strftime("%Y-%m-%d")
        if "Severity" in structured:
            structured["Severity"] = canonicalize_severity_value(str(structured.get("Severity") or ""))
        structured = {k: v for k, v in structured.items() if not (isinstance(k, str) and k.startswith("_"))}

        content_json = json.dumps(structured)
        if len(content_json) > 65536:
            log.warning("regenerate_finding_task: result_json truncated for task %s", generation_task_id)
            content_json = content_json[:65536]

        # Step 3: Storing result only — user must approve before we overwrite original
        _advance(adapter, generation_task_id, 3, task_type, model)

        task_log = json.loads(adapter.get_generation_task(generation_task_id).progress_log or "[]")
        task_log.append("Result ready for review.")
        adapter.update_generation_task(
            generation_task_id,
            status="completed",
            finding_id=finding_id,  # reference to the *original* finding to update on approval
            result_json=content_json,
            finished_at=datetime.utcnow(),
            progress_log=json.dumps(task_log),
        )
        log.info("regenerate_finding_task: completed for task %s, finding %s", generation_task_id, finding_id)
        return {"ok": True, "finding_id": finding_id}

    except Exception as e:
        log.exception("regenerate_finding_task: task %s failed: %s", generation_task_id, e)
        _fail(adapter, generation_task_id, "Regeneration failed. Please check your LLM settings and try again.")
        return {"ok": False, "error": str(e)}


@app.task(bind=True)
def generate_summaries_task(
    self,
    generation_task_id: str,
    report_id: str,
    user_id: str,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    llm_base_url: Optional[str] = None,
    llm_api_key: Optional[str] = None,
    llm_timeout: Optional[float] = None,
    sampling_params: Optional[Dict[str, Any]] = None,
    locale: Optional[str] = None,
    extra_instructions: Optional[str] = None,
):
    """
    Generate all three report summaries. Result stored only — user must review before saving.
    Three fields would be silently replaced without review; this preserves user agency.
    """
    from app.services.llm import chat_completion
    import json as _json

    adapter = get_adapter()

    task = adapter.claim_generation_task(generation_task_id, self.request.id)
    if not task:
        log.warning("generate_summaries_task: task %s could not be claimed", generation_task_id)
        return {"ok": False, "reason": "Task already claimed or not found"}

    task_type = "generate_summaries"
    provider, model, base_url = _resolve_llm(llm_provider, llm_model, llm_base_url)

    try:
        report = adapter.get_report(report_id)
        if not report:
            raise ValueError(f"Report {report_id} not found")

        findings_raw = list(adapter.list_findings(report_id))
        if not findings_raw:
            raise ValueError("Report has no findings to summarize")

        # Build severity distribution
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for f in findings_raw:
            try:
                content = _json.loads(f.content_json or "{}")
                sev = content.get("Severity", "").strip().capitalize()
                if sev in severity_counts:
                    severity_counts[sev] += 1
            except _json.JSONDecodeError as e:
                log.debug("Finding %s has invalid content_json: %s", f.id, e)

        highest_severity = next(
            (sev for sev in ["Critical", "High", "Medium", "Low", "Informational"] if severity_counts[sev] > 0),
            "Informational"
        )
        severity_constraint = (
            f"SEVERITY DISTRIBUTION (factual, do not deviate):\n"
            f"- Critical: {severity_counts['Critical']} finding(s)\n"
            f"- High: {severity_counts['High']} finding(s)\n"
            f"- Medium: {severity_counts['Medium']} finding(s)\n"
            f"- Low: {severity_counts['Low']} finding(s)\n"
            f"- Informational: {severity_counts['Informational']} finding(s)\n\n"
            f"Highest severity present: {highest_severity}\n\n"
            "CRITICAL CONSTRAINT: Only reference severity levels that actually appear in the findings "
            "(count > 0). Do not exaggerate severity levels."
        )

        findings_context = []
        for f in findings_raw:
            try:
                content = _json.loads(f.content_json or "{}")
            except _json.JSONDecodeError:
                content = {}
            finding_text = f"**{f.title}**\n"
            if content.get("Severity"):
                finding_text += f"Severity: {content['Severity']}\n"
            if content.get("Vulnerability Summary"):
                finding_text += f"Summary: {content['Vulnerability Summary']}\n"
            if content.get("Remediation"):
                finding_text += f"Remediation: {content['Remediation']}\n"
            findings_context.append(finding_text)
        context = "\n\n".join(findings_context)

        # Language instruction
        from app.api.generate import LOCALE_TO_LANGUAGE
        lang_name = LOCALE_TO_LANGUAGE.get((locale or "en").strip())
        lang_instruction = (
            f"Respond in the user's preferred language: {lang_name}. "
            "All content must be written in that language. "
            "Keep technical identifiers unchanged (CVE, CWE, OWASP codes, CVSS). "
        ) if lang_name else ""

        system_content = lang_instruction.strip()
        if extra_instructions and extra_instructions.strip():
            system_content = (system_content + "\n\nAdditional instructions:\n" + extra_instructions.strip()).strip()
        summary_messages = [{"role": "system", "content": system_content}] if system_content else []

        def _run_chat(messages):
            return chat_completion(
                messages=messages,
                temperature=0.7,
                provider_override=provider,
                model_override=model,
                base_url_override=base_url,
                api_key_override=llm_api_key,
                timeout_override=llm_timeout,
                sampling_params=sampling_params,
            ).strip()

        # Step 0: Executive summary
        _advance(adapter, generation_task_id, 0, task_type, model)
        executive_context = []
        for f in findings_raw:
            try:
                content = _json.loads(f.content_json or "{}")
            except _json.JSONDecodeError:
                content = {}
            finding_text = f.title
            if content.get("Severity"):
                sev = str(content.get("Severity", "")).strip().lower()
                impact = {
                    "critical": "immediate threat to operations",
                    "high": "significant risk to operations",
                    "medium": "moderate risk requiring action",
                    "low": "minor risk with long-term impact",
                    "informational": "best practice recommendation"
                }.get(sev, "requires attention")
                finding_text += f" ({impact})"
            executive_context.append(finding_text)

        exec_prompt = (
            "Based on these vulnerability findings, write a concise executive summary (2-3 paragraphs) "
            "suitable for non-technical C-level decision-makers.\n\n"
            "Focus on: (1) What business systems or operations are at risk, (2) Why this matters, "
            "(3) Prioritized action steps.\n\n"
            "CRITICAL INSTRUCTIONS: Avoid technical jargon, acronyms (CVE, CWE, OWASP, CVSS), and "
            "implementation details. Focus on business impact.\n\n"
            f"{severity_constraint}\n\n"
            f"Findings:\n- {chr(10).join('- ' + x for x in executive_context)}\n\nExecutive Summary:"
        )
        executive_summary = _run_chat(summary_messages + [{"role": "user", "content": exec_prompt}])

        # Step 1: Technical summary
        _advance(adapter, generation_task_id, 1, task_type, model)
        tech_prompt = (
            "Based on these vulnerability findings, write a technical summary (2-3 paragraphs) for "
            "technical stakeholders. Focus on attack vectors, affected systems, and technical severity:\n\n"
            f"{severity_constraint}\n\n{context}\n\nTechnical Summary:"
        )
        technical_summary = _run_chat(summary_messages + [{"role": "user", "content": tech_prompt}])

        # Step 2: Recommendations
        _advance(adapter, generation_task_id, 2, task_type, model)
        rec_prompt = (
            "Based on these vulnerability findings, write a summary of prioritized recommendations "
            "(2-3 paragraphs) with clear, actionable next steps.\n\n"
            "Focus on: (1) What to fix first, (2) Concrete actions, (3) Timeline/urgency.\n\n"
            f"{severity_constraint}\n\n{context}\n\nSummary of Recommendations:"
        )
        recommendations_summary = _run_chat(summary_messages + [{"role": "user", "content": rec_prompt}])

        # Step 3: Validate (basic non-empty check)
        _advance(adapter, generation_task_id, 3, task_type, model)
        if not executive_summary or not technical_summary or not recommendations_summary:
            raise ValueError("LLM returned empty summaries")

        # Step 4: Store result only — user reviews before saving to report
        _advance(adapter, generation_task_id, 4, task_type, model)
        result = {
            "summary_executive": executive_summary,
            "summary_technical": technical_summary,
            "summary_recommendations": recommendations_summary,
        }
        result_json = json.dumps(result)
        if len(result_json) > 65536:
            log.warning("generate_summaries_task: result_json truncated for task %s", generation_task_id)
            result_json = result_json[:65536]

        task_log = json.loads(adapter.get_generation_task(generation_task_id).progress_log or "[]")
        task_log.append("Summaries ready for review.")
        adapter.update_generation_task(
            generation_task_id,
            status="completed",
            result_json=result_json,
            finished_at=datetime.utcnow(),
            progress_log=json.dumps(task_log),
        )
        log.info("generate_summaries_task: completed for task %s, report %s", generation_task_id, report_id)
        return {"ok": True}

    except Exception as e:
        log.exception("generate_summaries_task: task %s failed: %s", generation_task_id, e)
        _fail(adapter, generation_task_id, "Summary generation failed. Please check your LLM settings and try again.")
        return {"ok": False, "error": str(e)}


@app.task(bind=True)
def vision_extraction_task(
    self,
    generation_task_id: str,
    image_base64: str,
    image_mime_type: str,
    prompt: Optional[str] = None,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    llm_base_url: Optional[str] = None,
    llm_api_key: Optional[str] = None,
    llm_timeout: Optional[float] = None,
    sampling_params: Optional[Dict[str, Any]] = None,
):
    """Extract text from an image using a vision model. Result stored inline."""
    from app.services.llm import vision_completion

    adapter = get_adapter()

    task = adapter.claim_generation_task(generation_task_id, self.request.id)
    if not task:
        log.warning("vision_extraction_task: task %s could not be claimed", generation_task_id)
        return {"ok": False, "reason": "Task already claimed or not found"}

    task_type = "vision_extraction"
    provider, model, base_url = _resolve_llm(llm_provider, llm_model, llm_base_url)

    try:
        # Step 0: Decoding image
        _advance(adapter, generation_task_id, 0, task_type, model)

        default_prompt = (
            "Extract content from this screenshot for pentest report notes.\n\n"
            "If the image contains text, transcribe it exactly:\n"
            "- URLs and endpoints (preserve exactly as shown)\n"
            "- HTTP headers, cookies, and parameters\n"
            "- Request/response bodies\n"
            "- Error messages or status codes\n"
            "- Code snippets or payloads\n"
            "- Any other visible text\n\n"
            "If the image contains little or no text, describe only what is literally visible in 1-2 sentences. "
            "Do not invent URLs, system names, or security context that are not clearly present in the image.\n\n"
            "Use [unclear] only for specific characters or words you cannot read. "
            "Do not add commentary beyond what is needed. Return only the extracted text or description."
        )
        effective_prompt = prompt or default_prompt

        # Step 1: Calling vision model
        _advance(adapter, generation_task_id, 1, task_type, model)

        extracted_text = vision_completion(
            prompt=effective_prompt,
            image_base64=image_base64,
            image_mime_type=image_mime_type,
            model_override=model,
            provider_override=provider,
            base_url_override=base_url,
            api_key_override=llm_api_key,
            timeout_override=llm_timeout,
            sampling_params=sampling_params,
        )

        # Step 2: Store result
        _advance(adapter, generation_task_id, 2, task_type, model)

        result_json = json.dumps({"text": extracted_text, "model": model})
        if len(result_json) > 65536:
            log.warning("vision_extraction_task: result truncated for task %s", generation_task_id)
            result_json = result_json[:65536]

        task_log = json.loads(adapter.get_generation_task(generation_task_id).progress_log or "[]")
        task_log.append("Text extracted.")
        adapter.update_generation_task(
            generation_task_id,
            status="completed",
            result_json=result_json,
            finished_at=datetime.utcnow(),
            progress_log=json.dumps(task_log),
        )
        log.info("vision_extraction_task: completed for task %s", generation_task_id)
        return {"ok": True}

    except Exception as e:
        log.exception("vision_extraction_task: task %s failed: %s", generation_task_id, e)
        _fail(adapter, generation_task_id, "Vision extraction failed. Please check your vision model settings and try again.")
        return {"ok": False, "error": str(e)}


@app.task(bind=True)
def validate_guidance_task(
    self,
    generation_task_id: str,
    finding_id: str,
    user_id: str,
    organization_id: str,
    report_id: str,
    llm_provider: Optional[str] = None,
    llm_model: Optional[str] = None,
    llm_base_url: Optional[str] = None,
    llm_api_key: Optional[str] = None,
    llm_timeout: Optional[float] = None,
    regenerate: bool = False,
):
    """
    Generate validation guidance for a finding using LLM. Auto-saves to finding.validation_guidance.
    Validation guidance is additive (does not overwrite structured content), so auto-save is safe.
    If guidance already exists and regenerate=False, completes immediately with cached result.
    """
    from app.services.llm import chat_completion
    from app.services.evidence_schema import EvidencePayload

    adapter = get_adapter()

    task = adapter.claim_generation_task(generation_task_id, self.request.id)
    if not task:
        log.warning("validate_guidance_task: task %s could not be claimed", generation_task_id)
        return {"ok": False, "reason": "Task already claimed or not found"}

    task_type = "validate_guidance"
    provider, model, base_url = _resolve_llm(llm_provider, llm_model, llm_base_url)

    try:
        # Step 0: Loading finding
        _advance(adapter, generation_task_id, 0, task_type, model)

        finding = adapter.get_finding(finding_id)
        if not finding:
            raise ValueError(f"Finding {finding_id} not found")

        # Cache check: if guidance exists and not forcing regeneration, return cached
        if finding.validation_guidance and not regenerate:
            log.info("validate_guidance_task: returning cached guidance for finding %s", finding_id)
            task_log = json.loads(adapter.get_generation_task(generation_task_id).progress_log or "[]")
            task_log.append("Cached guidance found.")
            adapter.update_generation_task(
                generation_task_id,
                status="completed",
                finding_id=finding_id,
                current_step=3,
                result_json=json.dumps({"guidance": finding.validation_guidance, "cached": True}),
                finished_at=datetime.utcnow(),
                progress_log=json.dumps(task_log),
            )
            return {"ok": True, "finding_id": finding_id, "cached": True}

        # Parse finding content
        try:
            content = json.loads(finding.content_json or "{}")
        except (json.JSONDecodeError, Exception) as e:
            log.warning("validate_guidance_task: invalid content_json for finding %s: %s", finding_id, e)
            content = {}

        title = finding.title or "Untitled Vulnerability"
        severity = content.get("Severity", "Unknown")
        summary = content.get("Vulnerability Summary", "")
        impact = content.get("Impact", "")
        affected_resources = content.get("Affected Resources", "")

        # Extract evidence if available
        evidence_text = ""
        if finding.evidence_payload:
            try:
                payload_obj = EvidencePayload.from_json(finding.evidence_payload)
                evidence_text = payload_obj.verbatim_text or ""
            except Exception as e:
                log.warning("validate_guidance_task: failed to parse evidence for finding %s: %s", finding_id, type(e).__name__)

        # Step 1: Calling LLM
        _advance(adapter, generation_task_id, 1, task_type, model)

        system_prompt = (
            "You are a security testing assistant helping authorized penetration testers validate vulnerabilities.\n\n"
            "IMPORTANT CONTEXT:\n"
            "- The user is an authorized security professional\n"
            "- They have written permission and rules of engagement\n"
            "- They are working within legal and ethical boundaries\n"
            "- This is part of authorized security testing with appropriate insurance coverage\n"
            "- Your role is to help them validate findings, NOT to facilitate unauthorized access\n\n"
            "Your task is to provide VALIDATION GUIDANCE only - clear, actionable steps to verify "
            "if the reported vulnerability actually exists. This helps ensure findings are accurate "
            "and not false positives."
        )

        user_prompt = (
            f"Finding to Validate:\n"
            f"Title: {title}\n"
            f"Severity: {severity}\n\n"
            f"Summary:\n{summary}\n\n"
            f"Impact:\n{impact}\n\n"
            f"Affected Resources:\n{affected_resources}\n\n"
            f"Evidence:\n{evidence_text[:500] if evidence_text else 'No evidence provided'}\n\n"
            "Please provide the SIMPLEST way to validate this vulnerability. Use markdown formatting throughout:\n"
            "- Use `## Section Title` for each section heading\n"
            "- Use bullet points (`-`) for all steps and lists — do NOT use numbered prose like \"Step 1:\", \"Step 2:\"\n"
            "- Use backticks for commands, payloads, and tool names\n\n"
            "Cover:\n"
            "- **Validation steps**: bullet-point procedure to verify the vulnerability exists\n"
            "- **Expected result**: what you should observe if it's real\n"
            "- **Tools / commands**: specific commands or tools (if applicable)\n"
            "- **Safe testing notes**: any precautions\n\n"
            "Focus on validation, not exploitation. Keep it concise and practical."
        )

        response_text = chat_completion(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            provider_override=provider,
            model_override=model,
            base_url_override=base_url,
            api_key_override=llm_api_key,
            timeout_override=llm_timeout,
            sampling_params={"max_tokens": 600},
        )

        # Step 2: Saving guidance
        _advance(adapter, generation_task_id, 2, task_type, model)

        adapter.update_finding(finding_id, validation_guidance=response_text)
        log.info("validate_guidance_task: saved guidance for finding %s", finding_id)

        result_json = json.dumps({"guidance": response_text, "cached": False})
        if len(result_json) > 65536:
            log.warning("validate_guidance_task: result_json truncated for task %s", generation_task_id)
            result_json = result_json[:65536]

        task_log = json.loads(adapter.get_generation_task(generation_task_id).progress_log or "[]")
        task_log.append("Guidance saved.")
        adapter.update_generation_task(
            generation_task_id,
            status="completed",
            finding_id=finding_id,
            result_json=result_json,
            finished_at=datetime.utcnow(),
            progress_log=json.dumps(task_log),
        )
        log.info("validate_guidance_task: completed for task %s, finding %s", generation_task_id, finding_id)
        return {"ok": True, "finding_id": finding_id}

    except Exception as e:
        log.exception("validate_guidance_task: task %s failed: %s", generation_task_id, e)
        _fail(adapter, generation_task_id, "Validation guidance failed. Please check your LLM settings and try again.")
        return {"ok": False, "error": str(e)}
