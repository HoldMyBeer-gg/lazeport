import io
import json
import logging
import re
from typing import Optional, Dict

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator

from app.services.docx_builder import build_docx
from app.validation import ValidatedString, sanitize_string, MAX_TITLE_LENGTH
from app.services.llm import ALLOWED_PROVIDERS
from app.services.link_validator import (
    extract_identifier_urls,
    extract_urls,
    get_valid_urls,
    identifier_to_url,
    is_canonical_url,
)
from app.services.structurer import structure_notes, apply_severity_override
from app.services.http_snippets import extract_http_snippets
from app.services.master_docx import extract_severity_criteria_from_bytes
from app.services.auth import get_current_user
from app.services.rbac import can_edit_report
from app.services.audit import log_delete, log_update
from app.services.field_extraction import (
    canonicalize_severity_value,
    derive_table_values,
    user_api_key_for_provider,
)
from app.db import get_adapter
from app.db.adapter import StorageAdapter

DEFAULT_EXTRA_INSTRUCTIONS = (
    "Write in a direct, professional security consulting tone. Use active voice and "
    "specific technical detail. Avoid flowery language, hedging phrases (for example, "
    '"it appears that", "it seems"), or overly formal constructions. No em dashes (\u2014), '
    "use commas, semicolons, or split sentences instead.\n\n"
    "Critical: If affected files are obviously unit test cases, consider that when deciding on severity.\n\n"
    "Critical: With the exception of extracting CVE identifiers when explicitly present: "
    'Do not invent any details. If it is not in the notes or SARIF metadata, write "Not provided in evidence".\n\n'
    "Critical: Evidence is verbatim. Do not paraphrase, reformat, normalize, or "
    '"clean up" file paths, line numbers, code, tool output, HTTP requests/responses, '
    "console output, or proof-of-concept code.\n\n"
    "Critical: Preserve ALL technical evidence from the notes and SARIF metadata, "
    "including file paths with line numbers, code snippets, HTTP requests/responses, "
    "console output, tool output, and proof-of-concept code. These details are essential "
    "for reproduction and client verification.\n\n"
    "Critical: Severity must follow the defined severity rubric only. If uncertain, "
    "choose the lower severity and justify using rubric language. Treat unit tests, "
    "behavior tests, and integration tests with lower severity or informational."
)


def _get_org_extra_instructions(org_id: str | None, adapter: StorageAdapter) -> str:
    """Return org-level LLM extra instructions, falling back to defaults."""
    if org_id:
        try:
            org = adapter.get_organization(org_id)
            if org and org.settings:
                settings = json.loads(org.settings)
                llm = settings.get("llm", {})
                ei = llm.get("extra_instructions")
                if ei is not None:
                    return ei
        except json.JSONDecodeError as e:
            log.debug("Org %s settings invalid JSON: %s", org_id, e)
        except Exception as e:
            log.debug("Could not load org extra instructions for %s: %s", org_id, e)
    return DEFAULT_EXTRA_INSTRUCTIONS


def _get_llm_extra_instructions(user_id: str, adapter: StorageAdapter, org_id: str | None = None) -> str:
    """Return LLM extra instructions: org settings > user field > default."""
    if org_id:
        return _get_org_extra_instructions(org_id, adapter)
    u = adapter.get_user_by_id(user_id)
    user_instructions = (getattr(u, "llm_extra_instructions", None) or "") if u else ""
    if user_instructions:
        return user_instructions
    if u:
        try:
            orgs = list(adapter.get_user_organizations(u.id))
            if orgs:
                return _get_org_extra_instructions(orgs[0].id, adapter)
        except Exception as e:
            log.debug("Could not get user org for extra instructions: %s", e)
    return DEFAULT_EXTRA_INSTRUCTIONS


from app.db.models import SYSTEM_ORG_ID


def _resolve_user_org_id(user, adapter) -> str:
    """Return the user's primary organization ID, falling back to the system org."""
    orgs = list(adapter.get_user_organizations(user.id))
    if orgs:
        return orgs[0].id
    return SYSTEM_ORG_ID


# Error codes for i18n (frontend maps to errors.llmProviderRequired etc.)
LLM_PROVIDER_REQUIRED = "llm_provider_required"
LLM_API_KEY_REQUIRED = "llm_api_key_required"
LLM_AUTH_FAILED = "llm_auth_failed"
LLM_CONNECTION_FAILED = "llm_connection_failed"
LLM_RATE_LIMIT = "llm_rate_limit"
LLM_GENERIC_FAILED = "llm_generic_failed"


def _llm_error_detail(code: str, message: str) -> dict:
    """Return detail dict with code for frontend i18n."""
    return {"code": code, "message": message}


def _require_llm_config(
    provider_override: str | None,
    user_api_key: str | None,
) -> None:
    """
    Validate LLM config before calling. Raises HTTPException(400) with code for i18n.
    Never leaks API keys or internal details.
    """
    if not provider_override or not str(provider_override).strip():
        raise HTTPException(
            status_code=400,
            detail=_llm_error_detail(
                LLM_PROVIDER_REQUIRED,
                "Please select an LLM provider in Settings (LLM Settings) before generating.",
            ),
        )
    provider = str(provider_override).strip().lower()
    if provider in ("ollama", "openai_compatible", "custom"):
        return  # These typically don't require a stored API key
    if not (user_api_key and user_api_key.strip()):
        raise HTTPException(
            status_code=400,
            detail=_llm_error_detail(
                LLM_API_KEY_REQUIRED,
                "Please add your API key for this provider in Settings → Profile.",
            ),
        )


def _llm_error_from_exception(exc: Exception) -> dict:
    """
    Map LLM exceptions to (code, message) for i18n. Never include API keys,
    stack traces, or internal error details.
    """
    err_str = str(exc).lower()
    if "auth" in err_str or "401" in err_str or ("invalid" in err_str and "key" in err_str):
        return _llm_error_detail(
            LLM_AUTH_FAILED,
            "API key for your LLM provider is invalid or expired. Please check Settings → Profile.",
        )
    if "connection" in err_str or "timeout" in err_str or "refused" in err_str:
        return _llm_error_detail(
            LLM_CONNECTION_FAILED,
            "Could not reach the LLM service. Check your connection and base URL in Settings.",
        )
    if "rate" in err_str or "429" in err_str:
        return _llm_error_detail(
            LLM_RATE_LIMIT,
            "LLM rate limit exceeded. Please try again in a few minutes.",
        )
    return _llm_error_detail(
        LLM_GENERIC_FAILED,
        "LLM request failed. Please check your provider and API key in Settings.",
    )


def _load_severity_criteria_from_org(org_id: str | None, adapter: StorageAdapter) -> Optional[Dict[str, str]]:
    """
    Load severity criteria from organization settings.
    Returns dict of severity definitions (Critical, High, Medium, Low, Informational), or None if not found or error.
    """
    if not org_id:
        return None
    try:
        org = adapter.get_organization(org_id)
        if not org or not org.severity_criteria:
            return None
        criteria = json.loads(org.severity_criteria)
        if criteria and isinstance(criteria, dict):
            # Validate that we have all 5 severity levels
            expected_levels = {"Critical", "High", "Medium", "Low", "Informational"}
            if expected_levels.issubset(criteria.keys()):
                log.info("Loaded %d severity definitions from org %s", len(criteria), org_id)
                return criteria
        return None
    except json.JSONDecodeError as e:
        log.debug("Org %s severity_criteria invalid JSON: %s", org_id, e)
        return None
    except Exception as e:
        log.debug("Could not load org severity criteria for %s: %s", org_id, e)
        return None


def _load_severity_criteria_from_template(template_name: str, adapter: StorageAdapter, organization_id: str | None = None) -> Optional[Dict[str, str]]:
    """
    Attempt to load severity criteria from specified master template in DB.
    Returns dict of severity definitions, or None if not found or error.
    Results are cached in memory based on content hash.
    """
    try:
        org_id = organization_id or adapter._get_default_org_id()
        template = adapter.get_master_template(template_name, org_id)
        if not template:
            return None
        criteria = extract_severity_criteria_from_bytes(template_name, template.content)
        if criteria:
            log.info("Loaded %d severity definitions from %s (cached)", len(criteria), template_name)
            return criteria
        return None
    except Exception as e:
        log.exception("Failed to extract severity criteria from %s: %s", template_name, e)
        return None


log = logging.getLogger("laze_report.api")

# Locale id (from frontend) -> language name for LLM instruction (non-vision only)
LOCALE_TO_LANGUAGE: Dict[str, str] = {
    "en": "English",
    "de": "German",
    "he": "Hebrew",
    "es-419": "Latin American Spanish",
    "zh-CN": "Simplified Chinese",
}

SEVERITY_LABELS: Dict[str, Dict[str, str]] = {
    "en": {
        "Critical": "Critical",
        "High": "High",
        "Medium": "Medium",
        "Low": "Low",
        "Informational": "Informational",
    },
    "de": {
        "Critical": "Kritisch",
        "High": "Hoch",
        "Medium": "Mittel",
        "Low": "Niedrig",
        "Informational": "Informativ",
    },
    "es-419": {
        "Critical": "Crítica",
        "High": "Alta",
        "Medium": "Media",
        "Low": "Baja",
        "Informational": "Informativa",
    },
    "he": {
        "Critical": "קריטי",
        "High": "גבוה",
        "Medium": "בינוני",
        "Low": "נמוך",
        "Informational": "מידע",
    },
    "zh-CN": {
        "Critical": "严重",
        "High": "高",
        "Medium": "中",
        "Low": "低",
        "Informational": "信息",
    },
}


def _localized_severity_label(severity: str, locale: Optional[str]) -> str:
    """Presentation-only localized severity label; storage remains canonical."""
    sev = str(severity or "").strip()
    if not sev:
        return ""
    labels = SEVERITY_LABELS.get((locale or "en").strip(), SEVERITY_LABELS["en"])
    return labels.get(sev, sev)


def _language_instruction(locale: Optional[str]) -> str:
    """Return system instruction to respond in user's preferred language, or empty string."""
    if not locale or not isinstance(locale, str):
        return ""
    lang_name = LOCALE_TO_LANGUAGE.get(locale.strip())
    if not lang_name:
        return ""
    return (
        f"Respond in the user's preferred language: {lang_name}. "
        "All content (summaries, narrative, recommendations) must be written in that language. "
        "Keep technical identifiers unchanged (CVE, CWE, OWASP codes, CVSS). "
    )


router = APIRouter()


class GenerateRequest(BaseModel):
    notes: str
    template: str
    use_ai: bool = True
    self_check: bool = False
    self_check_rounds: Optional[int] = 1
    vulnerability_title: Optional[str] = None
    severity_override: Optional[str] = None
    severity_reason: Optional[str] = None
    affected_roles: Optional[str] = None
    cvss_score: Optional[str] = None
    cvss_vector: Optional[str] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    llm_base_url: Optional[str] = None
    llm_timeout: Optional[float] = None
    sampling_params: Optional[Dict] = None
    locale: Optional[str] = None

    @field_validator('notes', 'template')
    @classmethod
    def validate_text(cls, v):
        return ValidatedString.notes_validator(v)
    
    @field_validator('vulnerability_title')
    @classmethod
    def validate_title(cls, v):
        if v is None:
            return v
        return sanitize_string(v, MAX_TITLE_LENGTH)
    
    @field_validator('self_check_rounds')
    @classmethod
    def validate_rounds(cls, v):
        if v is not None and (v < 1 or v > 5):
            raise ValueError("Self-check rounds must be between 1 and 5")
        return v
    
    @field_validator('severity_override')
    @classmethod
    def validate_severity(cls, v):
        if v is None:
            return v
        allowed = {'critical', 'high', 'medium', 'low', 'informational'}
        v_lower = str(v).strip().lower()
        if v_lower not in allowed:
            raise ValueError(f"Severity must be one of: {', '.join(allowed)}")
        return v_lower
    
    @field_validator('llm_provider')
    @classmethod
    def validate_provider(cls, v):
        if v is None:
            return v
        v_lower = str(v).strip().lower()
        if v_lower not in ALLOWED_PROVIDERS:
            raise ValueError(f"Provider must be one of: {', '.join(sorted(ALLOWED_PROVIDERS))}")
        return v_lower
    
    @field_validator('llm_base_url')
    @classmethod
    def validate_base_url(cls, v):
        return ValidatedString.url_validator(v)

    @field_validator('llm_timeout')
    @classmethod
    def validate_timeout(cls, v):
        if v is None:
            return v
        if v < 10 or v > 600:
            raise ValueError("Timeout must be between 10 and 600 seconds")
        return v


GenerateStructuredRequest = GenerateRequest


@router.post("/generate/structured")
def generate_structured(
    req: GenerateStructuredRequest,
    user=Depends(get_current_user),
    adapter=Depends(get_adapter),
):
    """Return structured vulnerability content (JSON) without generating DOCX. Useful for preview."""
    try:
        log.info("generate/structured: use_ai=%s, notes_len=%d", req.use_ai, len(req.notes or ""))
        settings_row = adapter.get_settings()
        template_name = user.default_master_template or settings_row.default_master_template or "master"
        user_org_id = _resolve_user_org_id(user, adapter)
        # Load severity criteria: org settings take priority, fall back to template
        severity_criteria = _load_severity_criteria_from_org(user_org_id, adapter)
        if not severity_criteria:
            severity_criteria = _load_severity_criteria_from_template(template_name, adapter, user_org_id)
        user_openai_key = user_api_key_for_provider(user, adapter, req.llm_provider)
        if req.use_ai:
            _require_llm_config(req.llm_provider, user_openai_key)
        extra_instructions = _get_llm_extra_instructions(user.id, adapter)
        structured, debug_info = structure_notes(
            notes=req.notes,
            template_markdown=req.template,
            use_ai=req.use_ai,
            llm_provider=req.llm_provider,
            llm_model=req.llm_model,
            llm_base_url=req.llm_base_url,
            llm_api_key_override=user_openai_key,
            org_context={
                "org_name": settings_row.org_name,
                "author_name": user.name or "",
                "voice_style": settings_row.voice_style,
            },
            self_check=req.self_check,
            self_check_rounds=req.self_check_rounds or 1,
            severity_criteria=severity_criteria,
            preferred_language=req.locale,
            extra_instructions=extra_instructions or None,
            timeout_override=req.llm_timeout,
            sampling_params=req.sampling_params,
        )
        # Set Found Date if missing (system-owned field; same as Burp/evidence flow)
        if not structured.get("Found Date"):
            from datetime import datetime
            structured["Found Date"] = datetime.utcnow().strftime("%Y-%m-%d")
        if req.severity_override:
            apply_severity_override(structured, req.severity_override, req.severity_reason)
        if "Severity" in structured:
            structured["Severity"] = canonicalize_severity_value(str(structured.get("Severity") or ""))

        overrides: Dict[str, str] = {}
        if req.severity_override:
            overrides["Severity"] = req.severity_override
        if req.cwe:
            overrides["CWE"] = req.cwe
        if req.owasp:
            overrides["OWASP"] = req.owasp
        if req.affected_roles:
            overrides["Affected Roles"] = req.affected_roles
        if req.cvss_score and req.cvss_vector:
            vec = req.cvss_vector
            if not vec.startswith("CVSS:3.1/"):
                vec = f"CVSS:3.1/{vec}"
            overrides["CVSS v3.1"] = f"{req.cvss_score} ({vec})"

        table_values = derive_table_values(structured, req.notes or "", overrides)
        for k, v in table_values.items():
            if not v:
                continue
            current = (structured.get(k) or "").strip()
            if not current:
                structured[k] = v
        log.info("generate/structured: source=%s", debug_info.get("source", "?"))

        # Build validated link list for preview (URLs + identifier-derived URLs)
        texts = [v for v in structured.values() if isinstance(v, str)]
        all_urls = []
        for t in texts:
            all_urls.extend(extract_urls(t))
            all_urls.extend(extract_identifier_urls(t))
        valid_urls = list(get_valid_urls(all_urls)) if all_urls else []

        # Map identifiers (CVE/CWE/OWASP) -> URL when validated
        identifier_links = {}
        token_re = re.compile(r"\bCVE-\d{4}-\d{4,7}\b|\bCWE-\d{1,5}\b|\bA\d{1,2}(?::20\d{2})?\b", re.I)
        for m in token_re.finditer("\n".join(texts)):
            token = m.group(0)
            url = identifier_to_url(token)
            if url and (url in valid_urls or is_canonical_url(url)):
                identifier_links[token.upper()] = url

        raw_http_snippets = extract_http_snippets(req.notes or "")
        return {
            "structured": structured,
            "debug": debug_info,
            "valid_urls": valid_urls,
            "identifier_links": identifier_links,
            "table_values": table_values,
            "display": {
                "severity_label": _localized_severity_label(str(structured.get("Severity") or ""), req.locale),
            },
            "raw_http_snippets": raw_http_snippets,
            "verification_log": debug_info.get("verification_log", []),
        }
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        log.exception("generate/structured failed: %s", type(e).__name__)
        raise HTTPException(status_code=400, detail=_llm_error_from_exception(e))


@router.post("/generate/docx")
def generate_docx(
    req: GenerateRequest,
    user=Depends(get_current_user),
    adapter=Depends(get_adapter),
):
    """Generate a DOCX report from pasted notes and template. Returns file download."""
    try:
        log.info("generate/docx: use_ai=%s", req.use_ai)
        settings_row = adapter.get_settings()
        template_name = user.default_master_template or settings_row.default_master_template or "master"
        user_org_id = _resolve_user_org_id(user, adapter)
        # Load severity criteria: org settings take priority, fall back to template
        severity_criteria = _load_severity_criteria_from_org(user_org_id, adapter)
        if not severity_criteria:
            severity_criteria = _load_severity_criteria_from_template(template_name, adapter, user_org_id)
        user_openai_key = user_api_key_for_provider(user, adapter, req.llm_provider)
        if req.use_ai:
            _require_llm_config(req.llm_provider, user_openai_key)
        extra_instructions = _get_llm_extra_instructions(user.id, adapter)
        structured, debug_info = structure_notes(
            notes=req.notes,
            template_markdown=req.template,
            use_ai=req.use_ai,
            llm_provider=req.llm_provider,
            llm_model=req.llm_model,
            llm_base_url=req.llm_base_url,
            llm_api_key_override=user_openai_key,
            org_context={
                "org_name": settings_row.org_name,
                "author_name": user.name or "",
                "voice_style": settings_row.voice_style,
            },
            self_check=req.self_check,
            self_check_rounds=req.self_check_rounds or 1,
            severity_criteria=severity_criteria,
            extra_instructions=extra_instructions or None,
            timeout_override=req.llm_timeout,
            sampling_params=req.sampling_params,
        )
        if not structured.get("Found Date"):
            from datetime import datetime
            structured["Found Date"] = datetime.utcnow().strftime("%Y-%m-%d")
        if req.severity_override:
            apply_severity_override(structured, req.severity_override, req.severity_reason)
        if "Severity" in structured:
            structured["Severity"] = canonicalize_severity_value(str(structured.get("Severity") or ""))
        overrides: Dict[str, str] = {}
        if req.severity_override:
            overrides["Severity"] = req.severity_override
        if req.cwe:
            overrides["CWE"] = req.cwe
        if req.owasp:
            overrides["OWASP"] = req.owasp
        if req.affected_roles:
            overrides["Affected Roles"] = req.affected_roles
        if req.cvss_score and req.cvss_vector:
            vec = req.cvss_vector
            if not vec.startswith("CVSS:3.1/"):
                vec = f"CVSS:3.1/{vec}"
            overrides["CVSS v3.1"] = f"{req.cvss_score} ({vec})"
        table_values = derive_table_values(structured, req.notes or "", overrides)
        for k, v in table_values.items():
            if not v:
                continue
            current = (structured.get(k) or "").strip()
            if not current:
                structured[k] = v
        log.info("generate/docx: source=%s", debug_info.get("source", "?"))
        raw_http_snippets = extract_http_snippets(req.notes or "")
        docx_buffer = build_docx(
            structured=structured,
            template=req.template,
            title=req.vulnerability_title or structured.get("title") or "",
            raw_http_snippets=raw_http_snippets,
            locale=req.locale,
        )
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        log.exception("generate/docx failed: %s", type(e).__name__)
        raise HTTPException(status_code=400, detail=_llm_error_from_exception(e))

    filename = "vulnerability_report.docx"
    if structured.get("title"):
        safe_title = "".join(c if c.isalnum() or c in " -_" else "_" for c in structured["title"])[:60]
        filename = f"{safe_title}.docx"

    return StreamingResponse(
        io.BytesIO(docx_buffer),
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


class GenerateSummariesRequest(BaseModel):
    report_id: str
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    llm_base_url: Optional[str] = None
    llm_timeout: Optional[float] = None
    sampling_params: Optional[Dict] = None
    locale: Optional[str] = None

    @field_validator('report_id')
    @classmethod
    def validate_report_id(cls, v):
        return ValidatedString.uuid_validator(v)
    
    @field_validator('llm_provider')
    @classmethod
    def validate_provider(cls, v):
        if v is None:
            return v
        v_lower = str(v).strip().lower()
        if v_lower not in ALLOWED_PROVIDERS:
            raise ValueError(f"Provider must be one of: {', '.join(sorted(ALLOWED_PROVIDERS))}")
        return v_lower
    
    @field_validator('llm_base_url')
    @classmethod
    def validate_base_url(cls, v):
        return ValidatedString.url_validator(v)

    @field_validator('llm_timeout')
    @classmethod
    def validate_timeout(cls, v):
        if v is None:
            return v
        if v < 10 or v > 600:
            raise ValueError("Timeout must be between 10 and 600 seconds")
        return v


@router.post("/generate/summaries")
def generate_summaries(
    req: GenerateSummariesRequest,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Generate executive, technical, and recommendations summaries from all findings in a report."""
    from app.services.llm import chat_completion
    import json as _json

    # Get report and check permissions first (404/403 before config validation)
    from app.services.rbac import can_view_report
    report = adapter.get_report(req.report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if not can_view_report(user, report, adapter):
        raise HTTPException(status_code=403, detail="Insufficient permissions to access this report")

    findings_raw = list(adapter.list_findings(req.report_id))
    if not findings_raw:
        raise HTTPException(status_code=400, detail="Report has no findings to summarize")

    user_openai_key = user_api_key_for_provider(user, adapter, req.llm_provider)
    _require_llm_config(req.llm_provider, user_openai_key)
    
    # Calculate deterministic severity distribution (policy first)
    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0
    }
    
    for f in findings_raw:
        try:
            content = _json.loads(f.content_json or "{}")
            sev = content.get("Severity", "").strip()
            # Normalize to canonical form
            sev_cap = sev.capitalize()
            if sev_cap in severity_counts:
                severity_counts[sev_cap] += 1
        except _json.JSONDecodeError as e:
            log.debug("Finding %s has invalid content_json: %s", f.id, e)
    
    # Determine highest actual severity present
    highest_severity = next(
        (sev for sev in ["Critical", "High", "Medium", "Low", "Informational"] 
         if severity_counts[sev] > 0),
        "Informational"
    )
    
    # Build severity constraint text
    severity_constraint = f"""
SEVERITY DISTRIBUTION (factual, do not deviate):
- Critical: {severity_counts['Critical']} finding(s)
- High: {severity_counts['High']} finding(s)
- Medium: {severity_counts['Medium']} finding(s)
- Low: {severity_counts['Low']} finding(s)
- Informational: {severity_counts['Informational']} finding(s)

Highest severity present: {highest_severity}

CRITICAL CONSTRAINT: Only reference severity levels that actually appear in the findings above (count > 0). Do not claim "critical vulnerabilities" or "critical findings" if the Critical count is 0. Do not exaggerate severity levels beyond what is documented.
""".strip()
    
    # Build a context string from all findings
    findings_context = []
    for f in findings_raw:
        try:
            content = _json.loads(f.content_json or "{}")
        except _json.JSONDecodeError as e:
            log.debug("Finding %s has invalid content_json: %s", f.id, e)
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
    lang_instruction = _language_instruction(req.locale)
    extra_instructions = _get_llm_extra_instructions(user.id, adapter)
    system_content = (lang_instruction or "").strip()
    if extra_instructions and extra_instructions.strip():
        system_content = (system_content + "\n\nAdditional instructions (apply to writing style and tone):\n" + extra_instructions.strip()).strip()
    summary_messages = [{"role": "system", "content": system_content}] if system_content else []

    def _run_chat(messages):
        return chat_completion(
            messages=messages,
            temperature=0.7,
            provider_override=req.llm_provider,
            model_override=req.llm_model,
            base_url_override=req.llm_base_url,
            api_key_override=user_openai_key,
            timeout_override=req.llm_timeout,
            sampling_params=req.sampling_params,
        ).strip()

    try:
        # Build a simplified context for executive summary (no jargon, business-focused)
        executive_context = []
        for f in findings_raw:
            try:
                content = _json.loads(f.content_json or "{}")
            except _json.JSONDecodeError as e:
                log.debug("Finding %s has invalid content_json: %s", f.id, e)
                content = {}

            # For executives: just title + simple impact statement
            finding_text = f.title
            if content.get("Severity"):
                sev = str(content.get("Severity", "")).strip().lower()
                impact_level = {
                    "critical": "immediate threat to operations",
                    "high": "significant risk to operations",
                    "medium": "moderate risk requiring action",
                    "low": "minor risk with long-term impact",
                    "informational": "best practice recommendation"
                }.get(sev, "requires attention")
                finding_text += f" ({impact_level})"
            executive_context.append(finding_text)

        executive_context_str = "\n- ".join(executive_context)

        # Generate executive summary
        executive_prompt = f"""Based on these vulnerability findings, write a concise executive summary (2-3 paragraphs) suitable for non-technical C-level decision-makers.

Focus on: (1) What business systems or operations are at risk, (2) Why this matters, (3) Prioritized action steps.

CRITICAL INSTRUCTIONS FOR EXECUTIVE SUMMARY:
- Avoid technical jargon, acronyms (CVE, CWE, OWASP, CVSS), and implementation details
- Translate any technical terms into simple business language
- No mention of specific tools, frameworks, or version numbers
- No references to line numbers, code snippets, or technical proofs
- Focus on the "so what?" - business impact, risk timeline, operational consequences
- Make it actionable: what should leadership do first?

{severity_constraint}

Findings (simplified for executives):
- {executive_context_str}

Executive Summary:"""
        executive_summary = _run_chat(summary_messages + [{"role": "user", "content": executive_prompt}])

        # Generate technical summary
        technical_prompt = f"""Based on these vulnerability findings, write a technical summary (2-3 paragraphs) for technical stakeholders. Focus on attack vectors, affected systems, and technical severity:

{severity_constraint}

{context}

Technical Summary:"""
        technical_summary = _run_chat(summary_messages + [{"role": "user", "content": technical_prompt}])

        # Generate recommendations summary
        recommendations_prompt = f"""Based on these vulnerability findings, write a summary of prioritized recommendations (2-3 paragraphs) with clear, actionable next steps.

Focus on: (1) What to fix first (highest priority), (2) Concrete actions clients should take, (3) Timeline/urgency for each action.

CRITICAL INSTRUCTIONS FOR RECOMMENDATIONS:
- Prioritize by actual risk/impact, not by severity label alone
- Be specific about WHO should fix it (developers, ops, security client, etc.)
- Include realistic timelines ("within 1 week", "before next release", etc.)
- Avoid jargon - explain remediation in plain language
- No technical implementation details - link to internal docs/tickets instead
- Each action should be something a non-technical person can understand or delegate

{severity_constraint}

{context}

Summary of Recommendations:"""
        recommendations_summary = _run_chat(summary_messages + [{"role": "user", "content": recommendations_prompt}])
    except HTTPException:
        raise
    except Exception as e:
        log.exception("LLM summaries failed: %s", type(e).__name__)
        raise HTTPException(status_code=400, detail=_llm_error_from_exception(e))

    return {
        "summary_executive": executive_summary,
        "summary_technical": technical_summary,
        "summary_recommendations": recommendations_summary,
    }


class ConsolidateFindingsRequest(BaseModel):
    report_id: str
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    llm_base_url: Optional[str] = None
    llm_timeout: Optional[float] = None
    sampling_params: Optional[Dict] = None
    locale: Optional[str] = None

    @field_validator('report_id')
    @classmethod
    def validate_report_id(cls, v):
        return ValidatedString.uuid_validator(v)

    @field_validator('llm_provider')
    @classmethod
    def validate_provider(cls, v):
        if v is None:
            return v
        v_lower = str(v).strip().lower()
        if v_lower not in ALLOWED_PROVIDERS:
            raise ValueError(f"Provider must be one of: {', '.join(sorted(ALLOWED_PROVIDERS))}")
        return v_lower

    @field_validator('llm_base_url')
    @classmethod
    def validate_base_url(cls, v):
        return ValidatedString.url_validator(v)

    @field_validator('llm_timeout')
    @classmethod
    def validate_timeout(cls, v):
        if v is None:
            return v
        if v < 10 or v > 600:
            raise ValueError("Timeout must be between 10 and 600 seconds")
        return v


def _strip_llm_markdown(text: str) -> str:
    """Strip markdown code fences from an LLM response."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = lines[1:] if lines[0].startswith("```") else lines
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)
    return text


@router.post("/generate/consolidate")
def consolidate_findings(
    request: Request,
    req: ConsolidateFindingsRequest,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Identify similar findings, merge them with AI, and overwrite with consolidated content.

    Uses a two-phase approach to avoid output-token limits on large reports:
    Phase 1 — sends titles only, asks LLM to return groups of similar IDs.
    Phase 2 — for each group, sends full content and asks LLM to merge them.
    """
    from app.services.llm import chat_completion
    import json as _json

    report = adapter.get_report(req.report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if not can_edit_report(user, report, adapter):
        raise HTTPException(status_code=403, detail="Insufficient permissions to edit this report")

    findings_raw = list(adapter.list_findings(req.report_id))
    if len(findings_raw) < 2:
        raise HTTPException(status_code=400, detail="Need at least 2 findings to consolidate")

    user_openai_key = user_api_key_for_provider(user, adapter, req.llm_provider)
    _require_llm_config(req.llm_provider, user_openai_key)
    extra_instructions = _get_llm_extra_instructions(user.id, adapter)
    findings_by_id = {f.id: f for f in findings_raw}

    llm_kwargs = dict(
        temperature=0.2,
        provider_override=req.llm_provider,
        model_override=req.llm_model,
        base_url_override=req.llm_base_url,
        api_key_override=user_openai_key,
        timeout_override=req.llm_timeout,
        sampling_params=req.sampling_params,
    )

    # ── Phase 1: Group by similarity (titles only) ─────────────────────────────
    titles_list = "\n".join(f"{f.id}: {f.title}" for f in findings_raw)
    phase1_prompt = f"""You are a security finding deduplicator.
Given the following list of pentest finding titles and IDs, identify groups of findings
that describe the same or very similar vulnerability (same class, same root cause).
Return ONLY a JSON array of arrays of IDs. Each inner array is one group of similar findings.
Only include groups with 2 or more findings. Do not include singletons. Return [] if nothing is similar.
Return valid JSON only — no markdown, no explanation.

Findings:
{titles_list}

JSON:"""

    try:
        phase1_response = chat_completion(
            messages=[{"role": "user", "content": phase1_prompt}],
            **llm_kwargs,
        )
    except HTTPException:
        raise
    except Exception as e:
        log.exception("LLM consolidate phase 1 failed: %s", type(e).__name__)
        raise HTTPException(status_code=400, detail=_llm_error_from_exception(e))

    phase1_response = _strip_llm_markdown(phase1_response)
    try:
        id_groups = _json.loads(phase1_response)
        if not isinstance(id_groups, list):
            raise ValueError("Expected a JSON array")
        # Validate structure: list of lists of strings
        id_groups = [
            [str(i) for i in grp]
            for grp in id_groups
            if isinstance(grp, list) and len(grp) >= 2
        ]
    except (ValueError, _json.JSONDecodeError) as e:
        log.exception("Consolidate phase 1 AI returned invalid JSON: %s", e)
        raise HTTPException(status_code=400, detail="AI returned invalid response. Please try again.")

    if not id_groups:
        return {"merged_count": 0, "message": "No similar findings to consolidate"}

    # ── Build system prompt for Phase 2 ────────────────────────────────────────
    lang_instruction = _language_instruction(req.locale)
    system_content = (lang_instruction or "").strip()
    if system_content:
        system_content += " Write narrative consolidated finding content (titles, summaries, justifications, remediation, etc.) in that language. Keep enum/table fields canonical and un-translated (Severity, CWE, OWASP, CVSS v3.1, Affected Roles). Keep CVE/CWE/OWASP/CVSS identifiers unchanged."
    else:
        system_content = "Write consolidated finding content (titles, summaries, justifications, remediation, etc.). Keep enum/table fields canonical and un-translated (Severity, CWE, OWASP, CVSS v3.1, Affected Roles). Keep CVE/CWE/OWASP/CVSS identifiers unchanged."
    if extra_instructions and extra_instructions.strip():
        system_content = system_content.rstrip() + "\n\nAdditional instructions (apply to writing style and tone):\n" + extra_instructions.strip()

    # ── Phase 2: Merge each group (full content, one call per group) ───────────
    ids_to_delete: list[str] = []
    merged_groups: list[dict] = []  # {ids, consolidated}

    for grp_ids in id_groups:
        # Resolve IDs to actual findings; skip any unknown IDs
        group_findings = [findings_by_id[fid] for fid in grp_ids if fid in findings_by_id]
        if len(group_findings) < 2:
            continue

        # Build per-group context with full content
        group_desc_parts = []
        for f in group_findings:
            try:
                content = _json.loads(f.content_json or "{}")
            except _json.JSONDecodeError:
                content = {}
            group_desc_parts.append(
                f"ID: {f.id}\nTitle: {f.title}\nContent:\n{_json.dumps(content, ensure_ascii=False)}"
            )
        group_context = "\n\n---\n\n".join(group_desc_parts)

        phase2_prompt = f"""You are a security report analyst. Merge the following similar vulnerability findings into ONE consolidated finding.

Rules:
- Merge the strongest severity, combine remediation steps, and unify the narrative.
- Preserve section keys: Finding Title, Severity, Vulnerability Summary, Justification, Rationale, Root Cause, Details, Remediation, Additional Notes, References, CVSS v3.1, CWE, OWASP, Affected Roles.
- Severity must be exactly one of: Critical, High, Medium, Low, Informational.
- Keep CWE/OWASP/CVSS values in canonical format.

Return valid JSON only, no markdown. Format:
{{
  "Finding Title": "Unified title",
  "Severity": "High",
  "Vulnerability Summary": "...",
  "Justification": "...",
  "Rationale": "...",
  "Root Cause": "...",
  "Details": "...",
  "Remediation": "...",
  "Additional Notes": "...",
  "References": "...",
  "CVSS v3.1": "...",
  "CWE": "...",
  "OWASP": "...",
  "Affected Roles": "..."
}}

Findings to merge:

{group_context}

JSON:"""

        try:
            phase2_response = chat_completion(
                messages=[
                    {"role": "system", "content": system_content},
                    {"role": "user", "content": phase2_prompt},
                ],
                **llm_kwargs,
            )
        except Exception as e:
            log.warning("LLM consolidate phase 2 failed for group %s: %s", grp_ids, e)
            continue  # skip this group, don't fail the whole operation

        phase2_response = _strip_llm_markdown(phase2_response)
        try:
            consolidated = _json.loads(phase2_response)
            if not isinstance(consolidated, dict):
                raise ValueError("Expected a JSON object")
        except (ValueError, _json.JSONDecodeError) as e:
            log.warning("Consolidate phase 2 invalid JSON for group %s: %s", grp_ids, e)
            continue  # skip this group gracefully

        merged_groups.append({"ids": [f.id for f in group_findings], "consolidated": consolidated})

    if not merged_groups:
        return {"merged_count": 0, "message": "No similar findings to consolidate"}

    # ── Apply merges to database ────────────────────────────────────────────────
    for grp in merged_groups:
        ids = grp["ids"]
        consolidated = grp["consolidated"]
        if "Severity" in consolidated:
            consolidated["Severity"] = canonicalize_severity_value(str(consolidated.get("Severity") or ""))
        keep_id = ids[0]
        keep_finding = findings_by_id[keep_id]
        content_json = _json.dumps(consolidated)
        title = consolidated.get("Finding Title") or consolidated.get("title") or keep_finding.title or ""
        adapter.update_finding(
            finding_id=keep_id,
            title=title,
            content_json=content_json,
            notes=keep_finding.notes or "",
            template=keep_finding.template or "",
        )
        org_id = report.organization_id or SYSTEM_ORG_ID
        log_update(adapter, org_id, user.id, "finding", keep_id, request, old_title=keep_finding.title, new_title=title)
        for aid in ids[1:]:
            if aid in findings_by_id:
                ids_to_delete.append(aid)

    for fid in ids_to_delete:
        finding = findings_by_id.get(fid)
        if finding:
            org_id = report.organization_id or SYSTEM_ORG_ID
            log_delete(adapter, org_id, user.id, "finding", fid, request, title=finding.title)
        adapter.delete_finding(fid)

    return {"merged_count": len(ids_to_delete), "message": f"Consolidated {len(ids_to_delete)} similar finding(s)"}
