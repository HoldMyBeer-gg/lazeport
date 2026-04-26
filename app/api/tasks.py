"""
API endpoints for background generation tasks.
Provides async enqueueing and status polling so the frontend
can fire-and-forget LLM calls and survive navigation/refresh.
"""
import json
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator

from app.services.auth import get_current_user
from app.services.rbac import can_edit_report, can_view_report
from app.services.field_extraction import user_api_key_for_provider
from app.services.llm import ALLOWED_PROVIDERS
from app.validation import ValidatedString
from app.db import get_adapter
from app.db.adapter import StorageAdapter

log = logging.getLogger("lazeport.api.tasks")
router = APIRouter()

# Tasks running longer than this are considered stale (worker crash, etc.)
STALE_THRESHOLD_MINUTES = 10


def _task_to_dict(task, include_result: bool = False) -> dict:
    """Serialize a GenerationTask to the API response shape."""
    status = task.status
    # Surface stale tasks so the frontend can show a timed-out style
    if (
        status == "running"
        and task.started_at
        and datetime.utcnow() - task.started_at > timedelta(minutes=STALE_THRESHOLD_MINUTES)
    ):
        status = "stale"

    try:
        progress_log = json.loads(task.progress_log or "[]")
    except (json.JSONDecodeError, Exception):
        progress_log = []

    d = {
        "id": task.id,
        "task_type": task.task_type,
        "title": task.title,
        "status": status,
        "report_id": task.report_id,
        "finding_id": task.finding_id,
        "current_step": task.current_step,
        "total_steps": task.total_steps,
        "progress_log": progress_log,
        "error": task.error or None,
        "created_at": task.created_at.isoformat() if task.created_at else None,
        "started_at": task.started_at.isoformat() if task.started_at else None,
        "finished_at": task.finished_at.isoformat() if task.finished_at else None,
    }
    if include_result:
        d["result_json"] = task.result_json or ""
    return d


# ── Enqueue: structured finding ─────────────────────────────────────────────

class EnqueueFindingRequest(BaseModel):
    report_id: str
    notes: str
    template: str
    finding_id: Optional[str] = None          # If set → regenerate existing (result stored only)
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    llm_base_url: Optional[str] = None
    llm_timeout: Optional[float] = None
    sampling_params: Optional[Dict] = None
    severity_criteria: Optional[Dict[str, str]] = None
    finding_metadata: Optional[Dict] = None
    locale: Optional[str] = None
    title_hint: Optional[str] = None          # Used for the task title shown in TaskBar

    @field_validator("report_id")
    @classmethod
    def validate_report_id(cls, v):
        return ValidatedString.uuid_validator(v)

    @field_validator("notes")
    @classmethod
    def validate_notes(cls, v):
        result = ValidatedString.notes_validator(v)
        if not result:
            raise ValueError("This field cannot be empty")
        return result

    @field_validator("template")
    @classmethod
    def validate_template(cls, v):
        if not v:
            return v  # template is optional (regeneration may not have one)
        return ValidatedString.notes_validator(v)

    @field_validator("llm_provider")
    @classmethod
    def validate_provider(cls, v):
        if v is None:
            return v
        v_lower = str(v).strip().lower()
        if v_lower not in ALLOWED_PROVIDERS:
            raise ValueError(f"Provider must be one of: {', '.join(sorted(ALLOWED_PROVIDERS))}")
        return v_lower

    @field_validator("llm_base_url")
    @classmethod
    def validate_base_url(cls, v):
        return ValidatedString.url_validator(v)

    @field_validator("llm_timeout")
    @classmethod
    def validate_timeout(cls, v):
        if v is None:
            return v
        if v < 10 or v > 600:
            raise ValueError("Timeout must be between 10 and 600 seconds")
        return v


@router.post("/generate/structured/async")
def enqueue_structured(
    req: EnqueueFindingRequest,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """
    Enqueue a background LLM finding generation task.
    Returns immediately with a task_id; poll GET /api/tasks/{task_id} for status.
    If finding_id is provided, this is a regeneration (result stored only; user must approve).
    """
    from app.api.generate import _require_llm_config, _resolve_user_org_id, _get_llm_extra_instructions
    from app.db.models import SYSTEM_ORG_ID
    from app.tasks.llm_generation import generate_finding_task, regenerate_finding_task, TOTAL_STEPS

    report = adapter.get_report(req.report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if not can_edit_report(user, report, adapter):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    user_api_key = user_api_key_for_provider(user, adapter, req.llm_provider)
    _require_llm_config(req.llm_provider, user_api_key)

    user_org_id = _resolve_user_org_id(user, adapter)
    settings_row = adapter.get_settings()
    org_context = {
        "org_name": settings_row.org_name or "",
        "author_name": user.name or "",
        "voice_style": settings_row.voice_style or "",
    }
    extra_instructions = _get_llm_extra_instructions(user.id, adapter, user_org_id)

    is_regen = bool(req.finding_id)
    task_type = "regenerate_finding" if is_regen else "generate_finding"

    # Build a human-readable title for the TaskBar
    hint = (req.title_hint or "").strip()
    if not hint and req.notes:
        hint = req.notes.strip()[:60]
    title = f"Regenerating: {hint}" if is_regen else f"Generating: {hint}"

    gt = adapter.create_generation_task(
        user_id=user.id,
        organization_id=user_org_id,
        report_id=req.report_id,
        task_type=task_type,
        title=title,
        total_steps=TOTAL_STEPS[task_type],
    )

    task_fn = regenerate_finding_task if is_regen else generate_finding_task
    kwargs = dict(
        generation_task_id=gt.id,
        notes=req.notes,
        template_markdown=req.template,
        report_id=req.report_id,
        organization_id=user_org_id,
        user_id=user.id,
        llm_provider=req.llm_provider,
        llm_model=req.llm_model,
        llm_base_url=req.llm_base_url,
        llm_api_key=user_api_key,
        llm_timeout=req.llm_timeout,
        sampling_params=req.sampling_params,
        org_context=org_context,
        extra_instructions=extra_instructions,
        severity_criteria=req.severity_criteria,
        finding_metadata=req.finding_metadata,
        locale=req.locale,
    )
    if is_regen:
        kwargs["finding_id"] = req.finding_id

    task_fn.delay(**kwargs)
    log.info("Enqueued %s task %s for user %s, report %s", task_type, gt.id, user.id, req.report_id)
    return {"task_id": gt.id, "status": "pending"}


# ── Enqueue: summaries ───────────────────────────────────────────────────────

class EnqueueSummariesRequest(BaseModel):
    report_id: str
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    llm_base_url: Optional[str] = None
    llm_timeout: Optional[float] = None
    sampling_params: Optional[Dict] = None
    locale: Optional[str] = None

    @field_validator("report_id")
    @classmethod
    def validate_report_id(cls, v):
        return ValidatedString.uuid_validator(v)

    @field_validator("llm_provider")
    @classmethod
    def validate_provider(cls, v):
        if v is None:
            return v
        v_lower = str(v).strip().lower()
        if v_lower not in ALLOWED_PROVIDERS:
            raise ValueError(f"Provider must be one of: {', '.join(sorted(ALLOWED_PROVIDERS))}")
        return v_lower

    @field_validator("llm_base_url")
    @classmethod
    def validate_base_url(cls, v):
        return ValidatedString.url_validator(v)

    @field_validator("llm_timeout")
    @classmethod
    def validate_timeout(cls, v):
        if v is None:
            return v
        if v < 10 or v > 600:
            raise ValueError("Timeout must be between 10 and 600 seconds")
        return v


@router.post("/generate/summaries/async")
def enqueue_summaries(
    req: EnqueueSummariesRequest,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """
    Enqueue background summary generation. Result is stored for review; report summaries are NOT
    overwritten until the user approves via the review modal.
    """
    from app.api.generate import _require_llm_config, _resolve_user_org_id, _get_llm_extra_instructions
    from app.tasks.llm_generation import generate_summaries_task, TOTAL_STEPS

    report = adapter.get_report(req.report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if not can_view_report(user, report, adapter):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    user_api_key = user_api_key_for_provider(user, adapter, req.llm_provider)
    _require_llm_config(req.llm_provider, user_api_key)

    user_org_id = _resolve_user_org_id(user, adapter)
    extra_instructions = _get_llm_extra_instructions(user.id, adapter, user_org_id)

    gt = adapter.create_generation_task(
        user_id=user.id,
        organization_id=user_org_id,
        report_id=req.report_id,
        task_type="generate_summaries",
        title="Generating report summaries...",
        total_steps=TOTAL_STEPS["generate_summaries"],
    )

    generate_summaries_task.delay(
        generation_task_id=gt.id,
        report_id=req.report_id,
        user_id=user.id,
        llm_provider=req.llm_provider,
        llm_model=req.llm_model,
        llm_base_url=req.llm_base_url,
        llm_api_key=user_api_key,
        llm_timeout=req.llm_timeout,
        sampling_params=req.sampling_params,
        locale=req.locale,
        extra_instructions=extra_instructions,
    )
    log.info("Enqueued generate_summaries task %s for user %s, report %s", gt.id, user.id, req.report_id)
    return {"task_id": gt.id, "status": "pending"}


# ── Enqueue: validation guidance ──────────────────────────────────────────────

class EnqueueValidationRequest(BaseModel):
    report_id: str
    finding_id: str
    regenerate: bool = False
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    llm_base_url: Optional[str] = None
    llm_timeout: Optional[float] = None
    title_hint: Optional[str] = None

    @field_validator("report_id")
    @classmethod
    def validate_report_id(cls, v):
        return ValidatedString.uuid_validator(v)

    @field_validator("finding_id")
    @classmethod
    def validate_finding_id(cls, v):
        return ValidatedString.uuid_validator(v)

    @field_validator("llm_provider")
    @classmethod
    def validate_provider(cls, v):
        if v is None:
            return v
        v_lower = str(v).strip().lower()
        if v_lower not in ALLOWED_PROVIDERS:
            raise ValueError(f"Provider must be one of: {', '.join(sorted(ALLOWED_PROVIDERS))}")
        return v_lower

    @field_validator("llm_base_url")
    @classmethod
    def validate_base_url(cls, v):
        return ValidatedString.url_validator(v)

    @field_validator("llm_timeout")
    @classmethod
    def validate_timeout(cls, v):
        if v is None:
            return v
        if v < 10 or v > 600:
            raise ValueError("Timeout must be between 10 and 600 seconds")
        return v


@router.post("/generate/validation-guidance/async")
def enqueue_validation(
    req: EnqueueValidationRequest,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """
    Enqueue background validation guidance generation for a single finding.
    Auto-saves guidance to finding.validation_guidance on completion.
    """
    from app.api.generate import _require_llm_config, _resolve_user_org_id
    from app.tasks.llm_generation import validate_guidance_task, TOTAL_STEPS

    report = adapter.get_report(req.report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if not can_view_report(user, report, adapter):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    finding = adapter.get_finding(req.finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if finding.report_id != req.report_id:
        raise HTTPException(status_code=400, detail="Finding does not belong to this report")

    user_api_key = user_api_key_for_provider(user, adapter, req.llm_provider)
    _require_llm_config(req.llm_provider, user_api_key)

    user_org_id = _resolve_user_org_id(user, adapter)

    hint = (req.title_hint or finding.title or "").strip()[:60]
    title = f"Validating: {hint}" if hint else "Validating finding..."

    gt = adapter.create_generation_task(
        user_id=user.id,
        organization_id=user_org_id,
        report_id=req.report_id,
        task_type="validate_guidance",
        title=title,
        total_steps=TOTAL_STEPS["validate_guidance"],
    )

    validate_guidance_task.delay(
        generation_task_id=gt.id,
        finding_id=req.finding_id,
        user_id=user.id,
        organization_id=user_org_id,
        report_id=req.report_id,
        llm_provider=req.llm_provider,
        llm_model=req.llm_model,
        llm_base_url=req.llm_base_url,
        llm_api_key=user_api_key,
        llm_timeout=req.llm_timeout,
        regenerate=req.regenerate,
    )
    log.info("Enqueued validate_guidance task %s for user %s, finding %s", gt.id, user.id, req.finding_id)
    return {"task_id": gt.id, "status": "pending"}


class EnqueueBulkValidationRequest(BaseModel):
    report_id: str
    finding_ids: list[str]
    regenerate: bool = False
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    llm_base_url: Optional[str] = None
    llm_timeout: Optional[float] = None

    @field_validator("report_id")
    @classmethod
    def validate_report_id(cls, v):
        return ValidatedString.uuid_validator(v)

    @field_validator("finding_ids")
    @classmethod
    def validate_finding_ids(cls, v):
        if not v:
            raise ValueError("finding_ids must not be empty")
        if len(v) > 50:
            raise ValueError("Maximum 50 findings per bulk request")
        return [ValidatedString.uuid_validator(fid) for fid in v]

    @field_validator("llm_provider")
    @classmethod
    def validate_provider(cls, v):
        if v is None:
            return v
        v_lower = str(v).strip().lower()
        if v_lower not in ALLOWED_PROVIDERS:
            raise ValueError(f"Provider must be one of: {', '.join(sorted(ALLOWED_PROVIDERS))}")
        return v_lower

    @field_validator("llm_base_url")
    @classmethod
    def validate_base_url(cls, v):
        return ValidatedString.url_validator(v)

    @field_validator("llm_timeout")
    @classmethod
    def validate_timeout(cls, v):
        if v is None:
            return v
        if v < 10 or v > 600:
            raise ValueError("Timeout must be between 10 and 600 seconds")
        return v


@router.post("/generate/validation-guidance/bulk/async")
def enqueue_bulk_validation(
    req: EnqueueBulkValidationRequest,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """
    Enqueue validation guidance for multiple findings in one request.
    Creates one Celery task per finding. Returns list of task_ids.
    """
    from app.api.generate import _require_llm_config, _resolve_user_org_id
    from app.tasks.llm_generation import validate_guidance_task, TOTAL_STEPS

    report = adapter.get_report(req.report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if not can_view_report(user, report, adapter):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    user_api_key = user_api_key_for_provider(user, adapter, req.llm_provider)
    _require_llm_config(req.llm_provider, user_api_key)

    user_org_id = _resolve_user_org_id(user, adapter)

    task_ids = []
    for fid in req.finding_ids:
        finding = adapter.get_finding(fid)
        if not finding or finding.report_id != req.report_id:
            log.warning("Skipping invalid finding %s in bulk validation for report %s", fid, req.report_id)
            continue

        hint = (finding.title or "").strip()[:60]
        title = f"Validating: {hint}" if hint else "Validating finding..."

        gt = adapter.create_generation_task(
            user_id=user.id,
            organization_id=user_org_id,
            report_id=req.report_id,
            task_type="validate_guidance",
            title=title,
            total_steps=TOTAL_STEPS["validate_guidance"],
        )

        validate_guidance_task.delay(
            generation_task_id=gt.id,
            finding_id=fid,
            user_id=user.id,
            organization_id=user_org_id,
            report_id=req.report_id,
            llm_provider=req.llm_provider,
            llm_model=req.llm_model,
            llm_base_url=req.llm_base_url,
            llm_api_key=user_api_key,
            llm_timeout=req.llm_timeout,
            regenerate=req.regenerate,
        )
        task_ids.append(gt.id)

    log.info("Enqueued %d validate_guidance tasks for user %s, report %s", len(task_ids), user.id, req.report_id)
    return {"task_ids": task_ids, "status": "pending"}


# ── Enqueue: vision extraction ───────────────────────────────────────────────

class EnqueueVisionRequest(BaseModel):
    image_base64: str
    image_mime_type: str = "image/png"
    prompt: Optional[str] = None
    vision_model: Optional[str] = None
    provider: Optional[str] = None
    base_url: Optional[str] = None
    llm_timeout: Optional[float] = None
    sampling_params: Optional[Dict] = None
    report_id: Optional[str] = None

    @field_validator("image_base64")
    @classmethod
    def validate_image(cls, v):
        if not v or len(v) < 50:
            raise ValueError("Invalid image data")
        if not all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in v):
            raise ValueError("Invalid base64 encoding")
        return v


@router.post("/vision/extract-text/async")
def enqueue_vision(
    req: EnqueueVisionRequest,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Enqueue background vision extraction. Result stored in task; frontend inserts text on completion."""
    from app.api.generate import _require_llm_config, _resolve_user_org_id
    from app.tasks.llm_generation import vision_extraction_task, TOTAL_STEPS

    user_api_key = user_api_key_for_provider(user, adapter, req.provider)
    _require_llm_config(req.provider, user_api_key)

    user_org_id = _resolve_user_org_id(user, adapter)
    model = req.vision_model or "gpt-4o-mini"

    gt = adapter.create_generation_task(
        user_id=user.id,
        organization_id=user_org_id,
        report_id=req.report_id,
        task_type="vision_extraction",
        title=f"Extracting image text ({model})...",
        total_steps=TOTAL_STEPS["vision_extraction"],
    )

    vision_extraction_task.delay(
        generation_task_id=gt.id,
        image_base64=req.image_base64,
        image_mime_type=req.image_mime_type,
        prompt=req.prompt,
        llm_provider=req.provider,
        llm_model=model,
        llm_base_url=req.base_url,
        llm_api_key=user_api_key,
        llm_timeout=req.llm_timeout,
        sampling_params=req.sampling_params,
    )
    log.info("Enqueued vision_extraction task %s for user %s", gt.id, user.id)
    return {"task_id": gt.id, "status": "pending"}


# ── Poll: list & get ─────────────────────────────────────────────────────────

@router.get("/tasks")
def list_tasks(
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """
    Return up to 50 most recent generation tasks for the authenticated user.
    Does not include result_json (keep polling payloads small).
    """
    tasks = list(adapter.list_generation_tasks(user.id, limit=50))
    return {"tasks": [_task_to_dict(t, include_result=False) for t in tasks]}


@router.get("/tasks/{task_id}")
def get_task(
    task_id: str,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Return full task including result_json. Only the owning user can access their tasks."""
    task = adapter.get_generation_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.user_id != user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    return _task_to_dict(task, include_result=True)


@router.delete("/tasks/{task_id}", status_code=204)
def cancel_task(
    task_id: str,
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """
    Cancel a task. Marks status as 'cancelled' in DB.
    Best-effort Celery revoke is attempted (may not interrupt a blocking LLM call).
    """
    task = adapter.get_generation_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.user_id != user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    if task.status in ("completed", "failed", "cancelled"):
        return  # Already terminal; no-op

    adapter.update_generation_task(task_id, status="cancelled", finished_at=datetime.utcnow())

    # Best-effort: try to revoke the Celery task (won't interrupt a blocking LLM call)
    if task.celery_task_id:
        try:
            from app.celery_app import app as celery_app
            celery_app.control.revoke(task.celery_task_id, terminate=True)
        except Exception as e:
            log.warning("Could not revoke Celery task %s: %s", task.celery_task_id, e)

    log.info("Task %s cancelled by user %s", task_id, user.id)
