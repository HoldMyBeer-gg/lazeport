from fastapi import APIRouter, Depends, HTTPException
from typing import List
from pydantic import BaseModel, field_validator

from app.db import get_adapter, models
from app.db.adapter import StorageAdapter
from app.services.auth import get_current_user
from app.services.rbac import can_view_report, can_access_finding
from app.services.sarif import findings_to_sarif

router = APIRouter()

MAX_EXPORT_FINDING_IDS = 500


class FindingsExportRequest(BaseModel):
    finding_ids: List[str]

    @field_validator("finding_ids")
    @classmethod
    def validate_finding_ids(cls, v):
        if not v:
            raise ValueError("finding_ids must not be empty")
        if len(v) > MAX_EXPORT_FINDING_IDS:
            raise ValueError(f"Cannot export more than {MAX_EXPORT_FINDING_IDS} findings at once")
        return v

@router.get("/api/export/findings/{finding_id}/sarif")
def export_finding_sarif(
    finding_id: str,
    user: models.User = Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Export a single finding in SARIF format."""
    finding = adapter.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    if not can_access_finding(user, finding, adapter):
        raise HTTPException(status_code=403, detail="Forbidden")
    return findings_to_sarif([finding])

@router.post("/api/export/findings/sarif")
def export_multiple_findings_sarif(
    payload: FindingsExportRequest,
    user: models.User = Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Export multiple findings in SARIF format."""
    all_findings = adapter.get_findings_by_ids(payload.finding_ids)
    findings = [f for f in all_findings if can_access_finding(user, f, adapter)]
    return findings_to_sarif(findings)

@router.get("/api/export/reports/{report_id}/sarif")
def export_report_sarif(
    report_id: str,
    user: models.User = Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """Export an entire report in SARIF format."""
    import json as _json
    
    report = adapter.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if not can_view_report(user, report, adapter):
        raise HTTPException(status_code=403, detail="Forbidden")
    
    findings_raw = adapter.list_findings(report_id)
    
    # Filter out False Positive findings
    findings = []
    for f in findings_raw:
        try:
            content = _json.loads(f.content_json or "{}")
        except Exception:
            content = {}
        
        confidence = content.get("Confidence", "").strip()
        if confidence == "False Positive":
            continue
        
        findings.append(f)
    
    return findings_to_sarif(findings, report_name=report.name)
