"""List and serve templates from the templates/ directory."""
import re
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse

from app.config import settings
from app.db import get_adapter
from app.db.adapter import StorageAdapter
from app.services.auth import get_current_user

router = APIRouter()

# Resolve templates dir: relative to project root or absolute
ROOT = Path(__file__).resolve().parent.parent.parent
TEMPLATES_DIR = Path(settings.templates_dir) if Path(settings.templates_dir).is_absolute() else ROOT / settings.templates_dir

# Allowlist: only safe filename chars (no ., /, \ to prevent traversal)
_TEMPLATE_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


@router.get("/templates", response_model=list[str])
def list_templates(_user=Depends(get_current_user)):
    """List template names (filenames without extension) from the templates directory."""
    if not TEMPLATES_DIR.exists():
        return []
    names = []
    for f in TEMPLATES_DIR.iterdir():
        if f.is_file() and f.suffix.lower() in (".html", ".htm", ".md", ".markdown", ".txt"):
            names.append(f.stem)
    return sorted(names)


@router.get("/master-templates", response_model=list[str])
def list_master_templates(
    user=Depends(get_current_user),
    adapter: StorageAdapter = Depends(get_adapter),
):
    """List master DOCX templates from the database."""
    # Get user's primary organization (first org they're a member of)
    orgs = list(adapter.get_user_organizations(user.id))
    org_id = orgs[0].id if orgs else adapter.ensure_system_org()
    templates = adapter.list_master_templates(org_id)
    return sorted([t.name for t in templates])


@router.get("/templates/{name}", response_class=PlainTextResponse)
def get_template(name: str, _user=Depends(get_current_user)):
    """Return the raw template content by name (e.g. default -> templates/default.html)."""
    if not name or not _TEMPLATE_NAME_RE.fullmatch(name):
        raise HTTPException(status_code=400, detail="Invalid template name")
    templates_dir = TEMPLATES_DIR.resolve()
    for ext in (".html", ".htm", ".md", ".markdown", ".txt"):
        path = (templates_dir / f"{name}{ext}").resolve()
        try:
            path.relative_to(templates_dir)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid template name")
        if path.is_file():
            return path.read_text(encoding="utf-8", errors="replace")
    raise HTTPException(status_code=404, detail=f"Template '{name}' not found")
