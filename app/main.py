"""
Lazeport - Paste messy pentest notes, get structured vuln write-ups and DOCX reports.
"""
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from app.config import settings

logging.basicConfig(
    level=getattr(logging, settings.log_level, logging.INFO),
    format="[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("laze_report")

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from app.middleware.security import SecurityHeadersMiddleware
from app.middleware.csrf import CSRFMiddleware
from app.middleware.rate_limit import APIRateLimitMiddleware
from app.middleware.docs_auth import DocsAuthMiddleware

_RUNNING_UNDER_PYTEST = "pytest" in __import__("sys").modules

from app.api import generate, templates
from app.api import providers as providers_api
from app.api import auth as auth_api
from app.api import admin as admin_api
from app.api import organizations as orgs_api
from app.api import export as export_api
from app.api import vision as vision_api
from app.api import findings as findings_api
from app.api import tasks as tasks_api
from app.db import get_adapter
from app.services.auth import ensure_bootstrap_admin, require_system_admin
from fastapi import Depends


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: init DB, provision templates, seed demo data, bootstrap admin if auth enabled."""
    adapter = get_adapter()
    adapter.init()
    _provision_master_templates(adapter)
    _seed_demo_data(adapter)
    if settings.auth_enabled:
        admin_password = ensure_bootstrap_admin(adapter)
        if admin_password:
            pw_file = Path("data/.admin_password")
            pw_file.parent.mkdir(parents=True, exist_ok=True)
            pw_file.write_text(f"ADMIN_PASSWORD={admin_password}\n")
            try:
                pw_file.chmod(0o600)
            except PermissionError:
                log.warning("chmod 600 failed for %s (filesystem may not support POSIX permissions)", pw_file)
            banner = (
                "\n"
                "============================================================\n"
                "  LAZEPORT FIRST-RUN: bootstrap admin account created\n"
                "------------------------------------------------------------\n"
                "  email:    admin@local.domain\n"
                f"  password: {admin_password}\n"
                "------------------------------------------------------------\n"
                "  This password is shown ONCE. Also saved to:\n"
                "    data/.admin_password  (chmod 600)\n"
                "  Log in and change it immediately.\n"
                "============================================================\n"
            )
            print(banner, flush=True)
            log.info("Bootstrap admin credentials created (see stdout banner; also at data/.admin_password)")
    from app.config import Settings
    if settings.session_secret_key == Settings._DEFAULT_SESSION_SECRET:
        log.warning("SESSION_SECRET_KEY is using the default value - set a strong random secret in production!")
    if settings.app_secret_key == Settings._DEFAULT_APP_SECRET:
        log.warning("APP_SECRET_KEY is using the default value - set a strong random secret in production!")
    yield
    # Shutdown: nothing to tear down today


app = FastAPI(
    title="Lazeport API",
    description="""
## 🔒 Secure Penetration Testing Reporting Platform

Transform raw pentest notes into professional, structured vulnerability reports with AI assistance.

### Features
- 🤖 AI-powered finding generation with self-verification
- 📄 Professional DOCX report generation
- 🎨 Customizable templates (Finding + Master DOCX)
- 🔗 Jira integration for ticket creation
- 🏢 Multi-tenant organization support
- 👥 Role-based access control (RBAC)
- 📊 Executive/Technical/Recommendations summaries
- 🔐 Enterprise-grade security (CSRF, XSS, input validation)

### Authentication
Most endpoints require authentication. Use `/auth/login/local` with admin credentials.

### Security
- CSRF protection via `X-CSRF-Token` header (required for POST/PUT/DELETE/PATCH)
- All inputs validated and sanitized
- Organization-level data isolation
- Comprehensive audit logging

### API Documentation
- **Swagger UI**: [/docs](/docs) (interactive)
- **ReDoc**: [/redoc](/redoc) (reference)
- **OpenAPI JSON**: [/openapi.json](/openapi.json) (spec)
    """,
    version="1.0.0",
    contact={
        "name": "Lazeport",
        "url": "https://github.com/yourusername/lazeport",
    },
    license_info={
        "name": "MIT",
    },
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# DocsAuth must run after SessionMiddleware so it can read request.scope["session"].
# In Starlette, last-added runs first; so add DocsAuth before Session.
app.add_middleware(DocsAuthMiddleware)
app.add_middleware(CSRFMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(APIRateLimitMiddleware, enabled=not _RUNNING_UNDER_PYTEST and not os.getenv("RATE_LIMIT_DISABLED"))
# Session after RateLimit so RateLimit can exempt authenticated users (scope["session"]).
app.add_middleware(SessionMiddleware, secret_key=settings.session_secret_key, max_age=settings.session_timeout_minutes * 60)

app.include_router(generate.router, prefix="/api", tags=["generate"])
app.include_router(templates.router, prefix="/api", tags=["templates"])
app.include_router(providers_api.router, prefix="/api", tags=["providers"])
app.include_router(auth_api.router, tags=["auth"])
app.include_router(admin_api.router, prefix="/api/admin", tags=["admin"])
app.include_router(orgs_api.router, prefix="/api", tags=["organizations"])
app.include_router(export_api.router, tags=["export"])
app.include_router(vision_api.router, tags=["vision"])
app.include_router(findings_api.router, tags=["findings"])
app.include_router(tasks_api.router, prefix="/api", tags=["tasks"])


def _load_factory_master_template() -> bytes | None:
    """Load the factory default master.docx from disk, or None if missing."""
    from pathlib import Path
    template_path = Path(__file__).parent.parent / "templates" / "master.docx"
    if template_path.exists():
        return template_path.read_bytes()
    log.warning("templates/master.docx not found - no factory default master template available")
    return None


def _provision_master_templates(adapter):
    """
    Ensure every organization has its own 'master' template.
    Copies the factory default from disk for any org that doesn't have one yet.
    """
    try:
        factory_content = _load_factory_master_template()
        if not factory_content:
            return

        orgs = adapter.list_organizations()
        for org in orgs:
            existing = adapter.get_master_template("master", org.id)
            if not existing:
                adapter.create_master_template("master", factory_content, organization_id=org.id)
                log.info("Provisioned default master.docx for org %s (%s)", org.slug, org.id)

    except Exception as e:
        log.exception("Failed to provision master templates: %s", e)


def _seed_demo_data(adapter):
    """Seed data on first boot. Normal mode: just ensure org exists (clean workspace). Demo mode (DEMO_MODE=1): rich data for Trends - 6 clients, 4 apps, 15+ reports, 80+ findings with varied severities/dates and tags."""
    import json as _json
    from datetime import timedelta
    import random as _rand

    try:
        existing_clients = list(adapter.list_clients())
        if existing_clients:
            return  # Already seeded

        org_id = adapter.ensure_system_org()

        if not settings.demo_mode:
            log.info("Normal mode - clean workspace (no demo data)")
            return

        # Demo mode: rich seed data
        log.info("DEMO MODE - seeding rich sample data for Trends...")
        _rand.seed(42)  # deterministic for reproducibility
        from datetime import datetime as _dt

        # Teams
        client_names = ["Team ACS", "Team Payments", "Team CRM", "Team Video", "Team IAM", "Team Core"]
        client_objs = [adapter.create_client(name=n, organization_id=org_id) for n in client_names]
        client_map = {t.name: t for t in client_objs}
        log.info("Seeded %d clients", len(client_objs))

        # Applications
        app_defs = [
            ("Public Web", "web"),
            ("Public API", "api"),
            ("Mobile App", "ios"),
            ("Firmware", "hardware"),
        ]
        app_objs = [adapter.create_application(name=n, type=t, organization_id=org_id) for n, t in app_defs]
        app_map = {a.name: a for a in app_objs}
        log.info("Seeded %d applications", len(app_objs))

        # Tags
        tag_names = [
            "OWASP Top 10", "PCI DSS", "Authentication", "Injection",
            "Config", "API Security", "Crypto", "PII", "Rate Limiting", "Firmware",
        ]
        tag_objs = [adapter.create_tag(org_id, name) for name in tag_names]
        tag_map = {t.name: t for t in tag_objs}
        log.info("Seeded %d tags", len(tag_objs))

        # Large vulnerability template pool (~40 unique vulns)
        vuln_templates = [
            # Critical (8)
            ("SQL Injection in login form", "Critical", "CWE-89", ["OWASP Top 10", "Injection"]),
            ("Auth bypass via mis-scoped JWT", "Critical", "CWE-287", ["Authentication", "OWASP Top 10"]),
            ("Broken Authentication on /api/v2/token", "Critical", "CWE-287", ["Authentication", "API Security"]),
            ("Insecure deserialization in session handler", "Critical", "CWE-502", ["OWASP Top 10"]),
            ("Remote Code Execution via file upload", "Critical", "CWE-434", ["OWASP Top 10", "API Security"]),
            ("LDAP Injection in user search", "Critical", "CWE-90", ["Injection", "Authentication"]),
            ("XML External Entity (XXE) processing", "Critical", "CWE-611", ["OWASP Top 10", "Injection"]),
            ("Privilege escalation via IDOR", "Critical", "CWE-639", ["OWASP Top 10", "Authentication"]),
            # High (10)
            ("Rate limit missing on login", "High", "CWE-307", ["Rate Limiting", "Authentication"]),
            ("Cross-Site Scripting (XSS) in Search", "High", "CWE-79", ["OWASP Top 10", "Injection"]),
            ("SSRF via URL fetch", "High", "CWE-918", ["OWASP Top 10", "API Security"]),
            ("Sensitive data in logs", "High", "CWE-532", ["PII", "Config"]),
            ("Path traversal in file download", "High", "CWE-22", ["OWASP Top 10"]),
            ("Weak TLS cipher suites", "High", "CWE-326", ["Crypto", "Config"]),
            ("JWT secret key brute-forceable", "High", "CWE-798", ["Crypto", "Authentication"]),
            ("Mass assignment on user profile", "High", "CWE-915", ["API Security", "OWASP Top 10"]),
            ("Stored XSS in comments field", "High", "CWE-79", ["OWASP Top 10", "Injection"]),
            ("Insecure direct object reference (IDOR)", "High", "CWE-639", ["OWASP Top 10"]),
            # Medium (10)
            ("CORS misconfig on admin", "Medium", "CWE-942", ["Config", "API Security"]),
            ("Missing anti-CSRF tokens", "Medium", "CWE-352", ["OWASP Top 10"]),
            ("Open redirect in OAuth callback", "Medium", "CWE-601", ["Authentication"]),
            ("Exposed stack trace in error response", "Medium", "CWE-209", ["Config"]),
            ("Session fixation after login", "Medium", "CWE-384", ["Authentication"]),
            ("Hardcoded API key in firmware image", "Medium", "CWE-798", ["Firmware", "Crypto"]),
            ("Clickjacking on payment page", "Medium", "CWE-1021", ["Config", "PCI DSS"]),
            ("Insufficient logging of auth events", "Medium", "CWE-778", ["Config", "Authentication"]),
            ("HTTP request smuggling", "Medium", "CWE-444", ["API Security"]),
            ("GraphQL introspection enabled in prod", "Medium", "CWE-200", ["API Security", "Config"]),
            # Low (8)
            ("Verbose server headers", "Low", "CWE-200", ["Config"]),
            ("Missing Content-Security-Policy header", "Low", "CWE-693", ["Config"]),
            ("Cookie without Secure flag", "Low", "CWE-614", ["Config"]),
            ("X-Frame-Options header missing", "Low", "CWE-1021", ["Config"]),
            ("Outdated jQuery library", "Low", "CWE-1104", ["Config"]),
            ("Missing X-Content-Type-Options", "Low", "CWE-693", ["Config"]),
            ("Password complexity not enforced", "Low", "CWE-521", ["Authentication"]),
            ("Auto-complete enabled on password field", "Low", "CWE-200", ["Config"]),
            # Informational (4)
            ("DNS zone transfer allowed", "Informational", "CWE-200", ["Config"]),
            ("HTTP methods TRACE/OPTIONS enabled", "Informational", "CWE-200", ["Config"]),
            ("Server software version disclosed", "Informational", "CWE-200", ["Config"]),
            ("HSTS max-age below recommended", "Informational", "CWE-693", ["Config"]),
        ]

        cvss_map = {"Critical": "9.8", "High": "7.5", "Medium": "5.3", "Low": "3.1", "Informational": "0.0"}
        now = _dt.utcnow()

        # ────────────────────────────────────────────────────
        # Generate combos: every client × every app = 24 base combos
        # Plus duplicate rounds for recent assessments = ~45 reports
        # ────────────────────────────────────────────────────
        all_findings = []
        report_count = 0
        combos = []
        quarters = ["Q3 2025", "Q4 2025", "Q1 2026"]
        for client in client_objs:
            for app_obj in app_objs:
                combos.append((client, app_obj))
        # Add a second round of recent assessments for half the combos
        extra = _rand.sample(combos, k=len(combos) // 2)
        combos.extend(extra)

        for client, app_obj in combos:
            quarter = _rand.choice(quarters)
            suffix = _rand.choice(["Pentest", "Assessment", "Review", "Audit", "Retest"])
            report_name = f"{app_obj.name} - {client.name} {quarter} {suffix}"
            # Spread report creation dates: 70% in last 60 days, 30% in 60-180 days
            if _rand.random() < 0.7:
                days_ago = _rand.randint(2, 60)
            else:
                days_ago = _rand.randint(60, 180)

            r = adapter.create_report(
                name=report_name,
                organization_id=org_id,
                client_id=client.id,
                application_id=app_obj.id,
            )
            report_count += 1

            # Tag the report
            for tag_name in _rand.sample(tag_names, k=_rand.randint(1, 4)):
                try:
                    adapter.add_entity_tag(tag_map[tag_name].id, "report", r.id)
                except Exception as e:
                    log.debug("Could not tag report %s: %s", r.id, e)

            # ── 8-15 findings per report (with replacement from template pool) ──
            n_findings = _rand.randint(8, 15)
            chosen_vulns = [vuln_templates[_rand.randint(0, len(vuln_templates) - 1)] for _ in range(n_findings)]
            for idx, (title, severity, cwe, finding_tags) in enumerate(chosen_vulns):
                # Vary the title slightly to avoid exact duplicates
                variant_title = f"{title} ({app_obj.name} #{idx + 1})" if n_findings > 10 else title

                # 65% Open, 35% Closed; enough closed to make charts dynamic
                status = "Closed" if _rand.random() < 0.35 else "Open"

                # Found date: cluster around the report date
                created_days_ago = max(1, days_ago + _rand.randint(-15, 20))
                found_date = now - timedelta(days=created_days_ago)

                content = {
                    "Severity": severity,
                    "CVSS v3.1": cvss_map.get(severity, "5.0"),
                    "CWE": cwe,
                    "Status": status,
                    "Vulnerability Summary": f"[Demo] {variant_title} - found during {quarter} assessment of {app_obj.name}.",
                    "Remediation": f"Apply standard {cwe} remediation guidance.",
                    "Found Date": found_date.strftime("%Y-%m-%d"),
                }
                if status == "Closed":
                    # Time-to-fix: 1 to 45 days (varied per client for interesting remediation data)
                    client_speed = {"Team ACS": (1, 10), "Team Payments": (3, 20), "Team CRM": (1, 8),
                                  "Team Video": (10, 45), "Team IAM": (5, 25), "Team Core": (7, 35)}
                    lo, hi = client_speed.get(client.name, (3, 25))
                    fix_days = _rand.randint(lo, hi)
                    closed_date = found_date + timedelta(days=fix_days)
                    if closed_date > now:
                        closed_date = now - timedelta(days=1)
                    content["Closed Date"] = closed_date.strftime("%Y-%m-%d")

                f = adapter.create_finding(
                    report_id=r.id,
                    title=variant_title,
                    content_json=_json.dumps(content),
                    notes="",
                    template="",
                    organization_id=org_id,
                )
                all_findings.append((f, finding_tags))

        # Apply tags to findings
        tag_assignment_count = 0
        for f, finding_tags in all_findings:
            for tag_name in finding_tags:
                if tag_name in tag_map:
                    try:
                        adapter.add_entity_tag(tag_map[tag_name].id, "finding", f.id)
                        tag_assignment_count += 1
                    except Exception as e:
                        log.debug("Could not tag finding %s: %s", f.id, e)

        # Also tag some clients
        for client in client_objs:
            for tag_name in _rand.sample(tag_names, k=_rand.randint(1, 2)):
                try:
                    adapter.add_entity_tag(tag_map[tag_name].id, "client", client.id)
                except Exception as e:
                    log.debug("Could not tag client %s: %s", client.id, e)

        log.info(
            "Demo seed complete: %d clients, %d apps, %d reports, %d findings, %d tags, %d tag assignments",
            len(client_objs), len(app_objs), report_count, len(all_findings),
            len(tag_objs), tag_assignment_count,
        )
    except Exception as e:
        log.exception("Failed to seed demo data: %s", e)


@app.get("/api/health")
def health():
    """Public health check - only returns basic status, no sensitive info."""
    return {"status": "ok"}


# Test-only endpoint: switch simulated user role (only when auth is disabled AND running under pytest)
from app.services.auth import is_auth_enabled

if not is_auth_enabled() and _RUNNING_UNDER_PYTEST:
    from pydantic import BaseModel as _BM

    class _SetRoleBody(_BM):
        role: str = "admin"

    @app.post("/api/_test/set-role", include_in_schema=False)
    def _test_set_role(body: _SetRoleBody):
        import app.services.auth as _auth_mod
        _auth_mod._test_forced_role = body.role or None
        return {"ok": True, "role": body.role}


@app.get("/api/spec")
def api_spec():
    """
    Alias for /openapi.json - returns the OpenAPI specification.

    Use this in API clients or to download the spec file.
    For interactive docs, use /docs or /redoc instead.
    """
    from fastapi.openapi.utils import get_openapi
    return get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )


@app.get("/api/health/detailed")
def health_detailed(_user = Depends(require_system_admin)):
    """Detailed health check - requires admin authentication."""
    return {
        "status": "ok",
        "llm_note": "LLM providers are configured per-user in Settings",
    }


# Serve frontend from frontend/dist
ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIST = ROOT / "frontend" / "dist"
if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")
    if (FRONTEND_DIST / "bg").exists():
        app.mount("/bg", StaticFiles(directory=FRONTEND_DIST / "bg"), name="bg")

    @app.get("/")
    def serve_index():
        return FileResponse(FRONTEND_DIST / "index.html")

    # Root-level static files (favicon, etc.) from dist root
    @app.get("/favicon.png")
    def serve_favicon():
        p = FRONTEND_DIST / "favicon.png"
        if p.exists():
            return FileResponse(p, media_type="image/png")
        raise HTTPException(status_code=404, detail="Not found")

    @app.get("/apple-touch-icon.png")
    def serve_apple_touch_icon():
        p = FRONTEND_DIST / "apple-touch-icon.png"
        if p.exists():
            return FileResponse(p, media_type="image/png")
        raise HTTPException(status_code=404, detail="Not found")

    # SPA routes that get index.html; anything else is 404 + text
    _SPA_PATH_PREFIXES = ("", "login", "invite", "dashboard")

    @app.get("/{path:path}")
    def serve_spa(path: str):
        if path.startswith("api/") or path in ("docs", "redoc", "openapi.json"):
            raise HTTPException(status_code=404, detail="Not found")
        first = path.split("/")[0] if path else ""
        if first in _SPA_PATH_PREFIXES:
            return FileResponse(FRONTEND_DIST / "index.html")
        return Response(
            content="Not found",
            status_code=404,
            media_type="text/plain",
        )
