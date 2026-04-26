# MANDATORY CONSTITUTION TO FOLLOW

## 0

You are the most elite and skilled coder in the world. As such, you:

- Never sacrifice security, integrity, or functionality for the quickest path.
- Know when you see an issue with code, ask about it. Do not ignore.
- Know that pleasing the user is secondary to security and integrity.

## 1

    When considering user insructions, exclude these folders to minimize token usage:
    - .git
    - .vscode
    - .venv
    - .pytest_cache
    - node_modules
    - venv

## 2

    During a brand new session - read this project root folder and all sub-folders (with the exception of above exlusions). Understand how it works deeply, what it does and all its specificities.

## 2.1

    Before comitting changes, ensure that no security vulnerabilities have been introduced by the changes.

## 2.1.1

    NEVER use external CDNs (jsDelivr, unpkg, etc.) to load libraries. All dependencies must be installed locally via npm/package managers and bundled with the app. This prevents:
    - Privacy leaks (third-party tracking of user requests)
    - CSP violations
    - Unnecessary external dependencies on unreliable services
    - Potential supply chain attacks

## 2.2

    When processing a user's request, consider whether it results in the most intuitive and modern standards for UI and UX design. If it does not, stop, and notify the user before continuing.

## 2.3

    UX solutions must be holistic: address the full user intent and workflow, not patchy or bandaid fixes that treat symptoms in isolation. When a user's goal is blocked by missing prerequisites, guide them through the complete flow in context—do not scatter partial fixes across pages.

## 3

    During any app modifications - If you add text user-readable text to the UI, always update all language files in `frontend/src/i18n/locales/` with their respective languages. Never assume "english fallback" for non-english users.

    Copying the English string verbatim into a non-English locale file is NOT a translation. Each locale must receive a genuine translation in that language. Pasting English values into de.json, es-419.json, he.json, or zh-CN.json is a violation of this rule.

## 4

    Do not mix UX designs: If editing, add a save button. DO NOT AUTO-SAVE.

## 5

    Ensure RBAC system does not break with any update. This requires running all RBAC related unit tests.

## 6

    Ensure all Python code changes have corresponding unit tests. Frontend-only (Vue/JS) changes do not require new tests.

## 6.1

    All UI changes must preserve and extend accessibility: use semantic HTML, ARIA attributes (labels, roles, live regions), keyboard navigability, and sufficient contrast. Never remove existing accessibility features. New interactive elements must be reachable and operable without a mouse.

## 7

    Do not cut corners, ever.

## 7.1

    Before stating that work is complete: () Verify the change works end-to-end (e.g. run the stack, run the flow, hit the feature). Do not claim done on "tasks implemented" alone. (2) Re-read this constitution and the active plan (if any). Confirm each applicable rule was followed. If you cannot verify or did not follow a rule, do not say done; fix it or state explicitly: "!! I IGNORED {{RULE}} BECAUSE {{REASON}} !!".

## 8

    If you ever decide to ignore one or more parts of a user's request or a rule of this constitution, you must state so explicitely: "!! I IGNORED {{REQUEST_OR_RULE}} BECAUSE {{REASON}} !!"

## 9

    Only change what was explicitly requested. If implementing a fix reveals related issues, raise them with the user before touching them. Do not refactor, restructure, or clean up adjacent code as a side effect.

## 10

    Before removing migration code or altering schema, confirm the migration has already run on all active environments. Schema changes are irreversible in production. Treat migration removal with the same caution as a destructive git operation — confirm first.

## 11

    Never silence exceptions with bare `except: pass` or `except Exception: pass`. All caught exceptions must be logged at minimum. Silent failure hides real errors and is a security and integrity risk.

## 12

    Never delete or replace existing tests as a convenience. Tests may only be removed when the exact behavior is demonstrably covered elsewhere, or when they test something that no longer exists. Any test removal must be explicitly justified.

## 13

    Code touching threads, background tasks, shared state, or database locking requires extra scrutiny. Flag such changes to the user before committing.

## 14

    docxtpl silently renders unrecognized `{{ TOKEN }}` placeholders as empty strings — it does not raise an error. When adding, renaming, or aliasing tokens in DOCX templates or in `build_master_docx()`, verify the token name is spelled identically on both sides (template file and context dict). After any such change, run `tests/test_master_docx.py` to confirm no tokens are left unresolved.

## 15

    Vue Router 4 silently ignores `router.push()` when the target route matches the currently active route (NavigationDuplicated). If navigation or a UI action must fire even when the user is already on the destination page, use a different mechanism: change a query param to force the route to differ, emit an event to the target component, or use a programmatic scroll/focus instead.

<!-- GSD:project-start source:PROJECT.md -->
## Project

**CLAUDE.md Compliance Enforcement**

A set of git hooks and static analysis tooling that enforces the Lazeport CLAUDE.md constitution on every commit and push. Pre-commit hooks run fast static checks; pre-push hooks add an LLM-based review via the Claude API to catch judgment-call violations that static analysis cannot detect. All hooks are committed as shell scripts and installed once per development machine.

**Core Value:** Every change to the Lazeport codebase is blocked at commit/push time if it violates CLAUDE.md — no violation reaches the repository.

### Constraints

- **Security**: Hooks must never log or transmit code to any service other than the Anthropic Claude API — no third-party analysis services
- **Performance**: Pre-commit must complete in under 3 seconds for typical changesets; LLM review is pre-push only to avoid blocking fast iteration
- **Compatibility**: Must not break GPG signing, existing pnpm/npm scripts, or the `run.sh` dev server workflow
- **Dependencies**: No new Python packages for static checks — use stdlib only; LLM review may use the `anthropic` SDK already available in the project
- **Distribution**: Shell scripts committed to `.claude-hooks/`; one `install-hooks.sh` for setup
<!-- GSD:project-end -->

<!-- GSD:stack-start source:codebase/STACK.md -->
## Technology Stack

## Languages
- Python 3.12 - Backend API, data processing, report generation, background tasks (see `Dockerfile`)
- JavaScript/Vue 3 - Frontend SPA with component-based UI (see `frontend/package.json`)
- Jinja2 - Template rendering for DOCX document generation (via `docxtpl`)
- Markdown - Content transformation and processing
## Runtime
- Python 3.12-slim (container: `python:3.12-slim@sha256:9e01bf1ae5db7649a236da7be1e94ffbbbdd7a93f867dd0d8d5720d9e1f89fab`)
- Node.js >=18.0.0 (frontend build requirement)
- pip - Python dependencies (see `requirements.txt`)
- pnpm 10.30.3 - Frontend dependencies (see `frontend/package.json`)
## Frameworks
- FastAPI 0.115.6+ - REST API framework, async request handling (see `app/main.py`)
- Starlette 0.49.1+ - ASGI middleware support (session, CSRF, security headers)
- Uvicorn 0.32.1 - ASGI server (2 workers in production, configurable via `docker-compose.yml`)
- SQLModel 0.0.22 - SQL ORM and schema definition (see `app/db/models.py`)
- SQLAlchemy 2.0.36 - Database abstraction layer (underlying SQLModel)
- Celery 5.4.0+ - Background task queue for long-running operations (LLM calls, Burp imports)
- Vue 3.5.24+ - Component framework, reactive UI
- Vue Router 4.6.4+ - Client-side routing (see `frontend/src/router.js`)
- Vue I18n 11.2.8+ - Multi-language support (see `frontend/src/i18n/locales/`)
- Vite 6.0.0+ - Build tool, dev server with HMR
- pytest 8.3.4 - Python unit/integration test framework
- pytest-cov 6.0.0 - Coverage reporting
- pytest-asyncio 0.24.0 - Async test support
- Playwright 1.58.2 - End-to-end test framework (see `package.json`)
- @vitejs/plugin-vue 5.2.0+ - Vue SFC compilation for Vite
- sharp 0.34.5 - Image processing for WebP conversion and favicon generation
- esbuild - Fast JavaScript bundler (via Vite)
## Key Dependencies
- openai 1.55.3 - OpenAI API client for LLM integrations (chat completion calls, models like gpt-4o, gpt-4o-mini)
- authlib 1.6.6+ - OAuth2/OIDC client for SSO integrations (see `app/services/oidc.py`)
- python-docx 1.1.2 - Read/write DOCX files (finding templates)
- docxtpl 0.20.0 - Jinja2-based DOCX templating for master report generation
- redis 5.0.0+ - Redis client for Celery broker/backend, session storage
- celery[redis] 5.4.0+ - Task queue with Redis transport (see `app/celery_app.py`)
- psycopg2-binary 2.9.9+ - PostgreSQL database adapter
- httpx 0.28.1 - Async HTTP client for API calls (LLM providers, Jira, OIDC discovery)
- cryptography 46.0.5 - AES encryption for sensitive user data (API keys, 2FA secrets)
- PyMuPDF 1.25.0+ - PDF parsing and manipulation
- pymupdf4llm 0.0.17+ - Extract text/structure from PDFs for LLM processing
- Pillow 12.1.1 - Image processing (WebP conversion, QR codes)
- pytesseract 0.3.10+ - OCR for image-based evidence extraction
- pyotp 2.9.0 - TOTP 2FA generation and verification
- qrcode[pil] 7.4.2 - QR code generation for 2FA setup
- defusedxml 0.7.1 - Safe XML parsing (XXE protection)
- itsdangerous 2.2.0 - URL-safe signing for tokens/invites
- python-multipart 0.0.22 - Multipart form parsing
- python-dotenv 1.0.1 - .env file configuration loading
- jinja2 3.1.6 - Template rendering (DOCX context preparation)
- marked 17.0.4 - Markdown parsing for content transformation
- dompurify 3.3.2 - XSS protection for user-supplied HTML (frontend)
- echarts 6.0.0 - Data visualization for analytics/trends dashboard
- @fontsource packages - Local font serving (IBM Plex Sans/Mono, JetBrains Mono)
## Configuration
- Environment-driven configuration via `app/config.py` (Settings class)
- `.env` file support via `python-dotenv` (not committed to repo)
- `.env.example` documents required configuration template
- `DATABASE_URL` - PostgreSQL connection string (default: `sqlite:///./data/lazeport.db`)
- `REDIS_URL` - Redis connection for Celery (default: `redis://localhost:6379/0`)
- `SESSION_SECRET_KEY` - PBKDF2 session signing key (required for production)
- `APP_SECRET_KEY` - Application secret for encryption (required for production)
- `AUTH_DISABLED` - Toggle authentication on/off (default: enabled)
- `DISABLE_2FA` - Option to disable 2FA requirement (default: enabled)
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM` - Email configuration
- `CORS_ORIGINS` - Comma-separated allowed origins (defaults to localhost dev ports)
- `PUBLIC_APP_URL` - Production URL for links in emails/tokens
- `DEMO_MODE` - Seed demo data for dashboard/trends (for testing)
- `LOG_LEVEL` - Python logging level (default: INFO)
- `vite.config.js` - Frontend build with Vue plugin, CSS chunking, API proxying
- `Dockerfile` - Multi-stage container build with Python 3.12-slim
- `docker-compose.yml` - Full stack orchestration (PostgreSQL, Redis, FastAPI app, Celery worker, Caddy reverse proxy)
## Platform Requirements
- Python 3.12+
- Node.js 18.0.0+
- pnpm 10.30.3+
- PostgreSQL 16+ (or SQLite for local testing)
- Redis 7+ (for Celery/sessions)
- Docker + Docker Compose (for containerized development)
- Container runtime (Docker/Kubernetes)
- PostgreSQL 16+ database
- Redis 7+ instance (or AWS ElastiCache)
- Reverse proxy (Caddy, Nginx, or cloud load balancer)
- HTTPS/TLS termination
- 2+ CPU cores, 2GB+ RAM minimum
- OIDC-compliant identity provider (Okta, Google, Microsoft Entra, Auth0)
- Jira Cloud instance for ticket integration
- OpenAI API, Anthropic, Google Gemini, Groq, Together, DeepSeek, or Mistral API keys for LLM generation
- Ollama local LLM server (for offline/private LLM inference)
- SMTP server for email notifications
<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->
## Conventions

## Naming Patterns
- Python modules: `snake_case.py` - e.g., `auth_service.py`, `docx_builder.py`
- Vue components: `PascalCase.vue` - e.g., `Modal.vue`, `FindingWorkflow.vue`
- Python service/adapter modules: `snake_case.py` - e.g., `sql_adapter.py`, `audit.py`
- Test files: `test_*.py` - e.g., `test_auth.py`, `test_2fa.py`
- View components: `PascalCase.vue` under `frontend/src/views/` - e.g., `Applications.vue`, `OrganizationManagement.vue`
- Store modules: `camelCase.js` - e.g., `backgroundTasks.js`, `generationTaskStore.js`
- Composables: `use*.js` - e.g., `useConfirm.js`, `useSeverityColors.js`
- Python functions: `snake_case()` - e.g., `hash_password()`, `verify_password()`, `authenticate_user()`
- Private Python functions: prefix with `_` - e.g., `_encode_b64()`, `_make_adapter()`
- JavaScript/Vue functions: `camelCase()` - e.g., `getSessionUser()`, `setStatus()`, `addApplication()`
- Private JS functions: prefix with `_` - e.g., `_getSystemTheme()`, `_syncSystemListener()`
- Validator functions: prefixed with `validate_` or `sanitize_` - e.g., `validate_email()`, `sanitize_string()`
- Python: `snake_case` - e.g., `user_id`, `organization_id`, `password_hash`, `session_secret_key`
- Constants (Python): `UPPER_SNAKE_CASE` - e.g., `MAX_CONTENT_LENGTH`, `PBKDF2_ITERATIONS`, `SYSTEM_ORG_ID`
- JavaScript/Vue refs: `camelCase` - e.g., `applications`, `newName`, `showModal`, `isOrgAdmin`
- Python classes: `PascalCase` - e.g., `User`, `Organization`, `AuditLog`, `ApiKey`
- Pydantic models: `PascalCase` - e.g., `ValidatedString` (custom validator class)
- Vue props/emits: `camelCase` - e.g., `show`, `title`, `closeOnBackdrop`
- Vue component data: `camelCase` refs - e.g., `router`, `applications`, `editId`
## Code Style
- No linter/formatter specified (no ESLint, Prettier, or Black config found)
- Python: Follow PEP 8 conventions implicitly
- JavaScript/Vue: Consistent use of modern syntax (ES6+, Vue 3 Composition API)
- Line length: Practical limit around 100-120 chars (observed in code)
- Indentation: Python uses 4 spaces, JavaScript/Vue uses 2 spaces
- Markdown: `markdownlint-cli2` configured via `.markdownlint-cli2.jsonc`
- Python: No explicit linter configuration (Pyright, flake8, or ruff could be added)
- JavaScript: No explicit linter configuration (ESLint could be added)
## Import Organization
- `app.` prefix used throughout for absolute imports from project root
- No path aliasing configured; absolute imports relative to project root are standard
## Error Handling
- Exceptions are caught with specific exception types when known - e.g., `except ValueError:`, `except _json.JSONDecodeError:`
- Broad `except Exception as e:` is used but ALWAYS logged - never silent failures
- Logging on exception: `log.exception()` for full traceback, `log.warning()`/`log.error()` for specific handling
- HTTPException raised with descriptive `detail` message for API responses
- `try/catch` blocks on async operations with error handling
- Errors thrown as `Error` objects with meaningful messages
- Error codes attached for programmatic handling (e.g., `e.code = 'rate_limit'`)
- API errors caught and examined for structured detail field
## Logging
- Logger created per module: `log = logging.getLogger(__name__)`
- Log levels used:
- Format: `"[%(asctime)s] [%(levelname)s] %(name)s: %(message)s"` (per `main.py`)
- Context always included: `log.debug("Message: %s", variable)` using format strings, not f-strings for logging
- Tests use `log.debug()` for diagnostic info
- No explicit logging output in test assertions
## Comments
- Docstrings on all functions and classes (required)
- Inline comments for non-obvious logic
- Comments for security-sensitive code (password hashing, CSRF tokens, redirect validation)
- References to issues/tickets (e.g., "LOW-19:" prefix in comments)
- Edge case handling (e.g., "docxtpl silently renders unrecognized placeholders as empty strings")
- Python: Triple-quoted docstrings with parameter descriptions
- JavaScript: Minimal JSDoc; Vue components use prop/emit definitions
## Function Design
- Generally 10-40 lines per function
- Longer functions break into helpers (e.g., `_parse_finding_content_safe()`, `_mark_stale_generating_as_failed()`)
- Complex logic extracted to separate service modules
- Prefer explicit parameters over kwargs for critical arguments
- Database adapters passed as `adapter: StorageAdapter` parameter
- Optional parameters use `Optional[]` type hints
- Pydantic models preferred for complex payloads
- Functions return tuples when multiple related values needed: `tuple[models.User, bool]`
- Dictionaries return wrapped in `{"ok": bool, ...}` pattern for API consistency
- Exceptions raised for error conditions (not returning error codes)
- Composables return reactive objects: `{ sevColors, SEV_ORDER }`
- Component methods are focused single-purpose functions
- Async operations wrapped in `try/catch` with error logging
## Module Design
- Services export public functions only
- Adapters expose interface methods (abstract pattern)
- Models defined in dedicated `models.py` with SQLModel tables
- Constants defined at module level: `PBKDF2_ITERATIONS = 210000`
- Store modules export state and functions: `export { THEMES, state, applyTheme, setTheme, loadTheme }`
- Composables return reactive object: `export function useConfirm() { return { ... } }`
- API module exports async request functions: `export async function request()`, `export async function loginLocal()`
- Components use `<script setup>` with props/emits at top
- Not extensively used; imports are direct to source file
- Example: `from app.api import generate, templates` (directory-level imports in main.py)
## Validation
- Custom `ValidatedString` class for input validation
- Validators applied via Pydantic `field_validator` decorator
- Security validation in `app/validation.py` module with constants and patterns
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->
## Architecture

## Pattern Overview
- Backend-driven multi-tenant architecture with role-based access control (RBAC) at organization level
- Database abstraction via StorageAdapter protocol enabling adapter-based persistence (SQL, future integrations)
- Separation of concerns: API routes → services → database layer
- Background task queue for long-running operations (LLM generation, Burp import)
- Session-based authentication with optional 2FA; SSO via OIDC
- Organization-scoped data isolation with cross-org member access via explicit report sharing
## Layers
- Purpose: Interactive Vue 3 SPA providing login, dashboard, report authoring, trend analysis, and configuration
- Location: `frontend/src/`
- Contains: Vue components, router, stores (Pinia), composables, internationalization, API client
- Depends on: Backend REST API, session cookies, CSRF tokens
- Used by: End users (security consultants, admins, readonly viewers)
- Purpose: RESTful endpoints enforcing request validation, authentication, authorization, and audit logging
- Location: `app/api/` (*.py files: generate.py, findings.py, auth.py, admin.py, organizations.py, export.py, tasks.py, etc.)
- Contains: FastAPI routers with request models, endpoint handlers, permission decorators
- Depends on: Services layer, RBAC, audit logging, database adapter
- Used by: Frontend, external clients (Jira, other integrations)
- Purpose: Encapsulate domain logic, transformations, external integrations, LLM interactions
- Location: `app/services/` (auth.py, rbac.py, llm.py, structurer.py, docx_builder.py, master_docx.py, evidence_schema.py, crypto.py, audit.py, etc.)
- Contains: User authentication, authorization checks, LLM calls, document generation, cryptography, evidence parsing
- Depends on: Database adapter, external APIs (OpenAI, local LLM), third-party libraries
- Used by: API layer, task workers
- Purpose: Abstract data storage and retrieval; provide adapter-based persistence strategy
- Location: `app/db/` (adapter.py, sql_adapter.py, models.py)
- Contains: SQLModel ORM models, StorageAdapter protocol interface, SQL implementation (SQLite/PostgreSQL)
- Depends on: SQLModel (SQLAlchemy), database drivers
- Used by: Services, API routes (via get_adapter dependency)
- Purpose: Execute long-running operations (LLM generation, Burp import, vision processing) asynchronously without blocking frontend
- Location: `app/tasks/` (llm_generation.py, burp_import.py), `app/celery_app.py`
- Contains: Celery task definitions, progress tracking, state mutations
- Depends on: Database adapter, services (LLM, structurer), Redis for task queue
- Used by: API endpoints (task initiation), task workers (task execution)
- Purpose: Cross-cutting concerns: CSRF protection, rate limiting, security headers, request authentication
- Location: `app/middleware/` (security.py, csrf.py, rate_limit.py, docs_auth.py)
- Contains: FastAPI middleware classes
- Depends on: Session management, request context
- Used by: FastAPI application startup
## Data Flow
- Frontend: Pinia stores (`generationTaskStore.js`, `backgroundTasks.js`, `theme.js`) for UI state, task progress, theme preference
- Backend: Immutable task progress stored in `GenerationTask.progress_log` (JSON array) and task state (pending/executing/completed/failed)
- Database: Transactional updates for resource ownership, audit trail captures all mutations
- No shared in-memory cache; Redis used only for Celery task queue, not application state
## Key Abstractions
- Purpose: Database-agnostic interface for all data operations
- Examples: `app/db/adapter.py` (protocol definition), `app/db/sql_adapter.py` (SQL implementation)
- Pattern: Protocol-based (structural typing) allows multiple implementations without inheritance
- Usage: Injected via `Depends(get_adapter)` on all endpoints; swappable for testing or future backends
- Purpose: Standardize vulnerability classification across organization
- Stored in: `Organization.severity_criteria` (JSON dict mapping severity level to definition text)
- Used by: LLM extra instructions, structurer validation
- Example: `{"Critical": "...", "High": "...", "Medium": "...", "Low": "...", "Informational": "..."}`
- Purpose: Immutable snapshot of scanner evidence (SARIF, Burp XML, plain notes)
- Stored in: `Finding.evidence_payload` (JSON)
- Contains: Union of SARIF, Burp items, raw notes; indexed for future machine learning
- Pattern: Write-once; read by LLM during regeneration to preserve original evidence
- Purpose: Track async operation state (finding generation, Burp import, summary generation)
- Stored in: `GenerationTask` table with progress_log (human-readable status messages)
- Polling: Frontend polls `GET /api/tasks/{task_id}` every 1-2s for progress updates
- Pattern: Celery task ID linked to DB task; claim semantics prevent race conditions
- Purpose: User-customizable Markdown structure for finding fields (title, severity, description, remediation)
- Stored in: `FindingTemplate` table; scoped per organization
- Used by: LLM generation to guide structure; display in report editor
- Pattern: Template variables (e.g., `{{title}}`, `{{severity}}`) replaced with LLM output
- Purpose: Organization-customizable DOCX shell with severity criteria and styling
- Stored in: `MasterTemplate.content` (binary DOCX blob)
- Used by: Export to DOCX; merged with finding templates and content via docxtpl
- Pattern: One-to-many with organizations; factory default provisioned on startup
## Entry Points
- Location: `app/main.py`
- Triggers: Application startup (FastAPI lifespan context manager)
- Responsibilities:
- Location: `frontend/src/main.js`
- Triggers: Browser page load
- Responsibilities:
- `POST /auth/login` — User login (email/password)
- `POST /auth/login/local` — Admin local login (for testing, AUTH_DISABLED)
- `POST /api/reports` — Create report shell
- `POST /api/generate/finding` — Submit notes for finding generation (Celery task)
- `GET /api/tasks/{task_id}` — Poll task progress
- `POST /export/report/{report_id}` — Export report to DOCX
- `GET /api/reports/{report_id}/findings` — Fetch all findings in report
- `PATCH /api/reports/{report_id}/findings/{finding_id}` — Update finding
- `POST /api/generate/summaries` — Generate executive/technical/recommendations summaries
- `app.tasks.llm_generation.generate_finding_task()` — Celery task for single finding
- `app.tasks.llm_generation.generate_summaries_task()` — Celery task for report summaries
- `app.tasks.burp_import.process_burp_scan()` — Celery task for Burp XML import
## Error Handling
- **Validation Errors:** Caught by FastAPI/Pydantic; return 422 with field-level details
- **Authentication Errors:** HTTPException(401) with "Invalid credentials" message (no user enumeration)
- **Authorization Errors:** HTTPException(403) with permission reason (cross-org access blocked, insufficient role)
- **LLM Errors:** Caught in Celery task; stored in GenerationTask.error with user-visible message; task state set to "failed"
- **Database Errors:** Logged at ERROR level; generic HTTPException(500) returned to client to avoid SQL leakage
- **Rate Limiting:** HTTPException(429) with structured detail including `seconds_remaining` (parsed by frontend)
- **CSRF Failures:** HTTPException(403) with "CSRF token invalid or missing"
- Example violation: `except: pass` on audit log creation — instead: `log.error(...)`
- Example violation: `except Exception: pass` on template provisioning — instead: `log.exception(...)`
- All caught exceptions must log at minimum; recommendation: re-raise or return explicit error status
## Cross-Cutting Concerns
- Framework: Python `logging` module
- Level: Configured via `LOG_LEVEL` env var (default INFO)
- Format: `[HH:MM:SS] [LEVEL] logger_name: message`
- Pattern: Loggers created per module: `log = logging.getLogger(__name__)`
- Critical paths: Task execution, auth, org access checks logged at INFO; errors at ERROR
- Framework: Pydantic (FastAPI integration)
- Input sanitization: `app/validation.py` with `sanitize_string()`, `ValidatedString` custom type
- Findings: Evidence preserved verbatim (never reformatted per Rule 2.3)
- Templates: Finding template names and master template names validated alphanumeric + underscore
- Session-based with Starlette SessionMiddleware
- Optional 2FA via TOTP (pyotp) or backup codes
- SSO via OIDC (per-organization provider config)
- Local auth (email/password hash) for testing/bootstrap
- API keys via hash comparison for programmatic access
- Every resource (report, finding, team, template) has `organization_id` foreign key
- Queries always filter by user's organization membership OR explicit share
- Fallback: System org for users without membership (system admins only)
- Cross-org access prevented by explicit check in every endpoint
- All mutations (create, update, delete) logged via `app.services.audit.log_*()` functions
- Captured: action, resource_type, resource_id, user, IP, user_agent, timestamp
- Scope: Organization-level; users can view org audit logs if org_admin+ role
- Pattern: Synchronous write to audit_log table; never dropped
<!-- GSD:architecture-end -->

<!-- GSD:workflow-start source:GSD defaults -->
## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:
- `/gsd:quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd:debug` for investigation and bug fixing
- `/gsd:execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->

<!-- GSD:profile-start -->
## Developer Profile

> Profile not yet configured. Run `/gsd:profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
