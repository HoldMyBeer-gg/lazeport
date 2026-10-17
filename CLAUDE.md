# MANDATORY CONSTITUTION TO FOLLOW

Rule numbers are stable because the git hooks in `.claude-hooks/` and their tests cite them. Gaps are intentional; retired rules are not renumbered.

## 0

- Never sacrifice security, integrity, or functionality for the quickest path.
- When you see an issue with code, ask about it. Do not ignore it.
- Pleasing the user is secondary to security and integrity.
- If you deviate from a request or from a rule here, say so explicitly and say why.

## 2.1

    Before committing changes, ensure that no security vulnerabilities have been introduced by the changes.

## 2.1.1

    NEVER use external CDNs (jsDelivr, unpkg, etc.) to load libraries. All dependencies must be installed locally via npm/package managers and bundled with the app. This prevents:
    - Privacy leaks (third-party tracking of user requests)
    - CSP violations
    - Unnecessary external dependencies on unreliable services
    - Potential supply chain attacks

## 2.2

    When processing a user's request, consider whether it results in the most intuitive and modern standards for UI and UX design. If it does not, stop, and notify the user before continuing.

## 2.3

    UX solutions must be holistic: address the full user intent and workflow, not patchy or bandaid fixes that treat symptoms in isolation. When a user's goal is blocked by missing prerequisites, guide them through the complete flow in context. Do not scatter partial fixes across pages.

## 3

    During any app modifications - If you add user-readable text to the UI, always update all language files in `frontend/src/i18n/locales/` with their respective languages. Never assume "english fallback" for non-english users.

    Copying the English string verbatim into a non-English locale file is NOT a translation. Each locale must receive a genuine translation in that language. Pasting English values into de.json, es-419.json, he.json, or zh-CN.json is a violation of this rule.

## 4

    Do not mix UX designs: If editing, add a save button. DO NOT AUTO-SAVE.

## 5

    Ensure RBAC system does not break with any update. This requires running all RBAC related unit tests (`tests/test_org_rbac.py`, `tests/test_jira_rbac.py`, `tests/test_rbac_adversarial.py`). The pre-push hook runs them whenever `app/**/*.py` changes.

## 6

    Ensure all Python code changes have corresponding unit tests. A new module `app/foo.py` needs `tests/test_foo.py` staged in the same commit (the pre-commit hook blocks otherwise). Frontend-only (Vue/JS) changes do not require new tests.

## 6.1

    All UI changes must preserve and extend accessibility: use semantic HTML, ARIA attributes (labels, roles, live regions), keyboard navigability, and sufficient contrast. Never remove existing accessibility features. New interactive elements must be reachable and operable without a mouse.

## 7

    Do not cut corners, ever.

## 7.1

    Before stating that work is complete, verify the change works end-to-end (run the tests, run the stack, hit the feature). Do not claim done on "tasks implemented" alone. If something could not be verified, say so instead of saying done.

## 9

    Only change what was explicitly requested. If implementing a fix reveals related issues, raise them with the user before touching them. Do not refactor, restructure, or clean up adjacent code as a side effect.

## 10

    Before removing migration code or altering schema, confirm the migration has already run on all active environments. Schema changes are irreversible in production. Treat migration removal with the same caution as a destructive git operation: confirm first.

## 11

    Never silence exceptions with bare `except: pass` or `except Exception: pass`. All caught exceptions must be logged at minimum. Silent failure hides real errors and is a security and integrity risk.

## 12

    Never delete or replace existing tests as a convenience. Tests may only be removed when the exact behavior is demonstrably covered elsewhere, or when they test something that no longer exists. Any test removal must be explicitly justified.

## 13

    Code touching threads, background tasks, shared state, or database locking requires extra scrutiny. Flag such changes to the user before committing. Commits that modify `app/tasks/`, add `import threading`, or introduce shared mutable state must carry the literal string `THREAD_REVIEWED=1` in the commit message, or the pre-push LLM reviewer blocks the push.

## 14

    docxtpl silently renders unrecognized `{{ TOKEN }}` placeholders as empty strings. It does not raise an error. When adding, renaming, or aliasing tokens in DOCX templates or in `build_master_docx()`, verify the token name is spelled identically on both sides (template file and context dict). After any such change, run `tests/test_master_docx.py` to confirm no tokens are left unresolved.

## 15

    Vue Router 4 silently ignores `router.push()` when the target route matches the currently active route (NavigationDuplicated). If navigation or a UI action must fire even when the user is already on the destination page, use a different mechanism: change a query param to force the route to differ, emit an event to the target component, or use a programmatic scroll/focus instead.

## Enforcement

The rules above are enforced by git hooks committed in `.claude-hooks/` and installed once per machine with `install-hooks.sh` (`core.hooksPath` points at the directory).

- **pre-commit** (static, stdlib only, under 3 seconds): CDN URLs (2.1.1), silent excepts (11), locale completeness when `en.json` gains keys (3), test-file pairing for new modules (6).
- **pre-push**: runs the RBAC suite when `app/**/*.py` changed (5) and the docxtpl tests when templates or `master_docx.py` changed (14), then an LLM review via the `claude` CLI that checks verbatim-English locale values, the `THREAD_REVIEWED=1` convention (13), and obvious scope mismatch between commit message and diff (9). The review has a hard 30-second timeout; very large diffs can trip it, and a retry usually passes.
- Hooks never send code anywhere except the Anthropic API, and must not break GPG signing, the pnpm scripts, or `run.sh`.

## Project map

Lazeport: pentest reporting platform. Python 3.13 FastAPI backend (CI also tests 3.12), Vue 3 SPA, PostgreSQL in Docker or SQLite locally, Redis + Celery for background work, Caddy for TLS in production.

- `app/main.py` - app factory, lifespan (DB init, template provisioning, bootstrap admin), static serving of `frontend/dist`, logging setup.
- `app/config.py` - every environment variable, read once into `settings`. The app does not load `.env` itself; Docker Compose supplies `data/.env`.
- `app/api/` - FastAPI routers. `auth.py` (local login, OIDC, 2FA, personal API keys), `admin.py` (profile, connectors, Jira, LLM guidance), `organizations.py` (orgs, members, OIDC config), `findings.py` (CRUD, SARIF/Burp/Nessus/CSV import), `tasks.py` (enqueue Celery jobs), `providers.py` (LLM model listing), `export.py`, `templates.py`.
- `app/services/` - domain logic: `auth.py`, `rbac.py`, `twofa.py`, `crypto.py` (Fernet, key derived from `APP_SECRET_KEY`), `llm.py` (provider presets, OpenAI-compatible client, `ensure_safe_base_url`), `jira.py`, `structurer.py` and `evidence_schema.py` (LLM output and evidence handling), `docx_builder.py` and `master_docx.py` (DOCX export), `audit.py`, `rate_limit.py`, `email.py`, `oidc.py`.
- `app/validation.py` - input validators, including `validate_outbound_url` (SSRF guard; `ALLOW_PRIVATE_LLM_URLS` / `ALLOW_PRIVATE_JIRA_URLS` relax it).
- `app/logging_utils.py` - `ScrubFilter`, attached to all root and Celery log handlers; escapes CR/LF/control characters in log messages and args.
- `app/db/` - `models.py` (SQLModel tables), `adapter.py` (StorageAdapter protocol), `sql_adapter.py` (the implementation). Routes get the adapter via `Depends(get_adapter)`; every resource is scoped by `organization_id`.
- `app/middleware/` - security headers and CSP, CSRF, rate limiting, docs auth.
- `app/tasks/` + `app/celery_app.py` - Celery tasks for LLM generation and Burp import. All generation and imports go through the queue; there is no inline fallback.
- `frontend/src/` - `views/` (pages), `components/`, `stores/` (theme, background tasks, generation tasks), `i18n/locales/` (en, de, es-419, he, zh-CN), `services/api.js` (API client), `router/`, `utils/`. Built with Vite 6; Node 20.9+ and pnpm 10.
- `tests/` - pytest, `tests/e2e/` is Playwright and excluded from the normal run. `tests/conftest.py` stubs DNS for the SSRF guard so tests never touch the network.
- `.claude-hooks/` - the enforcement hooks described above. `scripts/` - container bootstrap helpers.

Conventions worth knowing: loggers are `log = logging.getLogger(__name__)` with `%s` formatting, not f-strings; caught exceptions are always logged; Python is `snake_case`, Vue components `PascalCase.vue`, composables `use*.js`; audit every mutation through `app.services.audit`; cross-org access is denied explicitly in every endpoint.
