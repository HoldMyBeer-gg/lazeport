# Lazeport

Modern pentest reporting platform: organize clients and reports, generate AI-structured findings from raw notes, manage templates, create summaries, and export professional master DOCX reports.

**Cross-platform:** Windows, macOS, and Linux.

---

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/yourusername/lazeport.git
cd lazeport
pip install -r requirements.txt
cd frontend && pnpm install && cd ..

# 2. Run
./run.sh          # macOS/Linux
run.bat           # Windows

# 3. Open http://localhost:8000
```

**First-time login:** click **Sign in with password**, then:

| Field | Value |
|-------|-------|
| Email | `admin@local.domain` |
| Password | the value after `ADMIN_PASSWORD=` in `data/.admin_password` |

> The password is randomly generated on first run and written to `data/.admin_password`. Example: if the file contains `ADMIN_PASSWORD=abc123`, your password is `abc123`.

**That's it.** For LLM setup, Docker, production HTTPS, and advanced features, expand the sections below.

---

## Typical Workflow

1. **Set up clients** → "My Clients" → add client organizations
2. **Create reports** → "My Reports" → select client → new report
3. **Manage templates** → "My Templates" → create finding templates, upload master `.docx` templates
4. **Add findings** → open a report → either:
   - **Bulk import**: drag-and-drop SARIF (`.sarif`, `.json`) or Burp XML (`.xml`) into the findings page
   - **Individual**: select template → paste raw notes → click "Generate"
5. **Generate summaries** → click "Generate Summaries with AI"
6. **Export** → Master DOCX (full professional report) or SARIF (CI/CD integration)

---

<details>
<summary><strong>Features</strong></summary>

### Core Workflow

| Feature | What it does |
|---------|--------------|
| **Client Management** | Organize work by client. Create, edit, and delete clients from "My Clients". |
| **Report Management** | Create multiple reports per client. Track findings per engagement. |
| **Scanner Import** | Drag-and-drop SARIF or Burp XML into the findings page. Auto-merges duplicates, preserves locations, and queues for AI generation. Supports resume for large imports. |
| **Finding Generation** | Paste raw notes from manual testing or scanners. AI structures them into professional findings with proper sections (Summary, Details, Remediation, References, etc.). |
| **AI Self-Check** | Optional multi-pass validation — AI reviews its own output for accuracy before finalizing. |
| **Evidence Anchoring** | SARIF imports anchor all file paths and metadata to scanner output, preventing hallucinations and ensuring correct SARIF round-trips. Link evidence to exact source locations (URL, line, byte range). |
| **Severity & CVSS** | Automatic severity classification (Critical/High/Medium/Low/Informational) with CVSS 3.1 vector support. AI uses your org's severity criteria from master templates. |
| **2FA** | Optional TOTP-based 2FA for all users, with backup codes for account recovery. |
| **Finding Templates** | Reusable templates with custom sections, stored in the database. |
| **Master DOCX Templates** | Upload `.docx` templates with placeholder tokens (`{{ CLIENT_NAME }}`, `{{ YEAR }}`, `{{ FINDINGS_HIGH }}`, etc.). |
| **Report Summaries** | AI-generated executive, technical, and recommendations summaries from all findings. Included in master DOCX export. |
| **Master Report Export** | One-click complete pentest report with all findings, summaries, and metadata in professional DOCX. SARIF export for CI/CD integration. |
| **Connectors** | Connect external tools like Jira for seamless workflow integration. |

### LLM & AI

| Feature | What it does |
|---------|--------------|
| **Multi-Provider Support** | Ollama (local), OpenAI, Anthropic, Gemini, Groq, and more. Select your provider in Settings — no environment variables needed. |
| **UI-Selected Models** | Choose provider, model, and API key in the UI. Settings persist in localStorage. |
| **Severity Classification** | AI respects your org's severity criteria defined in master templates. |
| **Hyperlink Detection** | Auto-converts CWE-XXX, CVE-XXXX-XXXX, CVSS vectors, and URLs to clickable links in DOCX. |

### Integrations

| Feature | What it does |
|---------|--------------|
| **Jira Connector** | Create Jira tickets directly from findings with automatic severity mapping. |
| **Extensible Architecture** | Easy to add more connectors (GitHub, Linear, Slack, etc.). |

### Security & Auth

| Feature | What it does |
|---------|--------------|
| **Automatic HTTPS** | Caddy + Let's Encrypt for production SSL (zero configuration). |
| **Security Headers** | CSP, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, HSTS (when SSL enabled). |
| **Input Sanitization** | DOMPurify for HTML sanitization, defusedxml for safe XML parsing (prevents XXE/DoS). |
| **LLM Output Validation** | Strict JSON schema validation with retry logic to prevent malformed output. |
| **RBAC** | Org-level roles: org_owner, org_admin, consultant, readonly. |
| **Session Management** | Encrypted sessions with configurable secrets. |
| **Database Storage** | Docker: PostgreSQL. Non-Docker: SQLite. Sensitive data encrypted at rest. |
| **Encrypted Credentials** | Connector API tokens encrypted with Fernet (AES-128). |
| **Audit Trail** | Tracks auth, clients, reports, findings, templates, connectors, and settings. View in **Organization → Audit Logs**. |
| **2FA Support** | TOTP-based two-factor authentication with recovery codes. |

### UI & UX

| Feature | What it does |
|---------|--------------|
| **Modern Vue.js SPA** | Fast, responsive single-page application. |
| **Dark/Light Themes** | Multiple themes including Solarized variants. |
| **Drag-and-Drop Upload** | Drop SARIF/Burp files directly into the findings notes box. |
| **Background Task Queue** | Long-running imports show progress notifications. Click to navigate to report. |
| **Bulk Operations** | Select multiple findings for bulk delete or consolidation. |
| **Multi-Language Support** | English, German, Spanish (Latin America), Hebrew, Chinese (Simplified). Set in Settings. |

</details>

---

<details>
<summary><strong>LLM Providers</strong></summary>

Configure your provider in **Settings → LLM Provider**:

1. Click **Settings** (gear icon, top-right)
2. Select your provider (OpenAI, Ollama, Anthropic, Gemini, Groq, Together, DeepSeek, Mistral, or custom)
3. Enter your API key (if required) and base URL (if using a custom/compatible endpoint)
4. Select your model from the available list

Your choices persist in **localStorage** across sessions. No environment variables needed.

### Adding a new provider

1. **`app/services/llm.py`** — add the provider to `PROVIDER_PRESETS` with its base URL and label; add a default model to `DEFAULT_MODELS`.
2. **Frontend** — add the provider to the LLM provider dropdown in Settings.
3. **Test** — verify end-to-end via the UI.

</details>

---

<details>
<summary><strong>Master Template Tokens</strong></summary>

Master templates (`.docx` files uploaded via "My Templates") use [Jinja2](https://jinja.palletsprojects.com/) syntax via [python-docx-template](https://docxtpl.readthedocs.io/). Tokens must be in `{{ TOKEN_NAME }}` format (with spaces) and can appear anywhere — body, tables, headers, footers.

> **Warning:** Unrecognized tokens silently render as empty strings with no error. Spell token names exactly as listed below.

### Available tokens

| Token | Replaced with | Example |
|-------|---------------|---------|
| **Report & Client** | | |
| `{{ CLIENT_NAME }}` | Client name | "Acme Corp" |
| `{{ REPORT_NAME }}` | Report name | "Q1 2026 Pentest" |
| `{{ APP_NAME }}` | Client name (report name as fallback) | "Acme Corp" |
| **Your Company** | | |
| `{{ MY_COMPANY_NAME }}` / `{{ COMPANY_NAME }}` | Your company name (from profile) | "SecureTech Inc" |
| `{{ MY_COMPANY_DEPARTMENT }}` / `{{ DEPARTMENT_NAME }}` | Your department | "DevSecOps" |
| **Author** | | |
| `{{ AUTHOR }}` / `{{ AUTHOR_NAME }}` | Author name (from profile) | "John Smith" |
| `{{ AUTHOR_EMAIL }}` / `{{ MY_EMAIL }}` | Author contact email | "john@securetech.com" |
| `{{ AUTHOR_PHONE }}` / `{{ MY_PHONE }}` | Author phone | "+1 555-0123" |
| `{{ AUTHOR_TITLE }}` / `{{ MY_TITLE }}` | Author job title | "Principal Consultant" |
| **Dates** | | |
| `{{ DATE }}` | Current date (YYYY-MM-DD) | "2026-02-07" |
| `{{ YEAR }}` | Current year | "2026" |
| `{{ MONTH }}` | Month name | "February" |
| `{{ MONTH_YEAR }}` | Month and year | "February 2026" |
| **Findings** | | |
| `{{ FINDINGS_CRITICAL }}` | Placeholder — critical findings inserted here | |
| `{{ FINDINGS_HIGH }}` | Placeholder — high findings inserted here | |
| `{{ FINDINGS_MEDIUM }}` | Placeholder — medium findings inserted here | |
| `{{ FINDINGS_LOW }}` | Placeholder — low findings inserted here | |
| `{{ FINDINGS_INFORMATIONAL }}` | Placeholder — informational findings inserted here | |
| **Summaries** | | |
| `{{ SUMMARY_EXECUTIVE }}` | Executive summary | "The assessment identified..." |
| `{{ SUMMARY_TECHNICAL }}` | Technical summary | "From a technical perspective..." |
| `{{ SUMMARY_RECOMMENDATIONS }}` | Recommendations summary | "Priority actions include..." |
| **Reserved** | | |
| `{{ TABLE_OF_CONTENTS }}` | Reserved for future use | |
| `{{ MY_COMPANY_LOGO }}` | Reserved for future use | |

### How findings are inserted

Each `{{ FINDINGS_* }}` placeholder is replaced with a count (e.g., "[3 high finding(s)]"), then **immediately after** that paragraph the app inserts fully formatted findings:

- **Title** as Heading 2
- **Severity** line (colored text)
- **Metadata table** (Severity, CVSS, CWE, OWASP) with automatic hyperlinks
- **Prose sections** as Heading 3 (Summary, Details, Remediation, References, etc.)

### Automatic hyperlinks

References in metadata tables and prose sections are auto-converted to clickable links:

- **URLs**: `https://example.com` → clickable link
- **CWE**: `CWE-89` → links to cwe.mitre.org
- **CVE**: `CVE-2021-12345` → links to cve.mitre.org
- **CVSS vectors**: `CVSS:3.1/AV:N/...` → links to FIRST CVSS calculator with vector pre-filled

### Severity criteria

If your master template includes severity definitions, the AI uses **your org's criteria** for classification. Select which template provides the criteria in **My Profile → Default Master Template**.

Definitions can be formatted as:
- **Prose**: `Critical: definition text here...`
- **Table**: first column = severity level, second column = definition

</details>

---

<details>
<summary><strong>Auth, 2FA & Database</strong></summary>

### Authentication

Local admin auth with session cookies. On first startup a bootstrap admin password is generated and saved to `data/.admin_password`. Username: `admin@local.domain`.

**RBAC roles (org level):** org_owner, org_admin, consultant, readonly.

```bash
# Disable auth for local development (never in production)
export AUTH_DISABLED=1
```

### Two-Factor Authentication

All users can enable optional TOTP-based 2FA:

1. Go to **Settings → Enable 2FA**
2. Scan the QR code with your authenticator app (Google Authenticator, Authy, Microsoft Authenticator, etc.)
3. Enter the 6-digit code to confirm setup
4. **Save your backup codes** in a secure location

```bash
# Disable 2FA globally (dev/test only)
export DISABLE_2FA=1
```

### Production secrets

```bash
SESSION_SECRET_KEY=your-random-secret-here
APP_SECRET_KEY=your-random-secret-here
```

### Database

- **Docker Compose:** Uses PostgreSQL. Credentials auto-generated to `data/.postgres_password` on first run.
- **`./run.sh` (local):** SQLite (`data/lazeport.db`) by default.

To use Postgres without Docker:

```bash
export DB_ADAPTER=sql
export DATABASE_URL=postgresql://user:pass@host:5432/lazeport
```

</details>

---

<details>
<summary><strong>Running</strong></summary>

### Local (no Docker)

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cd frontend && pnpm install && pnpm run build && cd ..

uvicorn app.main:app --reload
```

Or use the helper scripts: **`./run.sh`** (macOS/Linux) / **`run.bat`** (Windows).

Open **http://127.0.0.1:8000**.

---

### Docker — Development mode

```bash
./run_docker.sh
```

For frontend hot-reload while iterating:

```bash
./run_docker.sh --no-build           # Start backend, skip frontend build
cd frontend && pnpm run build:watch  # Rebuilds on every save; refresh browser
```

**Services:**

| Service | Description |
|---------|-------------|
| `app` | Lazeport API (port 8000) |
| `celery` | Background task worker |
| `redis` | Task queue |
| `db` | PostgreSQL (credentials in `data/.postgres_password`) |

Access at **http://localhost:8000**.

---

### Docker — Production (automatic HTTPS)

```bash
# Prerequisites:
# 1. Domain name pointing to this server
# 2. Edit Caddyfile.docker — uncomment and add your domain
# 3. Open ports 80 and 443

docker-compose up -d
```

Caddy automatically obtains and renews SSL certificates from Let's Encrypt.

Access at **https://yourdomain.com**. See [PRODUCTION.md](PRODUCTION.md) for step-by-step instructions.

---

### Local HTTPS (optional)

Only needed to test SSL-specific features before production:

```bash
brew install mkcert nss   # macOS
./setup_local_https.sh
# Edit Caddyfile and uncomment the localhost:8000 block
./run_with_caddy.sh
```

Access at `https://localhost:8000` with a trusted certificate (no browser warnings).


</details>

---

<details>
<summary><strong>Tests</strong></summary>

```bash
pip install -r requirements.txt   # includes pytest, pytest-cov
python -m pytest tests/ --cov=app --cov-report=term-missing --cov-report=html
```

- Terminal shows coverage % and missing lines
- HTML report: open `htmlcov/index.html` for a line-by-line view

Use **`./run_tests.sh`** (macOS/Linux) / **`run_tests.bat`** (Windows) as a shortcut.

</details>

---

<details>
<summary><strong>Environment Variables</strong></summary>

All have sensible defaults. For production, set at minimum `SESSION_SECRET_KEY` and `APP_SECRET_KEY`.

| Variable | Description |
|----------|-------------|
| `SESSION_SECRET_KEY` | Session signing key. |
| `APP_SECRET_KEY` | Encryption key for bootstrap admin password. |
| `AUTH_DISABLED` | `1` to bypass auth (dev/test only). |
| `DISABLE_2FA` | `1` to disable 2FA globally (dev/test only). |
| `DB_ADAPTER` | `sql` for SQLite/Postgres. |
| `DATABASE_URL` | Connection string (default: `sqlite:///./data/lazeport.db`). |
| `REDIS_URL` | Redis connection URL (default: `redis://localhost:6379/0`). |
| `CELERY_BROKER_URL` | Celery broker (defaults to `REDIS_URL`). |
| `CORS_ORIGINS` | Comma-separated allowed CORS origins. Defaults to localhost ports. |
| `TEMPLATES_DIR` | Master template directory (default: `templates/`). |
| `PUBLIC_APP_URL` | Public URL used in email links (e.g., `https://lazeport.example.com`). |
| `SMTP_HOST` | SMTP server for notifications. |
| `SMTP_PORT` | SMTP port (default: `587`). |
| `SMTP_USERNAME` | SMTP username. |
| `SMTP_PASSWORD` | SMTP password. |
| `SMTP_FROM` | "From" address for notification emails. |
| `SMTP_USE_TLS` | `0` to disable TLS (default: enabled). |
| `LOG_LEVEL` | `DEBUG`, `INFO`, `WARNING`, `ERROR` (default: `INFO`). |
| `DEMO_MODE` | `1` to enable demo mode with sample data on the Trends page. |


</details>

---

## Production

See [PRODUCTION.md](PRODUCTION.md) for complete deployment instructions: Caddy/Let's Encrypt setup, Docker Compose configuration, and security best practices.

---

## License

SEE [LICENSE](LICENSE)
