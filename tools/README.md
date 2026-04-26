# Lazeport Security Tools

Security scanning and testing tools for CASA (Connected Application Security Assessment) compliance.

## Overview

This directory contains scripts for:

- **SAST** (Static Application Security Testing) - Code analysis
- **DAST** (Dynamic Application Security Testing) - Runtime testing
- **SCA** (Software Composition Analysis) - Dependency vulnerabilities
- **Secret Scanning** - Hardcoded credentials, API keys

## Quick Start

```bash
# Run all fast checks (SAST, SCA, secrets)
./tools/run_security.sh

# Include DAST scan (requires running app)
ZAP_ENABLED=1 ./tools/run_security.sh

# View findings interactively (TUI)
./tools/view-findings.sh          # Auto-installs deps if needed
# or
python tools/security_tui.py      # Requires: pip install -r tools/requirements.txt

# Or run tools individually
./tools/fluidattacks.sh    # SAST scan
./tools/zap-scan.sh         # DAST scan
./tools/get-token.sh        # Get auth token
```

## Setup (One-Time)

### 1. Install Python Tools

```bash
pip install bandit pip-audit safety semgrep
```

### 2. Install System Tools (macOS)

```bash
brew install gitleaks trivy
```

### 3. Pull Docker Images

```bash
docker pull fluidattacks/sast:latest
docker pull ghcr.io/zaproxy/zaproxy:stable
```

### 4. Install Frontend Tools

```bash
cd frontend
npm install -D eslint eslint-plugin-vue eslint-plugin-security \
  eslint-plugin-no-unsanitized eslint-plugin-sonarjs
```

### 5. Install TUI Tools (Optional)

```bash
pip install -r tools/requirements.txt  # Installs textual for interactive viewer
```

## Scripts

### `run_security.sh` - Comprehensive Security Gate

Runs all security checks in sequence. Exits with code 1 if any check fails.

**What it checks:**

1. ✓ Sensitive files (.env, keys, credentials)
2. ✓ Hardcoded secrets (API keys, passwords)
3. ✓ Python security (Bandit, Semgrep)
4. ✓ Python dependencies (pip-audit, Safety)
5. ✓ Frontend code (ESLint)
6. ✓ Frontend dependencies (npm audit)
7. ✓ Secret scanning (Gitleaks - git history)
8. ✓ Fluid Attacks SAST (CASA compliance)
9. ✓ Container vulnerabilities (Trivy)
10. ✓ Configuration sanity checks
11. ✓ Unit tests (pytest)
12. ⊘ OWASP ZAP DAST (optional, set `ZAP_ENABLED=1`)

**Usage:**

```bash
# Standard run
./tools/run_security.sh

# Include ZAP scan
ZAP_ENABLED=1 ./tools/run_security.sh

# Use in CI/CD
./tools/run_security.sh || exit 1  # Fail the build on findings
```

### `fluidattacks.sh` - SAST Scanner

Runs Fluid Attacks static analysis for CASA compliance.

**Output:**

- `Fluid-Attacks-Results.json` - SARIF format report
- Summary printed to stdout

**What it finds:**

- Code vulnerabilities (SQL injection, XSS, etc.)
- Cryptographic issues
- Authentication/authorization flaws
- Configuration problems
- Supply chain risks

**Usage:**

```bash
./tools/fluidattacks.sh
```

### `zap-scan.sh` - DAST Scanner

Runs OWASP ZAP dynamic security testing against running application.

**Requirements:**

- Docker
- Lazeport API running on `localhost:8000`
- `data/.admin_password` file (for authenticated scans)

**Usage:**

```bash
# Full authenticated scan
./tools/zap-scan.sh

# API-only scan
./tools/zap-scan.sh --api

# Unauthenticated scan (public endpoints)
./tools/zap-scan.sh --unauthenticated

# Scan frontend (Vue SPA)
./tools/zap-scan.sh --target http://localhost:5173

# Custom target with existing token
./tools/zap-scan.sh --target https://staging.example.com --bearer "eyJhb..."
```

**Output:**

- `zap-results/<timestamp>/results-*.xml` - ZAP report (XML format)
- Summary printed to stdout

### `get-token.sh` - Auth Token Grabber

Gets JWT bearer token from Lazeport API for authenticated testing.

**Usage:**

```bash
# Default (reads from data/.admin_password)
./tools/get-token.sh

# Custom credentials
./tools/get-token.sh --user admin --password secret

# Custom API URL
./tools/get-token.sh --url http://staging.example.com:8000

# Use with ZAP
./tools/zap-scan.sh --bearer "$(./tools/get-token.sh)"
```

### `security_tui.py` - Universal Security Findings Viewer 🚀

**Portable** terminal UI that works with **any security tool** that outputs SARIF!

**Universal SARIF Support:**

- ✅ Fluid Attacks, Semgrep, CodeQL, Snyk, Trivy, ESLint, Bandit
- ✅ Any SARIF 2.1.0 compliant tool
- ✅ OWASP ZAP (XML format)
- ✅ **Works in any project** - completely portable!

**Features:**

- ✨ Mouse-clickable list with keyboard shortcuts
- 📋 One-click copy to clipboard → paste into Cursor/AI chat
- 📂 Open file in Cursor at exact line number
- 🎨 Color-coded by severity
- 🔍 Preview pane with code context
- 📊 Statistics dashboard
- 🔄 Auto-discovers all security reports

**Usage:**

```bash
# Auto-discover all findings (any SARIF or ZAP XML)
python tools/security_tui.py

# Specific SARIF file (from any tool!)
python tools/security_tui.py report.sarif
python tools/security_tui.py semgrep-results.json

# ZAP results
python tools/security_tui.py zap-results/*/results-*.xml

# Multiple files from different tools
python tools/security_tui.py fluid.sarif semgrep.json zap.xml

# Force format detection
python tools/security_tui.py --format sarif custom.json
```

**Keyboard Shortcuts:**

- `↑/↓` or mouse - Navigate findings
- `Enter` or click - Select finding
- `c` - Copy to clipboard (formatted for AI chat)
- `o` - Open file in Cursor at line
- `r` - Refresh findings
- `q` - Quit
- `?` - Help

**Workflow:**

1. Run security scans: `./tools/run_security.sh` (or any SARIF tool)
2. Open TUI: `python tools/security_tui.py`
3. Click/select a finding
4. Press `c` to copy formatted prompt
5. Paste into Cursor chat → AI fixes it!
6. Or press `o` to jump straight to the code

**Supported Formats:**

- SARIF JSON (universal standard)
- OWASP ZAP XML
- Auto-detects format

**Portable!** Copy `security_tui.py` to any project and use it with Semgrep, CodeQL, Snyk, or any SARIF tool.

See [SECURITY_TUI_README.md](SECURITY_TUI_README.md) for full documentation.

## CASA Compliance

For Google CASA (Connected Application Security Assessment) submission, provide:

### Tier 2 Requirements

**1. SAST Scan:**

- Report: `Fluid-Attacks-Results.json`
- Config: `config.yaml`
- Tool: Fluid Attacks (free tier)

**2. DAST Scan:**

- Report: `zap-results/<timestamp>/results-*.xml`
- Config: `tools/zap-casa-api-config.conf`
- Tool: OWASP ZAP

**3. SCA (Dependency Scan):**

- Python: Run `pip-audit` (included in `run_security.sh`)
- JavaScript: Run `npm audit` (included in `run_security.sh`)
- Container: Run `trivy` (included in `run_security.sh`)

### Running Full CASA Scan

```bash
# 1. Start the application
docker-compose up -d

# 2. Run complete security suite
ZAP_ENABLED=1 ./tools/run_security.sh

# 3. Collect reports
ls -lh Fluid-Attacks-Results.json
ls -lh zap-results/*/
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.12'
      
      - name: Install tools
        run: |
          pip install bandit pip-audit safety semgrep
          docker pull fluidattacks/sast:latest
      
      - name: Run security scan
        run: ./tools/run_security.sh
      
      - name: Upload results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-reports
          path: |
            Fluid-Attacks-Results.json
            zap-results/
```

### Pre-commit Hook

```bash
# .git/hooks/pre-push
#!/bin/sh
echo "Running security checks..."
./tools/run_security.sh || {
  echo "Security checks failed. Fix issues or use --no-verify to skip."
  exit 1
}
```

## Troubleshooting

### "Docker image not found"

```bash
docker pull fluidattacks/sast:latest
docker pull ghcr.io/zaproxy/zaproxy:stable
```

### "Failed to obtain authentication token"

1. Check if API is running: `curl http://localhost:8000/health`
2. Verify admin password exists: `cat data/.admin_password`
3. Try manual login: `./tools/get-token.sh`

### "ZAP scan finds no endpoints"

- Ensure target URL is correct (use `http://host.docker.internal:8000` from Docker)
- Check authentication token is valid
- Try unauthenticated scan first: `./tools/zap-scan.sh --unauthenticated`

### "Fluid Attacks scan is slow"

- First run downloads and caches dependencies (can take 5-10 minutes)
- Subsequent runs are faster (~2-3 minutes)
- Large codebases take longer

## File Reference

```
tools/
├── README.md                    # This file
├── run_security.sh              # Main security gate
├── fluidattacks.sh              # SAST scanner
├── zap-scan.sh                  # DAST scanner
├── get-token.sh                 # Auth token grabber
├── security_tui.py              # Interactive findings viewer (TUI)
├── requirements.txt             # Python deps for TUI
└── zap-casa-api-config.conf     # ZAP rule config
```

## Additional Resources

- [Google CASA](https://appdefensealliance.dev/casa)
- [OWASP ZAP](https://www.zaproxy.org/)
- [Fluid Attacks](https://fluidattacks.com/)
- [Bandit](https://github.com/PyCQA/bandit)
- [Semgrep](https://semgrep.dev/)
