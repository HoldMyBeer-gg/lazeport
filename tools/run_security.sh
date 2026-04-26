#!/usr/bin/env sh
# ──────────────────────────────────────────────────────────────────────────────
# Pre-push security gate
#
# Purpose: Catch obvious vulnerabilities, leaked secrets, and unsafe
#          dependencies before code reaches production.
#
# Exit code:
#   0 - all checks passed
#   1 - one or more checks reported findings
#
# Install dependencies (one-time):
#   pip install bandit pip-audit safety semgrep
#   brew install gitleaks trivy              # macOS
#   docker pull fluidattacks/sast:latest     # Fluid Attacks SAST
#   docker pull ghcr.io/zaproxy/zaproxy:stable  # OWASP ZAP (optional)
#   cd frontend && npm i -D eslint eslint-plugin-vue eslint-plugin-security \
#     eslint-plugin-no-unsanitized eslint-plugin-sonarjs
#
# Recommended frontend scripts (frontend/package.json):
#   "lint": "eslint . --ext .js,.ts,.vue",
#   "typecheck": "tsc --noEmit"   # optional if TS exists
# ──────────────────────────────────────────────────────────────────────────────
set -e

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

# Ensure common tool locations are in PATH for non-interactive shells
export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin:$HOME/.pyenv/shims:$PATH"

overall_status=0
checks_run=0
checks_skipped=0

# ── Helpers ──────────────────────────────────────────────────────────────────
run_tool() {
  label="$1"
  shift
  set +e
  "$@"
  code=$?
  set -e
  checks_run=$((checks_run + 1))
  if [ $code -ne 0 ]; then
    overall_status=1
    echo "  ✗ $label - exited with status $code"
  else
    echo "  ✓ $label - passed"
  fi
  return 0
}

skip_tool() {
  label="$1"
  install_hint="$2"
  checks_skipped=$((checks_skipped + 1))
  echo "  ⊘ $label - not installed ($install_hint)"
}

section() {
  echo ""
  echo "═══ $1 ═══"
}

# ── Activate virtualenv ─────────────────────────────────────────────────────
if [ -d .venv ]; then
  # shellcheck disable=SC1091
  . .venv/bin/activate
fi

# ═══════════════════════════════════════════════════════════════════════════════
section "1. Sensitive file / secret checks (fast, no tools needed)"
# ═══════════════════════════════════════════════════════════════════════════════

# 1a. Check for .env files that should never be committed
echo "  Checking for .env files in tracked tree..."
env_files=$(git ls-files --cached --others --exclude-standard '*.env' '.env*' 2>/dev/null || true)
if [ -n "$env_files" ]; then
  echo "  ✗ .env files found in repo:"
  echo "$env_files" | sed 's/^/      /'
  overall_status=1
else
  echo "  ✓ No .env files in tracked tree"
fi

# 1b. Check for private keys, certificates, or credential files
echo "  Checking for private keys / credential files..."
sensitive_patterns='\.pem$|\.key$|\.p12$|\.pfx$|credentials\.json$|service.account\.json$|id_rsa$|id_ed25519$'
sensitive_files=$(git ls-files --cached --others --exclude-standard 2>/dev/null | grep -E "$sensitive_patterns" || true)
if [ -n "$sensitive_files" ]; then
  echo "  ✗ Potential secrets/keys found in repo:"
  echo "$sensitive_files" | sed 's/^/      /'
  overall_status=1
else
  echo "  ✓ No private keys or credential files found"
fi

# 1c. Quick grep for hardcoded high-entropy secrets (API keys, tokens)
echo "  Scanning for hardcoded secrets in Python/JS source..."
secret_grep=$(grep -rnE \
  '(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|glpat-[a-zA-Z0-9\-]{20,}|password\s*=\s*"[^"]{8,}")' \
  app/ frontend/src/ \
  --include='*.py' --include='*.js' --include='*.vue' --include='*.ts' \
  2>/dev/null \
  | grep -v 'test' | grep -v 'fake' | grep -v 'example' | grep -v 'nosec' \
  || true)
if [ -n "$secret_grep" ]; then
  echo "  ✗ Possible hardcoded secrets:"
  echo "$secret_grep" | head -10 | sed 's/^/      /'
  overall_status=1
else
  echo "  ✓ No hardcoded secrets detected"
fi

# 1d. Verify data/.admin_password is not tracked
admin_pw_tracked=$(git ls-files --cached 'data/.admin_password' 2>/dev/null || true)
if [ -n "$admin_pw_tracked" ]; then
  echo "  ✗ data/.admin_password is tracked in git - add to .gitignore!"
  overall_status=1
else
  echo "  ✓ data/.admin_password not tracked"
fi

# ═══════════════════════════════════════════════════════════════════════════════
section "2. Static analysis (SAST)"
# ═══════════════════════════════════════════════════════════════════════════════

if command -v bandit >/dev/null 2>&1; then
  run_tool "Bandit (Python security linter)" bandit -r app -ll --quiet
else
  skip_tool "Bandit" "pip install bandit"
fi

if command -v semgrep >/dev/null 2>&1; then
  # Fast but covers backend + frontend
  run_tool "Semgrep (FastAPI + JS/Vue rules)" semgrep \
    --config=p/fastapi \
    --config=p/javascript \
    --config=p/vue \
    --sarif \
    --quiet
else
  skip_tool "Semgrep" "pip install semgrep"
fi

# ═══════════════════════════════════════════════════════════════════════════════
section "3. Python dependency vulnerabilities"
# ═══════════════════════════════════════════════════════════════════════════════

if command -v pip-audit >/dev/null 2>&1; then
  run_tool "pip-audit" pip-audit -r requirements.txt
else
  skip_tool "pip-audit" "pip install pip-audit"
fi

if command -v safety >/dev/null 2>&1; then
  run_tool "Safety" safety check -r requirements.txt
else
  skip_tool "Safety" "pip install safety"
fi

# ═══════════════════════════════════════════════════════════════════════════════
section "4. Frontend static analysis + dependency vulnerabilities"
# ═══════════════════════════════════════════════════════════════════════════════

if [ -f frontend/package.json ]; then
  if command -v pnpm >/dev/null 2>&1; then
    # 4a. Lint / typecheck (only if scripts exist)
    if pnpm --prefix frontend run | grep -q " lint"; then
      run_tool "ESLint (frontend)" pnpm --prefix frontend run lint
    else
      echo "  ⊘ No frontend lint script found - add one (recommended)"
      echo "     e.g. in frontend/package.json: \"lint\": \"eslint . --ext .js,.ts,.vue\""
      checks_skipped=$((checks_skipped + 1))
    fi

    if pnpm --prefix frontend run | grep -q " typecheck"; then
      run_tool "Typecheck (frontend)" pnpm --prefix frontend run typecheck
    else
      echo "  ⊘ No frontend typecheck script found - optional (skip if JS-only)"
      checks_skipped=$((checks_skipped + 1))
    fi

    # 4b. pnpm audit - fail only on HIGH/CRITICAL (and ignore dev deps)
    echo "  Running pnpm audit (frontend) - only HIGH/CRITICAL..."
    set +e
    pnpm --prefix frontend audit --prod --audit-level=high
    audit_code=$?
    set -e
    if [ $audit_code -eq 0 ]; then
      echo "  ✓ pnpm audit (frontend) - no HIGH/CRITICAL vulns"
      checks_run=$((checks_run + 1))
    else
      overall_status=1
      checks_run=$((checks_run + 1))
      echo "  ✗ pnpm audit (frontend) - vulnerabilities detected"
    fi
  else
    skip_tool "pnpm audit / lint" "install Node.js and pnpm"
  fi
else
  echo "  ⊘ No frontend package.json found - skipping"
fi

# ═══════════════════════════════════════════════════════════════════════════════
section "5. Secret scanning (git history)"
# ═══════════════════════════════════════════════════════════════════════════════

if command -v gitleaks >/dev/null 2>&1; then
  run_tool "Gitleaks" gitleaks detect --source . --no-banner
else
  skip_tool "Gitleaks" "brew install gitleaks"
fi

# ═══════════════════════════════════════════════════════════════════════════════
section "6. Container / filesystem scan (optional)"
# ═══════════════════════════════════════════════════════════════════════════════

if command -v trivy >/dev/null 2>&1; then
  run_tool "Trivy (filesystem)" trivy fs . --severity HIGH,CRITICAL --quiet
  if [ -f Dockerfile ]; then
    image_name="lazeport"
    if docker image inspect "$image_name" >/dev/null 2>&1; then
      run_tool "Trivy (Docker image)" trivy image "$image_name" --severity HIGH,CRITICAL --quiet
    else
      echo "  ⊘ Docker image '$image_name' not found locally - skipping image scan"
      checks_skipped=$((checks_skipped + 1))
    fi
  fi
else
  skip_tool "Trivy" "brew install trivy"
fi

# ═══════════════════════════════════════════════════════════════════════════════
section "7. Fluid Attacks SAST (CASA compliance)"
# ═══════════════════════════════════════════════════════════════════════════════

if command -v docker >/dev/null 2>&1; then
  if docker image inspect fluidattacks/sast:latest >/dev/null 2>&1; then
    echo "  Running Fluid Attacks SAST scanner..."
    set +e
    "$ROOT_DIR/tools/fluidattacks.sh"
    code=$?
    set -e
    checks_run=$((checks_run + 1))
    if [ $code -ne 0 ]; then
      overall_status=1
      echo "  ✗ Fluid Attacks - vulnerabilities detected"
    else
      echo "  ✓ Fluid Attacks - passed"
    fi
  else
    echo "  ⊘ Fluid Attacks image not found - pull with: docker pull fluidattacks/sast:latest"
    checks_skipped=$((checks_skipped + 1))
  fi
else
  skip_tool "Fluid Attacks SAST" "install Docker"
fi

# ═══════════════════════════════════════════════════════════════════════════════
section "8. Configuration sanity checks"
# ═══════════════════════════════════════════════════════════════════════════════

# 7a. Verify DEBUG / AUTH flags are not left in unsafe states
echo "  Checking for unsafe runtime flags..."
unsafe_flags=0
if grep -q 'AUTH_DISABLED.*=.*1\|AUTH_DISABLED.*=.*true' docker-compose*.yml .env 2>/dev/null; then
  echo "  ✗ AUTH_DISABLED=1 found in docker-compose or .env - must be off in production!"
  unsafe_flags=1
fi
if grep -q 'DEBUG.*=.*1\|DEBUG.*=.*true\|DEBUG.*=.*True' docker-compose*.yml .env 2>/dev/null; then
  echo "  ✗ DEBUG mode enabled in docker-compose or .env"
  unsafe_flags=1
fi
if [ $unsafe_flags -eq 0 ]; then
  echo "  ✓ No unsafe runtime flags detected"
else
  overall_status=1
fi

# 7b. Verify .gitignore covers sensitive paths
echo "  Checking .gitignore coverage..."
gitignore_ok=1
for pattern in ".env" "data/" "certs/" "*.pem" "*.key"; do
  if ! grep -qF "$pattern" .gitignore 2>/dev/null; then
    echo "  ✗ .gitignore missing pattern: $pattern"
    gitignore_ok=0
  fi
done
if [ $gitignore_ok -eq 1 ]; then
  echo "  ✓ .gitignore covers sensitive paths"
else
  overall_status=1
fi

# ═══════════════════════════════════════════════════════════════════════════════
section "9. OWASP ZAP DAST scan (optional, requires running app)"
# ═══════════════════════════════════════════════════════════════════════════════

# ZAP is optional because it requires the app to be running and takes longer
# Set ZAP_ENABLED=1 to include it in the security scan
if [ "${ZAP_ENABLED:-0}" = "1" ]; then
  if command -v docker >/dev/null 2>&1; then
    if [ -x "$ROOT_DIR/tools/zap-scan.sh" ]; then
      echo "  Running OWASP ZAP scan (this may take several minutes)..."
      set +e
      "$ROOT_DIR/tools/zap-scan.sh" --api
      code=$?
      set -e
      checks_run=$((checks_run + 1))
      if [ $code -eq 0 ]; then
        echo "  ✓ ZAP scan - passed"
      elif [ $code -eq 1 ]; then
        echo "  ⚠ ZAP scan - warnings found"
      else
        overall_status=1
        echo "  ✗ ZAP scan - vulnerabilities detected"
      fi
    else
      echo "  ⊘ tools/zap-scan.sh not found or not executable"
      checks_skipped=$((checks_skipped + 1))
    fi
  else
    skip_tool "OWASP ZAP" "install Docker"
  fi
else
  echo "  ⊘ ZAP scan disabled (set ZAP_ENABLED=1 to enable)"
  echo "     Run manually: ./tools/zap-scan.sh"
  checks_skipped=$((checks_skipped + 1))
fi

# ═══════════════════════════════════════════════════════════════════════════════
section "10. Unit tests (quick smoke test)"
# ═══════════════════════════════════════════════════════════════════════════════

if command -v pytest >/dev/null 2>&1 || [ -f .venv/bin/pytest ]; then
  pytest_cmd="pytest"
  [ -f .venv/bin/pytest ] && pytest_cmd=".venv/bin/pytest"
  # shellcheck disable=SC2086
  run_tool "Pytest (unit tests)" $pytest_cmd tests/ -x -q --tb=line
else
  skip_tool "Pytest" "pip install pytest"
fi

# ═══════════════════════════════════════════════════════════════════════════════
section "Summary"
# ═══════════════════════════════════════════════════════════════════════════════

echo ""
echo "  Checks run:     $checks_run"
echo "  Checks skipped: $checks_skipped"

if [ $checks_skipped -gt 2 ]; then
  echo ""
  echo "  ⚠  Several checks are missing or skipped. For fuller coverage, install:"
  echo "     pip install bandit pip-audit safety semgrep"
  echo "     brew install gitleaks trivy"
  echo "     docker pull fluidattacks/sast:latest ghcr.io/zaproxy/zaproxy:stable"
  echo "     cd frontend && npm i -D eslint eslint-plugin-vue eslint-plugin-security eslint-plugin-no-unsanitized eslint-plugin-sonarjs"
  echo ""
  echo "  To enable ZAP DAST scanning: ZAP_ENABLED=1 ./tools/run_security.sh"
  echo "  Or run manually: ./tools/zap-scan.sh"
fi

echo ""
if [ $overall_status -ne 0 ]; then
  echo "  ✗ FAILED - findings detected. Review above before pushing to production."
  echo ""
  echo "  💡 View findings interactively: python tools/security_tui.py"
  echo "     (Install TUI: pip install -r tools/requirements.txt)"
  exit 1
fi
echo "  ✓ ALL CLEAR - no obvious vulnerabilities or sensitive data detected."
