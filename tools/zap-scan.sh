#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# zap-scan.sh - Run OWASP ZAP DAST scan against Lazeport (CASA compliance)
#
# Usage:
#   ./zap-scan.sh                                   # Scan localhost:8000
#   ./zap-scan.sh --target http://localhost:5173    # Scan frontend
#   ./zap-scan.sh --api                             # API-only scan
#   ./zap-scan.sh --unauthenticated                 # Skip authentication
#
# Requirements:
#   - Docker
#   - Lazeport API running (for authentication)
#   - data/.admin_password file (for default auth)
# ---------------------------------------------------------------------------
set -euo pipefail

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

# Defaults
TARGET="${TARGET:-http://host.docker.internal:8000}"
SCAN_TYPE="full"          # full | api
API_FORMAT="openapi"
AUTHENTICATED="true"
OUTPUT_DIR="./zap-results"
ZAP_IMAGE="ghcr.io/zaproxy/zaproxy:stable"
BEARER_TOKEN=""

# Parse args
usage() {
  cat <<EOF
Lazeport ZAP Scanner (CASA Compliance)

Usage: $0 [options]

Options:
  --target URL              Target URL (default: http://host.docker.internal:8000)
  --api                     Run API scan instead of full scan
  --unauthenticated         Skip authentication (public endpoints only)
  --bearer TOKEN            Use specific bearer token (skips auto-login)
  --output DIR              Output directory (default: ./zap-results)
  --image IMAGE             ZAP Docker image (default: ghcr.io/zaproxy/zaproxy:stable)
  -h, --help                Show this help

Examples:
  # Full authenticated scan
  $0

  # API-only scan
  $0 --api

  # Unauthenticated scan (public endpoints)
  $0 --unauthenticated

  # Scan frontend (Vue SPA)
  $0 --target http://host.docker.internal:5173
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)           TARGET="$2"; shift 2 ;;
    --api)              SCAN_TYPE="api"; shift ;;
    --unauthenticated)  AUTHENTICATED="false"; shift ;;
    --bearer)           BEARER_TOKEN="$2"; shift 2 ;;
    --output)           OUTPUT_DIR="$2"; shift 2 ;;
    --image)            ZAP_IMAGE="$2"; shift 2 ;;
    -h|--help)          usage ;;
    *)                  echo "Unknown option: $1"; usage ;;
  esac
done

# Setup
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SCAN_DIR="${OUTPUT_DIR}/${TIMESTAMP}"
mkdir -p "$SCAN_DIR"

echo ""
echo "=== Lazeport ZAP Scanner ==="
echo "  Target:        $TARGET"
echo "  Scan type:     $SCAN_TYPE"
echo "  Authenticated: $AUTHENTICATED"
echo "  Output:        $SCAN_DIR"
echo ""

# Get authentication token if needed
if [[ "$AUTHENTICATED" == "true" && -z "$BEARER_TOKEN" ]]; then
  echo "Getting authentication token..."
  if [[ ! -x "tools/get-token.sh" ]]; then
    chmod +x tools/get-token.sh
  fi
  
  set +e
  BEARER_TOKEN=$(tools/get-token.sh --url "${TARGET%:*}:8000" 2>&1 | tee /dev/stderr | tail -1)
  TOKEN_EXIT=$?
  set -e
  
  if [[ $TOKEN_EXIT -ne 0 || -z "$BEARER_TOKEN" ]]; then
    echo ""
    echo "Error: Failed to obtain authentication token."
    echo "  - Is the Lazeport API running?"
    echo "  - Does data/.admin_password exist?"
    echo "  - Try running manually: ./tools/get-token.sh"
    echo ""
    echo "To skip authentication: $0 --unauthenticated"
    exit 1
  fi
  echo ""
fi

# Pick config and scan script
if [[ "$SCAN_TYPE" == "api" ]]; then
  CONFIG_FILE="tools/zap-casa-api-config.conf"
  SCAN_SCRIPT="zap-api-scan.py"
  RESULTS_FILE="results-api.xml"
else
  # For full scan, use the API config (it's more lenient)
  # CASA assessors typically want the official config
  CONFIG_FILE="tools/zap-casa-api-config.conf"
  SCAN_SCRIPT="zap-full-scan.py"
  RESULTS_FILE="results-full.xml"
fi

# Verify config exists
if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "Error: $CONFIG_FILE not found"
  echo "Copy it from: https://appdefensealliance.dev/casa/tier-2/ast-guide/dynamic-scan"
  exit 1
fi

# Build docker run command
CMD=(
  docker run --rm
  --add-host=host.docker.internal:host-gateway
  -v "$ROOT_DIR:/zap/wrk/:rw"
  -t "$ZAP_IMAGE"
  "$SCAN_SCRIPT"
  -t "$TARGET"
  -c "$CONFIG_FILE"
  -r "$RESULTS_FILE"
)

# API format flag
if [[ "$SCAN_TYPE" == "api" ]]; then
  CMD+=(-f "$API_FORMAT")
fi

# Add bearer token if authenticated
if [[ -n "$BEARER_TOKEN" ]]; then
  echo "Injecting bearer token into ZAP requests..."
  CMD+=(-z "replacer.full_list(0).description=auth")
  CMD+=(-z "replacer.full_list(0).enabled=true")
  CMD+=(-z "replacer.full_list(0).matchtype=REQ_HEADER")
  CMD+=(-z "replacer.full_list(0).matchstr=Authorization")
  CMD+=(-z "replacer.full_list(0).regex=false")
  CMD+=(-z "replacer.full_list(0).replacement=Bearer ${BEARER_TOKEN}")
fi

# Run scan
echo "Running ZAP scan..."
echo "Command: ${CMD[*]}"
echo ""
echo "--- ZAP Output ---"
echo ""

EXIT_CODE=0
"${CMD[@]}" || EXIT_CODE=$?

echo ""
echo "--- Scan Complete (exit code: $EXIT_CODE) ---"
echo ""

# Collect results
if [[ -f "$RESULTS_FILE" ]]; then
  mv "$RESULTS_FILE" "$SCAN_DIR/"
  echo "✓ Results: $SCAN_DIR/$RESULTS_FILE"
  
  # Show summary
  if command -v python3 >/dev/null 2>&1; then
    python3 << 'PYEOF' "$SCAN_DIR/$RESULTS_FILE" || true
import sys
import xml.etree.ElementTree as ET

try:
    tree = ET.parse(sys.argv[1])
    root = tree.getroot()
    
    # ZAP XML format: <alertitem>
    alerts = root.findall('.//alertitem')
    
    if not alerts:
        print("✓ No vulnerabilities found")
    else:
        print(f"\nFound {len(alerts)} alert(s):")
        
        by_risk = {}
        for alert in alerts:
            risk = alert.find('riskdesc').text if alert.find('riskdesc') is not None else 'Unknown'
            risk_level = risk.split()[0] if risk else 'Unknown'
            by_risk[risk_level] = by_risk.get(risk_level, 0) + 1
        
        for risk, count in sorted(by_risk.items(), reverse=True):
            print(f"  {risk}: {count}")
        
        print("\nTop 5 findings:")
        for i, alert in enumerate(alerts[:5], 1):
            name = alert.find('name').text if alert.find('name') is not None else 'Unknown'
            url = alert.find('uri').text if alert.find('uri') is not None else 'Unknown'
            risk = alert.find('riskdesc').text if alert.find('riskdesc') is not None else 'Unknown'
            print(f"{i}. [{risk}] {name}")
            print(f"   URL: {url}")
except Exception as e:
    print(f"Could not parse results: {e}", file=sys.stderr)
PYEOF
  fi
else
  echo "✗ $RESULTS_FILE not found - scan may have failed"
fi

# Copy config for CASA submission
cp "$CONFIG_FILE" "$SCAN_DIR/"

echo ""
echo "=== Done ==="
echo ""
echo "For CASA submission, provide:"
echo "  1. $SCAN_DIR/$RESULTS_FILE     (scan results)"
echo "  2. $SCAN_DIR/$(basename "$CONFIG_FILE")  (scan config)"
echo ""

if [[ $EXIT_CODE -eq 0 ]]; then
  echo "Result: ✓ PASS - no FAIL-level findings"
elif [[ $EXIT_CODE -eq 1 ]]; then
  echo "Result: ⚠ WARN - warnings found but no failures"
elif [[ $EXIT_CODE -eq 2 ]]; then
  echo "Result: ✗ FAIL - one or more FAIL-level findings detected"
  echo "  Review $SCAN_DIR/$RESULTS_FILE for details"
else
  echo "Result: Scan exited with code $EXIT_CODE"
fi

exit $EXIT_CODE
