#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# get-token.sh - Get JWT bearer token from Lazeport API
#
# Usage:
#   ./get-token.sh                                 # Uses default admin creds
#   ./get-token.sh --url http://localhost:8000     # Custom base URL
#   ./get-token.sh --user admin --password secret  # Custom credentials
#
# Output: JWT token (stdout) for use with ZAP --bearer flag
# ---------------------------------------------------------------------------
set -euo pipefail

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

# Defaults
BASE_URL="${BASE_URL:-http://localhost:8000}"
USERNAME="admin"
PASSWORD=""

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --url)      BASE_URL="$2"; shift 2 ;;
    --user)     USERNAME="$2"; shift 2 ;;
    --password) PASSWORD="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 [--url URL] [--user USER] [--password PASS]"
      echo ""
      echo "Gets JWT token from Lazeport API for authenticated scanning."
      echo "Reads admin password from data/.admin_password if not provided."
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Read admin password from file if not provided
if [[ -z "$PASSWORD" ]]; then
  if [[ -f "data/.admin_password" ]]; then
    PASSWORD=$(cat data/.admin_password)
    echo "[get-token] Using password from data/.admin_password" >&2
  else
    echo "Error: data/.admin_password not found and --password not provided" >&2
    echo "Generate it with: python -c 'import secrets; print(secrets.token_urlsafe(32))' > data/.admin_password" >&2
    exit 1
  fi
fi

# Login and extract token
echo "[get-token] Logging in as $USERNAME to $BASE_URL..." >&2

RESPONSE=$(curl -s -X POST "$BASE_URL/auth/login/local" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}" \
  2>&1)

# Check if curl failed
if [[ $? -ne 0 ]]; then
  echo "Error: curl failed. Is the API running at $BASE_URL?" >&2
  exit 1
fi

# Extract token using jq (if available) or python
if command -v jq >/dev/null 2>&1; then
  TOKEN=$(echo "$RESPONSE" | jq -r '.access_token // empty')
elif command -v python3 >/dev/null 2>&1; then
  TOKEN=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('access_token', ''))" 2>/dev/null || echo "")
else
  # Fallback: grep (fragile but works)
  TOKEN=$(echo "$RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4 || echo "")
fi

if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
  echo "Error: Failed to extract token from login response" >&2
  echo "Response was:" >&2
  echo "$RESPONSE" >&2
  exit 1
fi

echo "[get-token] ✓ Token obtained (${#TOKEN} chars)" >&2

# Output just the token to stdout (for piping to other commands)
echo "$TOKEN"
