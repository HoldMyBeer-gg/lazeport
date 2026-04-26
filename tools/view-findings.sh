#!/usr/bin/env bash
# Wrapper to launch security findings TUI

set -euo pipefail

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

# Check if textual is installed
if ! python3 -c "import textual" 2>/dev/null; then
  echo "Installing required dependencies..."
  pip3 install -q -r tools/requirements.txt
  echo "✓ Dependencies installed"
  echo ""
fi

# Launch TUI
exec python3 tools/security_tui.py "$@"
