#!/bin/sh
set -e

# ──────────────────────────────────────────────
# Lazeport — Docker launcher
# Usage:
#   ./run_docker.sh          # Normal: org + admin only, empty workspace
#   ./run_docker.sh --demo   # Demo:   rich seed data for Trends page
#   ./run_docker.sh --no-build  # Skip frontend build (use with build:watch)
#   ./run_docker.sh --rebuild   # Force full image rebuild (fixes missing deps e.g. psycopg2)
# ──────────────────────────────────────────────

DEMO_MODE=0
NO_BUILD=0
REBUILD=0
for arg in "$@"; do
  case "$arg" in
    --demo) DEMO_MODE=1 ;;
    --no-build) NO_BUILD=1 ;;
    --rebuild) REBUILD=1 ;;
    *) echo "Unknown flag: $arg"; exit 1 ;;
  esac
done

# Build frontend unless --no-build (run build:watch in another terminal)
if [ "$NO_BUILD" = "0" ]; then
  cd frontend && pnpm install && rm -rf dist && pnpm run build
  cd ..
else
  if [ ! -d frontend/dist ] || [ ! -f frontend/dist/index.html ]; then
    echo "  dist/ missing — doing one-time build (then use build:watch for changes)"
    cd frontend && pnpm install && pnpm run build
    cd ..
  fi
  echo ""
  echo "  Skipping rebuild. For live frontend updates, run in another terminal:"
  echo "    cd frontend && pnpm run build:watch"
  echo ""
fi

# Export so docker-compose picks it up
export DEMO_MODE

# Ensure PostgreSQL password file exists (Compose reads env_file at startup)
mkdir -p data
DATA_DIR="$(pwd)/data" python3 scripts/ensure_postgres_password.py

# Build app image (shared by app + celery) so dependencies like psycopg2-binary are installed.
if [ "$REBUILD" = "1" ]; then
  docker-compose -f docker-compose.dev.yml build --no-cache app
else
  docker-compose -f docker-compose.dev.yml build app
fi

echo ""
if [ "$DEMO_MODE" = "1" ]; then
  echo "  Starting in DEMO mode (rich seed data for Trends)"
else
  echo "  Starting in NORMAL mode (clean workspace)"
fi
echo "  App: http://localhost:8000"
echo ""

docker-compose -f docker-compose.dev.yml up
