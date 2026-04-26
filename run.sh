#!/usr/bin/env sh
# Quick run for Lazeport (backend).
# Usage: ./run.sh          -- run backend only
#        ./run.sh --tmux   -- run Redis, Celery, backend, and frontend dev in a 2x2 tmux session
set -e

SESSION="lazeport"
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

[ -f .venv/bin/activate ] && . .venv/bin/activate

if [ "$1" = "--tmux" ]; then
  if ! command -v tmux >/dev/null 2>&1; then
    echo "tmux is required for --tmux. Install with: brew install tmux"
    exit 1
  fi
  if ! command -v redis-server >/dev/null 2>&1; then
    echo "redis-server is required for --tmux. Install with: brew install redis"
    exit 1
  fi
  if [ ! -d "frontend/dist" ] || [ -n "$(find frontend/src -newer frontend/dist -print -quit 2>/dev/null)" ]; then
    echo "Building frontend..."
    (cd frontend && pnpm install && pnpm run build)
  fi
  if tmux has-session -t "$SESSION" 2>/dev/null; then
    exec tmux attach -t "$SESSION"
  fi
  tmux new-session -d -s "$SESSION" -c "$ROOT" -- "redis-server"
  tmux split-window -h -t "$SESSION" -c "$ROOT" -- sh -c '[ -f .venv/bin/activate ] && . .venv/bin/activate; celery -A app.celery_app worker --loglevel=info'
  tmux split-window -v -t "$SESSION":0.0 -c "$ROOT" -- sh -c '[ -f .venv/bin/activate ] && . .venv/bin/activate; uvicorn app.main:app --reload'
  tmux split-window -v -t "$SESSION":0.1 -c "$ROOT" -- sh -c 'cd frontend && pnpm run dev'
  tmux select-layout -t "$SESSION" tiled
  echo "Launched lazeport in tmux session '$SESSION' (Redis, Celery, Backend, Frontend)"
  exec tmux attach -t "$SESSION"
fi

if [ ! -d "frontend/dist" ] || [ -n "$(find frontend/src -newer frontend/dist -print -quit 2>/dev/null)" ]; then
  echo "Building frontend..."
  (cd frontend && pnpm install && pnpm run build)
fi
echo "Backend on http://127.0.0.1:8000"
echo "Frontend dev: (cd frontend && pnpm install && pnpm run dev)"
exec uvicorn app.main:app --reload
