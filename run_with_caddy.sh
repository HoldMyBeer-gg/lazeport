#!/bin/bash
# Run Lazeport with Caddy reverse proxy (automatic HTTPS)

set -e

echo "🚀 Starting Lazeport with Caddy..."

# Check if Caddy is installed
if ! command -v caddy &> /dev/null; then
    echo "❌ Caddy is not installed."
    echo ""
    echo "Install Caddy:"
    echo "  macOS:   brew install caddy"
    echo "  Linux:   See https://caddyserver.com/docs/install"
    echo "  Windows: See https://caddyserver.com/docs/install"
    exit 1
fi

# Build frontend if needed
if [ ! -d "frontend/dist" ] || [ "$(find frontend/src -newer frontend/dist -print -quit)" ]; then
    echo "📦 Building frontend..."
    cd frontend && pnpm install && pnpm run build && cd ..
fi

# Start FastAPI on port 8001 in background
echo "🐍 Starting FastAPI backend on port 8001..."
uvicorn app.main:app --host 127.0.0.1 --port 8001 --reload &
BACKEND_PID=$!

# Wait for backend to be ready
echo "⏳ Waiting for backend to start..."
sleep 3

# Start Caddy on port 8000
echo "🌐 Starting Caddy on port 8000..."
echo ""
echo "✅ Lazeport is running at:"
echo "   http://localhost:8000"
echo ""
echo "Press Ctrl+C to stop both services"
echo ""

# Trap Ctrl+C to kill both processes
trap "echo ''; echo '🛑 Stopping services...'; kill $BACKEND_PID 2>/dev/null; pkill -P $$ 2>/dev/null; exit" INT TERM

# Run Caddy in foreground
caddy run --config Caddyfile

# Cleanup on exit
kill $BACKEND_PID 2>/dev/null
