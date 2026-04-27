@echo off
REM Run Lazeport with Caddy reverse proxy (automatic HTTPS)

echo Starting Lazeport with Caddy...

REM Check if Caddy is installed
where caddy >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Caddy is not installed.
    echo.
    echo Download from: https://caddyserver.com/download
    echo Or install with: winget install Caddy.Caddy
    pause
    exit /b 1
)

REM Build frontend if needed
powershell -NoProfile -Command "if (-not (Test-Path 'frontend/dist')) { exit 1 } $src=(Get-ChildItem 'frontend/src' -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime; $dist=(Get-ChildItem 'frontend/dist' -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime; if ($src -gt $dist) { exit 1 }"
if %ERRORLEVEL% NEQ 0 (
    echo Building frontend...
    cd frontend
    call pnpm install
    call pnpm run build
    cd ..
)

REM Start FastAPI on port 8001 in background
echo Starting FastAPI backend on port 8001...
start /B uvicorn app.main:app --host 127.0.0.1 --port 8001 --reload

REM Wait for backend
timeout /t 3 /nobreak >nul

REM Start Caddy on port 8000
echo Starting Caddy on port 8000...
echo.
echo Lazeport is running at:
echo   http://localhost:8000
echo.
echo Press Ctrl+C to stop
echo.

caddy run --config Caddyfile
