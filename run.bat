@echo off
REM Quick run for Lazeport (backend). Uses .env if present.
if exist .venv\Scripts\activate.bat call .venv\Scripts\activate.bat
echo Backend on http://127.0.0.1:8000
echo Frontend dev: cd frontend ^&^& pnpm install ^&^& pnpm run dev
REM Build frontend if dist is missing or stale
powershell -NoProfile -Command "if (-not (Test-Path 'frontend/dist')) { exit 1 } $src=(Get-ChildItem 'frontend/src' -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime; $dist=(Get-ChildItem 'frontend/dist' -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime; if ($src -gt $dist) { exit 1 }"
if %ERRORLEVEL% NEQ 0 (
	echo Building frontend...
	cd frontend
	call pnpm install
	call pnpm run build
	cd ..
)
uvicorn app.main:app --reload
pause
