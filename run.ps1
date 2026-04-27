# Quick run for Lazeport (backend). Uses .env if present.
$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

if (Test-Path ".venv\Scripts\Activate.ps1") {
    & .\.venv\Scripts\Activate.ps1
}

Write-Host "Backend on http://127.0.0.1:8000"
Write-Host "Frontend dev: cd frontend; pnpm install; pnpm run dev"

$needBuild = $false
if (-not (Test-Path "frontend/dist")) {
    $needBuild = $true
} else {
    $srcLatest = Get-ChildItem "frontend/src" -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $distLatest = Get-ChildItem "frontend/dist" -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($srcLatest -and $distLatest -and $srcLatest.LastWriteTime -gt $distLatest.LastWriteTime) {
        $needBuild = $true
    }
}

if ($needBuild) {
    Write-Host "Building frontend..."
    Push-Location frontend
    pnpm install
    pnpm run build
    Pop-Location
}

uvicorn app.main:app --reload
