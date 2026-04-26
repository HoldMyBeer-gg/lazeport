$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
pnpm install
pnpm run dev
