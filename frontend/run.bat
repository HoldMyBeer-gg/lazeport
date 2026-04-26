@echo off
cd /d %~dp0
call pnpm install
call pnpm run dev
