#!/usr/bin/env sh
set -e
pnpm install
pnpm run build
pnpm run dev
