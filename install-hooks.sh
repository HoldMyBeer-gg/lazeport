#!/usr/bin/env sh
# ──────────────────────────────────────────────────────────────────────────────
# install-hooks.sh — Configure CLAUDE.md enforcement hooks for this repo
#
# Run once after cloning (or re-run at any time; this script is idempotent):
#
#   ./install-hooks.sh
#
# What this does:
#   1. Sets git config core.hooksPath to .claude-hooks/ so git picks up the
#      pre-commit and pre-push hook scripts committed in this repository.
#   2. chmod +x all hook scripts in .claude-hooks/ (pre-commit, pre-push).
#   3. Soft-warns if the `claude` CLI is not found in PATH.
#      (The CLI is required for the pre-push LLM review; not needed for
#       pre-commit static checks.)
#
# Exit codes:
#   0 — success (always; the claude CLI warning is informational only)
# ──────────────────────────────────────────────────────────────────────────────

# Resolve the repo root (the directory containing this script).
REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# Ensure common tool locations are in PATH for non-interactive shells.
export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin:$HOME/.pyenv/shims:$PATH"

# 1. Configure git to use .claude-hooks/ as the hooks directory.
#    This takes precedence over the global core.hooksPath and over
#    the legacy .git/hooks/ directory.
git -C "$REPO_ROOT" config core.hooksPath .claude-hooks/

# 2. chmod +x hook entry-point scripts (not lib/ helpers).
for hook in pre-commit pre-push; do
    if [ -f "$REPO_ROOT/.claude-hooks/$hook" ]; then
        chmod +x "$REPO_ROOT/.claude-hooks/$hook"
    fi
done

# 3. Soft-warn if the `claude` CLI is not in PATH.
#    Exit 0 regardless — developers can install hooks before installing the CLI.
if ! command -v claude >/dev/null 2>&1; then
    echo "" >&2
    echo "NOTE: 'claude' CLI not found in PATH." >&2
    echo "The Claude Code CLI is required for the pre-push LLM review (not needed for pre-commit static checks)." >&2
    echo "Install it from: https://claude.ai/code" >&2
    echo "" >&2
fi

exit 0
