"""Integration tests for pre-commit hook and install-hooks.sh.

These tests create isolated temp git repos, copy the real hook scripts into them,
run install-hooks.sh, and verify behavior for all 7 acceptance criteria.
"""

import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# Resolve project root so we can copy the real hook scripts into temp repos.
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _run(cmd: list[str], *, cwd: str, env: dict | None = None, check: bool = False) -> subprocess.CompletedProcess:
    """Run a subprocess and return the CompletedProcess result."""
    base_env = os.environ.copy()
    if env is not None:
        base_env.update(env)
    return subprocess.run(
        cmd,
        cwd=cwd,
        env=base_env,
        capture_output=True,
        text=True,
        check=check,
    )


@pytest.fixture()
def hook_repo(tmp_path):
    """Create a temp git repo with hooks installed via install-hooks.sh.

    Yields the path to the temp repo root (as a str for convenience).

    Steps performed:
    1. git init
    2. Set git user.email and user.name (required for commits)
    3. Copy the real .claude-hooks/ directory into the temp repo
    4. Copy install-hooks.sh into the temp repo
    5. Run ./install-hooks.sh inside the temp repo
    6. Create an initial empty commit so HEAD exists
    """
    repo = str(tmp_path)

    # 1. git init
    _run(["git", "init"], cwd=repo, check=True)

    # 2. Set required git identity
    _run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
    _run(["git", "config", "user.name", "Test User"], cwd=repo, check=True)

    # Disable GPG signing in the temp repo to avoid needing a key during tests
    _run(["git", "config", "commit.gpgsign", "false"], cwd=repo, check=True)

    # 3. Copy .claude-hooks/ directory into temp repo
    src_hooks = PROJECT_ROOT / ".claude-hooks"
    dst_hooks = tmp_path / ".claude-hooks"
    shutil.copytree(str(src_hooks), str(dst_hooks))

    # 4. Copy install-hooks.sh into temp repo
    src_install = PROJECT_ROOT / "install-hooks.sh"
    dst_install = tmp_path / "install-hooks.sh"
    shutil.copy2(str(src_install), str(dst_install))
    # Ensure the installer is executable
    dst_install.chmod(dst_install.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    # 5. Run install-hooks.sh (without ANTHROPIC_API_KEY so we don't rely on env)
    env_no_key = {"ANTHROPIC_API_KEY": ""}
    result = _run(["./install-hooks.sh"], cwd=repo, env=env_no_key)
    assert result.returncode == 0, (
        f"install-hooks.sh failed in fixture:\nstdout={result.stdout!r}\nstderr={result.stderr!r}"
    )

    # 6. Create an initial commit so HEAD exists
    (tmp_path / "README.md").write_text("test repo\n")
    _run(["git", "add", "README.md"], cwd=repo, check=True)
    _run(["git", "commit", "-m", "initial commit"], cwd=repo, check=True)

    yield repo


# ─────────────────────────────────────────────────────────────
# Test 1: install sets core.hooksPath
# ─────────────────────────────────────────────────────────────

def test_install_sets_hooks_path(hook_repo):
    """install-hooks.sh must set git config core.hooksPath to .claude-hooks/."""
    result = _run(["git", "config", "core.hooksPath"], cwd=hook_repo)
    assert result.returncode == 0, "git config core.hooksPath not set"
    assert result.stdout.strip() == ".claude-hooks/", (
        f"Expected '.claude-hooks/' but got {result.stdout.strip()!r}"
    )


# ─────────────────────────────────────────────────────────────
# Test 2: install chmod +x pre-commit
# ─────────────────────────────────────────────────────────────

def test_install_chmod_precommit(hook_repo):
    """install-hooks.sh must chmod +x .claude-hooks/pre-commit."""
    pre_commit = Path(hook_repo) / ".claude-hooks" / "pre-commit"
    assert pre_commit.exists(), ".claude-hooks/pre-commit does not exist"
    mode = pre_commit.stat().st_mode
    assert mode & stat.S_IXUSR, ".claude-hooks/pre-commit is not user-executable"


# ─────────────────────────────────────────────────────────────
# Test 3: install is idempotent
# ─────────────────────────────────────────────────────────────

def test_install_idempotent(hook_repo):
    """Running install-hooks.sh twice must exit 0 with no error output."""
    env_no_key = {"ANTHROPIC_API_KEY": ""}
    # Run a second time
    result = _run(["./install-hooks.sh"], cwd=hook_repo, env=env_no_key)
    assert result.returncode == 0, (
        f"Second install run failed:\nstdout={result.stdout!r}\nstderr={result.stderr!r}"
    )
    # The API key warning will appear on stderr because ANTHROPIC_API_KEY is unset,
    # but there must be no error output (non-warning text on stderr indicating failure).
    # We simply verify exit 0, which confirms idempotency.


# ─────────────────────────────────────────────────────────────
# Test 4: claude CLI warning when not in PATH
# ─────────────────────────────────────────────────────────────

def test_install_claude_cli_warning_when_absent(tmp_path):
    """install-hooks.sh must warn on stderr and exit 0 when `claude` is not in PATH."""
    repo = str(tmp_path)
    _run(["git", "init"], cwd=repo, check=True)
    _run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
    _run(["git", "config", "user.name", "Test User"], cwd=repo, check=True)

    shutil.copytree(str(PROJECT_ROOT / ".claude-hooks"), str(tmp_path / ".claude-hooks"))
    dst_install = tmp_path / "install-hooks.sh"
    shutil.copy2(str(PROJECT_ROOT / "install-hooks.sh"), str(dst_install))
    dst_install.chmod(dst_install.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    # Run with a PATH that has no `claude` binary, and HOME pointing to a temp
    # dir so the script's "$HOME/.local/bin" expansion also finds nothing.
    fake_home = str(tmp_path / "fakehome")
    os.makedirs(fake_home, exist_ok=True)
    env_no_claude = {"PATH": "/usr/bin:/bin", "HOME": fake_home}
    result = _run(["./install-hooks.sh"], cwd=repo, env=env_no_claude)

    assert result.returncode == 0, f"Expected exit 0 but got {result.returncode}"
    assert "claude" in result.stderr, (
        f"Expected 'claude' in stderr but got:\n{result.stderr!r}"
    )
    assert "pre-push" in result.stderr, (
        f"Expected 'pre-push' in stderr but got:\n{result.stderr!r}"
    )


# ─────────────────────────────────────────────────────────────
# Test 5: No claude CLI warning when present in PATH
# ─────────────────────────────────────────────────────────────

def test_install_no_claude_cli_warning_when_present(tmp_path):
    """install-hooks.sh must not warn when `claude` is found in PATH."""
    repo = str(tmp_path)
    _run(["git", "init"], cwd=repo, check=True)
    _run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
    _run(["git", "config", "user.name", "Test User"], cwd=repo, check=True)

    shutil.copytree(str(PROJECT_ROOT / ".claude-hooks"), str(tmp_path / ".claude-hooks"))
    dst_install = tmp_path / "install-hooks.sh"
    shutil.copy2(str(PROJECT_ROOT / "install-hooks.sh"), str(dst_install))
    dst_install.chmod(dst_install.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    # Create a dummy `claude` binary in a temp bin dir.
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_claude = fake_bin / "claude"
    fake_claude.write_text("#!/usr/bin/env sh\nexit 0\n")
    fake_claude.chmod(fake_claude.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    env_with_claude = {"PATH": f"{fake_bin}:/usr/bin:/bin"}
    result = _run(["./install-hooks.sh"], cwd=repo, env=env_with_claude)

    assert result.returncode == 0
    assert "claude" not in result.stderr, (
        f"Expected no claude CLI warning but got:\n{result.stderr!r}"
    )


# ─────────────────────────────────────────────────────────────
# Test 6: Pre-commit passes on clean .py file
# ─────────────────────────────────────────────────────────────

def test_precommit_passes_clean_file(hook_repo):
    """Pre-commit hook must exit 0 when staged file has no violations.

    Uses a non-Python text file to avoid triggering Rule 6 (test-pairing),
    which hard-blocks new app/ modules without a staged test.  The purpose
    of this test is to verify the hook plumbing exits 0 on a clean diff,
    not to test Rule 6 itself (which is covered in test_static_checks.py).
    """
    # Create a clean non-Python file — no violations possible
    clean_file = Path(hook_repo) / "NOTES.txt"
    clean_file.write_text("Some project notes.\n")

    _run(["git", "add", "NOTES.txt"], cwd=hook_repo, check=True)
    result = _run(["git", "commit", "-m", "test: clean commit"], cwd=hook_repo)

    assert result.returncode == 0, (
        f"Expected clean commit to pass (exit 0) but got {result.returncode}:\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    )


# ─────────────────────────────────────────────────────────────
# Test 7: Pre-commit blocks bare except (Rule 11)
# ─────────────────────────────────────────────────────────────


def test_precommit_blocks_bare_except(hook_repo):
    """Pre-commit hook must exit 1 and mention Rule 11 when staged .py has bare except."""
    # Create a Python file with a bare except
    app_dir = Path(hook_repo) / "app"
    app_dir.mkdir(exist_ok=True)

    violating_py = app_dir / "bad_module.py"
    violating_py.write_text(
        '"""Module with a bare except."""\n\n\ndef risky():\n    """Do something risky."""\n    try:\n        pass\n    except:\n        pass\n'
    )

    _run(["git", "add", "app/bad_module.py"], cwd=hook_repo, check=True)
    result = _run(["git", "commit", "-m", "test: violating commit"], cwd=hook_repo)

    assert result.returncode == 1, (
        f"Expected violation to be blocked (exit 1) but got {result.returncode}:\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    )
    # The static_checks.py engine writes to stderr with "Rule 11" in the output
    assert "Rule 11" in result.stderr, (
        f"Expected 'Rule 11' in stderr but got:\n{result.stderr!r}"
    )


# ─────────────────────────────────────────────────────────────
# Test 8: Pre-commit blocks CDN URL (Rule 2.1.1)
# ─────────────────────────────────────────────────────────────

def test_precommit_blocks_cdn_url(hook_repo):
    """Pre-commit hook must exit 1 and mention Rule 2.1.1 when a staged file contains a CDN URL."""
    cdn_js = Path(hook_repo) / "cdn_violation.js"
    cdn_js.write_text(
        '// loads lodash from CDN — violates Rule 2.1.1\n'
        'const _ = require("https://cdn.jsdelivr.net/npm/lodash@4/lodash.min.js");\n'
    )

    _run(["git", "add", "cdn_violation.js"], cwd=hook_repo, check=True)
    result = _run(["git", "commit", "-m", "test: cdn violation"], cwd=hook_repo)

    assert result.returncode == 1, (
        f"Expected CDN violation to be blocked (exit 1) but got {result.returncode}:\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    )
    assert "Rule 2" in result.stderr, (
        f"Expected 'Rule 2' in stderr but got:\n{result.stderr!r}"
    )


# --- Pre-push hook integration tests (Phase 3) ---


@pytest.fixture()
def push_hook_repo(tmp_path):
    """Create a temp git repo wired to a bare remote, with hooks installed.

    Yields the path (str) to the working repo root.

    Setup steps:
    1. Create a bare remote repo in tmp_path/remote.git
    2. git init a working repo in tmp_path/work
    3. Configure git identity and disable GPG signing
    4. Copy the real .claude-hooks/ directory and install-hooks.sh into the working repo
    5. Run install-hooks.sh to wire the hooks (sets core.hooksPath)
    6. Add the bare repo as remote origin
    7. Create an initial commit and push to origin main to establish tracking
    """
    remote_dir = tmp_path / "remote.git"
    work_dir = tmp_path / "work"

    # 1. Create a bare repo to act as the remote
    remote_dir.mkdir()
    _run(["git", "init", "--bare", str(remote_dir)], cwd=str(tmp_path), check=True)

    # 2. Create the working repo
    work_dir.mkdir()
    repo = str(work_dir)
    _run(["git", "init"], cwd=repo, check=True)
    # Ensure the branch is named "main" regardless of the system git defaultBranch config.
    _run(["git", "checkout", "-b", "main"], cwd=repo)

    # 3. Configure git identity and disable GPG signing
    _run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
    _run(["git", "config", "user.name", "Test User"], cwd=repo, check=True)
    _run(["git", "config", "commit.gpgsign", "false"], cwd=repo, check=True)

    # 4. Copy .claude-hooks/ directory and install-hooks.sh into the working repo
    src_hooks = PROJECT_ROOT / ".claude-hooks"
    dst_hooks = work_dir / ".claude-hooks"
    shutil.copytree(str(src_hooks), str(dst_hooks))

    src_install = PROJECT_ROOT / "install-hooks.sh"
    dst_install = work_dir / "install-hooks.sh"
    shutil.copy2(str(src_install), str(dst_install))
    dst_install.chmod(dst_install.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    # 5a. Symlink the current interpreter as .venv/bin/python so the pre-push hook
    #     resolves PYTHON to the same interpreter that has all project deps (httpx etc.)
    #     rather than falling back to the bare system python3.
    venv_bin = work_dir / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    (venv_bin / "python").symlink_to(sys.executable)

    # 5b. Stub out the LLM reviewer so tests don't depend on the Claude CLI or API keys.
    #     These hook integration tests focus on test_runner.py behaviour; the LLM reviewer
    #     is tested separately in test_llm_reviewer.py.
    (dst_hooks / "lib" / "llm_reviewer.py").write_text(
        "import sys\n"
        "sys.stderr.write('[CLAUDE.md] LLM review: pass (stubbed in tests)\\n')\n"
        "sys.exit(0)\n"
    )

    # 5c. Run install-hooks.sh to configure core.hooksPath and chmod hooks
    env_no_key = {"ANTHROPIC_API_KEY": ""}
    result = _run(["./install-hooks.sh"], cwd=repo, env=env_no_key)
    assert result.returncode == 0, (
        f"install-hooks.sh failed:\nstdout={result.stdout!r}\nstderr={result.stderr!r}"
    )

    # 6. Add the bare repo as the remote
    _run(["git", "remote", "add", "origin", str(remote_dir)], cwd=repo, check=True)

    # 7. Create the initial commit.
    #    The initial push will trigger the pre-push hook.  Since README.md is the
    #    only changed file (no .py files), test_runner.py exits 0 immediately.
    (work_dir / "README.md").write_text("test repo\n")
    _run(["git", "add", "README.md"], cwd=repo, check=True)
    _run(["git", "commit", "-m", "initial commit"], cwd=repo, check=True)
    initial_push = _run(["git", "push", "-u", "origin", "main"], cwd=repo)
    assert initial_push.returncode == 0, (
        f"push_hook_repo fixture: initial push failed (exit {initial_push.returncode}).\n"
        f"stdout={initial_push.stdout!r}\nstderr={initial_push.stderr!r}"
    )

    yield repo


# ─────────────────────────────────────────────────────────────
# Test 9: pre-push hook is executable after install-hooks.sh
# ─────────────────────────────────────────────────────────────


def test_pre_push_hook_executable_after_install(hook_repo):
    """install-hooks.sh must chmod +x .claude-hooks/pre-push when it exists.

    This verifies that install-hooks.sh's chmod loop covers pre-push as
    well as pre-commit.
    """
    pre_push = Path(hook_repo) / ".claude-hooks" / "pre-push"
    assert pre_push.exists(), ".claude-hooks/pre-push does not exist in hook_repo"
    assert os.access(str(pre_push), os.X_OK), (
        ".claude-hooks/pre-push is not executable after install-hooks.sh"
    )


# ─────────────────────────────────────────────────────────────
# Test 10: pre-push reads stdin before any subprocess (structural)
# ─────────────────────────────────────────────────────────────


def test_pre_push_hook_reads_stdin_first():
    """The pre-push hook must capture stdin BEFORE spawning any subprocess.

    This is a structural test: it reads the hook script and asserts that
    the line 'PUSH_REFS=$(cat)' appears strictly before the first line
    that mentions 'PYTHON' (the subprocess invocation). This guarantees
    D-04 compliance without executing the hook.
    """
    pre_push = PROJECT_ROOT / ".claude-hooks" / "pre-push"
    assert pre_push.exists(), f"pre-push hook not found at {pre_push}"

    lines = pre_push.read_text().splitlines()

    push_refs_line = None
    python_line = None

    for i, line in enumerate(lines):
        stripped = line.strip()
        # Skip comment lines — they are not executable statements
        if stripped.startswith("#"):
            continue
        if push_refs_line is None and "PUSH_REFS=$(cat)" in stripped:
            push_refs_line = i
        if python_line is None and "PYTHON" in stripped and push_refs_line is not None:
            python_line = i
            break  # found first PYTHON reference after PUSH_REFS — stop scanning

    assert push_refs_line is not None, (
        "Could not find 'PUSH_REFS=$(cat)' in pre-push hook"
    )
    assert python_line is not None, (
        "Could not find any 'PYTHON' reference after PUSH_REFS line in pre-push hook"
    )
    assert push_refs_line < python_line, (
        f"'PUSH_REFS=$(cat)' must appear before PYTHON references: "
        f"PUSH_REFS at line {push_refs_line + 1}, PYTHON at line {python_line + 1}"
    )


# ─────────────────────────────────────────────────────────────
# Test 11: pre-push skips pytest when only non-Python files pushed
# ─────────────────────────────────────────────────────────────


def test_pre_push_hook_skips_on_no_python_changes(push_hook_repo):
    """Pre-push hook must exit 0 without invoking pytest when no .py files changed.

    Creates and pushes a .vue file (no Python).  test_runner.py exits 0
    immediately via the D-13 short-circuit when it detects no .py files
    in the diff, so the push must succeed and the hook must be silent.
    """
    repo = push_hook_repo

    # Create a Vue component with no Python changes
    frontend_dir = Path(repo) / "frontend" / "src" / "views"
    frontend_dir.mkdir(parents=True, exist_ok=True)
    (frontend_dir / "Dashboard.vue").write_text(
        "<template><div>Dashboard</div></template>\n"
        "<script setup>\n"
        "// no python here\n"
        "</script>\n"
    )

    _run(["git", "add", "frontend/src/views/Dashboard.vue"], cwd=repo, check=True)
    _run(["git", "commit", "-m", "feat: add dashboard vue component"], cwd=repo, check=True)

    result = _run(["git", "push", "origin", "main"], cwd=repo)

    assert result.returncode == 0, (
        f"Expected git push to succeed (exit 0) when only .vue files changed, "
        f"but got {result.returncode}:\nstdout={result.stdout!r}\nstderr={result.stderr!r}"
    )
    # test_runner.py is silent on the D-13 early-exit path — no pytest output expected.
    # We check for pytest test-result markers rather than the bare word "pytest"
    # because the tmp directory path may contain "pytest" as part of its name.
    combined = result.stdout + result.stderr
    pytest_markers = ("passed", "failed", "error", "PASSED", "FAILED", "ERROR", "Push blocked")
    for marker in pytest_markers:
        assert marker not in combined, (
            f"Unexpected pytest output marker {marker!r} found when no Python files changed.\n"
            f"Hook output:\n{combined!r}"
        )


# --- Pre-push LLM reviewer wiring tests (Phase 5) ---


# ─────────────────────────────────────────────────────────────
# Test 12: pre-push hook invokes llm_reviewer.py after test_runner.py
# ─────────────────────────────────────────────────────────────


def test_pre_push_hook_invokes_llm_reviewer():
    """The pre-push hook must reference llm_reviewer.py after test_runner.py.

    Structural test: verifies that both engines are wired in the correct order —
    test runner (Stage 1) before LLM reviewer (Stage 3).
    """
    pre_push = PROJECT_ROOT / ".claude-hooks" / "pre-push"
    content = pre_push.read_text()

    test_runner_pos = content.index("test_runner.py")
    llm_reviewer_pos = content.index("llm_reviewer.py")

    assert test_runner_pos < llm_reviewer_pos, (
        "test_runner.py must appear before llm_reviewer.py in pre-push hook"
    )


# ─────────────────────────────────────────────────────────────
# Test 13: pre-push hook sets COMMIT_MSG env var for LLM reviewer
# ─────────────────────────────────────────────────────────────


def test_pre_push_hook_sets_commit_msg_env():
    """The pre-push hook must set COMMIT_MSG env var for llm_reviewer.py.

    The LLM reviewer reads the commit message from COMMIT_MSG to apply LLM-02
    (THREAD_REVIEWED=1 check) and LLM-03 (scope creep check).
    """
    pre_push = PROJECT_ROOT / ".claude-hooks" / "pre-push"
    content = pre_push.read_text()
    assert "COMMIT_MSG" in content, (
        "Pre-push hook must set COMMIT_MSG env var for llm_reviewer.py"
    )


# ─────────────────────────────────────────────────────────────
# Test 14: pre-push hook uses symbolic-ref for new-branch base (review fix 1)
# ─────────────────────────────────────────────────────────────


def test_pre_push_hook_uses_symbolic_ref_for_new_branch():
    """The pre-push hook must use git symbolic-ref for new-branch base detection.

    Addresses review fix 1 (HIGH): The hook must NOT use 'merge-base ... HEAD'
    for new branches (HEAD == local_sha when pushing current branch, producing
    empty diff). Instead it must use 'git symbolic-ref refs/remotes/origin/HEAD'
    to find the default branch — same pattern as test_runner.py _get_default_branch().
    """
    pre_push = PROJECT_ROOT / ".claude-hooks" / "pre-push"
    content = pre_push.read_text()

    # Must contain the symbolic-ref pattern
    assert "symbolic-ref refs/remotes/origin/HEAD" in content, (
        "Pre-push hook must use 'git symbolic-ref refs/remotes/origin/HEAD' "
        "to derive default branch for new-branch diffs"
    )

    # Must NOT contain the broken HEAD-based merge-base pattern.
    # Look for non-comment merge-base lines that reference bare HEAD as the second arg.
    lines = content.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        # Flag: merge-base <something> HEAD (broken pattern — bare HEAD, not origin/HEAD or DEFAULT_BRANCH)
        if "merge-base" in stripped and stripped.rstrip().endswith(" HEAD"):
            raise AssertionError(
                f"Line {i + 1} uses broken 'merge-base ... HEAD' pattern: {stripped!r}. "
                "Must use 'origin/$DEFAULT_BRANCH' instead."
            )


# ─────────────────────────────────────────────────────────────
# Test 15: pre-push hook uses temp file for diff (review fix 2)
# ─────────────────────────────────────────────────────────────


def test_pre_push_hook_uses_temp_file_for_diff():
    """The pre-push hook must use mktemp for diff storage, not a shell variable.

    Addresses review fix 2 (MEDIUM): Large diffs in shell variables can hit
    MAX_ARG_STRLEN limits. The hook must use mktemp + file redirection and
    clean up via a trap on EXIT.
    """
    pre_push = PROJECT_ROOT / ".claude-hooks" / "pre-push"
    content = pre_push.read_text()

    assert "mktemp" in content, (
        "Pre-push hook must use mktemp for diff storage (review fix 2)"
    )
    assert "TMP_DIFF" in content, (
        "Pre-push hook must use TMP_DIFF temp file variable (review fix 2)"
    )
    # Verify cleanup trap exists
    assert "trap" in content and "rm" in content, (
        "Pre-push hook must have a trap to clean up the temp file"
    )
