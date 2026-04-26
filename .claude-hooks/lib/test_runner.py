#!/usr/bin/env python3
"""Pre-push test runner for CLAUDE.md Rules 5 and 14.

Reads pushed ref pairs from stdin, computes the union of changed files across
all refs, and conditionally runs pytest suites based on what changed:

  - PUSH-01 / Rule 5:  If any app/**/*.py file changed → run RBAC test suite.
  - PUSH-02 / Rule 14: If any docxtpl-related file changed → run docxtpl tests.

All output goes to stderr so git does not interpret it as a protocol message.
Exit 0 on success (or no relevant files changed). Exit 1 to block the push.

Designed to be called from .claude-hooks/pre-push (thin POSIX sh wrapper).
Stdlib-only — no third-party packages required.
"""
import os
import re
import subprocess
import sys

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ZERO_SHA = "0" * 40

DOCXTPL_EXACT = {
    "app/services/docx_builder.py",
    "app/services/master_docx.py",
}
DOCXTPL_PREFIX = "templates/"
DOCXTPL_SUFFIX = ".docx"


# ---------------------------------------------------------------------------
# Ref parsing
# ---------------------------------------------------------------------------


def parse_push_refs(stdin_text: str) -> list[tuple[str, str, str, str]]:
    """Parse pre-push stdin into (local_ref, local_sha, remote_ref, remote_sha) tuples.

    Git pre-push hook stdin format (one line per ref being pushed):
      <local_ref> <local_sha> <remote_ref> <remote_sha>

    Lines with a number of fields other than 4 are silently skipped.

    Args:
        stdin_text: Full text read from stdin.

    Returns:
        List of 4-tuples; empty list when stdin is empty or has no valid lines.
    """
    refs = []
    for line in stdin_text.strip().splitlines():
        parts = line.split()
        if len(parts) == 4:
            refs.append(tuple(parts))
    return refs


# ---------------------------------------------------------------------------
# Default branch detection
# ---------------------------------------------------------------------------


def _get_default_branch() -> str:
    """Resolve the remote HEAD branch name without a network call.

    Uses `git symbolic-ref refs/remotes/origin/HEAD` which reads a local ref,
    avoiding the network hang that `git remote show origin` can cause in
    test environments (Pitfall 6).

    Returns:
        Branch name string (e.g. 'main', 'master'). Falls back to 'main'
        if the symbolic-ref is not set or the command fails.
    """
    result = subprocess.run(
        ["git", "symbolic-ref", "refs/remotes/origin/HEAD"],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        # Returns "refs/remotes/origin/main" → extract last segment "main"
        return result.stdout.strip().split("/")[-1]
    return "main"  # safe fallback


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------


def get_changed_files(remote_sha: str, local_sha: str) -> list[str]:
    """Return the list of file paths changed between remote_sha and local_sha.

    Handles the new-branch case where remote_sha is all zeros (ZERO_SHA):
    instead of passing the invalid zero SHA to `git diff`, the function
    resolves the merge-base with the default branch and diffs from there.
    Falls back to `git log --name-only` if merge-base computation fails
    (e.g. brand-new repo with no common ancestor).

    Args:
        remote_sha: The SHA the remote currently points to. ZERO_SHA on new branch.
        local_sha:  The SHA being pushed (local tip).

    Returns:
        List of non-empty file path strings.
    """
    if remote_sha == ZERO_SHA:
        # New branch: find the merge-base with the default remote branch so we
        # only diff the commits unique to this branch (D-06).
        default_branch = _get_default_branch()
        try:
            mb_result = subprocess.run(
                ["git", "merge-base", "HEAD", default_branch],
                capture_output=True,
                text=True,
                check=True,
            )
            base = mb_result.stdout.strip()
        except subprocess.CalledProcessError:
            # No common ancestor (e.g. orphan branch) — list all files in the SHA.
            result = subprocess.run(
                ["git", "log", "--name-only", "--format=", local_sha],
                capture_output=True,
                text=True,
            )
            return [f for f in result.stdout.splitlines() if f]
        remote_sha = base

    result = subprocess.run(
        ["git", "diff", "--name-only", remote_sha, local_sha],
        capture_output=True,
        text=True,
    )
    return [f for f in result.stdout.splitlines() if f]


# ---------------------------------------------------------------------------
# Trigger rules
# ---------------------------------------------------------------------------


def needs_rbac_tests(changed_files: list[str]) -> bool:
    """Return True if any app/**/*.py file appears in the changed file list.

    Implements PUSH-01 / Rule 5: any change to a production Python module
    under app/ must have the full RBAC test suite pass before reaching the
    remote repository.

    Args:
        changed_files: List of repo-relative file paths from the push diff.

    Returns:
        True if RBAC tests should run; False otherwise.
    """
    return any(f.startswith("app/") and f.endswith(".py") for f in changed_files)


def needs_docxtpl_tests(changed_files: list[str]) -> bool:
    """Return True if any docxtpl-related file appears in the changed file list.

    Implements PUSH-02 / Rule 14: changes to docxtpl template files or the
    DOCX builder/master services must have the docxtpl token test suite pass
    to guard against silent rendering failures.

    Triggers on:
      - app/services/docx_builder.py (DOCXTPL_EXACT)
      - app/services/master_docx.py  (DOCXTPL_EXACT)
      - Any *.docx file              (DOCXTPL_SUFFIX)
      - Any path under templates/    (DOCXTPL_PREFIX)

    Args:
        changed_files: List of repo-relative file paths from the push diff.

    Returns:
        True if docxtpl tests should run; False otherwise.
    """
    for f in changed_files:
        if f in DOCXTPL_EXACT:
            return True
        if f.startswith(DOCXTPL_PREFIX):
            return True
        if f.endswith(DOCXTPL_SUFFIX):
            return True
    return False


# ---------------------------------------------------------------------------
# pytest invocation
# ---------------------------------------------------------------------------


def run_pytest(args: list[str]) -> tuple[int, str]:
    """Run pytest with the given arguments using the current interpreter.

    Uses sys.executable to ensure pytest runs inside the same virtual
    environment as this script (D-09), not a system-level pytest that may
    be missing application dependencies.

    Args:
        args: Additional arguments to pass to pytest after `-m pytest`.

    Returns:
        Tuple of (exit_code, combined_output) where combined_output is the
        concatenation of stdout and stderr from the pytest process.
    """
    result = subprocess.run(
        [sys.executable, "-m", "pytest"] + args,
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout + result.stderr


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _count_failures(pytest_output: str) -> int:
    """Parse pytest output to extract the number of test failures.

    Matches the pytest summary line format: "N failed, M passed in X.Xs".

    Args:
        pytest_output: Combined stdout+stderr from a pytest run.

    Returns:
        Integer failure count, or 1 if the count cannot be parsed (e.g.
        collection error — assume at least one failure).
    """
    match = re.search(r"(\d+) failed", pytest_output)
    if match:
        return int(match.group(1))
    return 1  # unknown count — assume at least one


def report_failure(suite_name: str, pytest_output: str) -> None:
    """Write pytest output and a block message to stderr.

    All output goes to stderr to avoid git interpreting pre-push stdout as
    a protocol message (D-15, D-17). No banner or framing is added around
    the raw pytest output.

    Args:
        suite_name:   Human-readable name for the test suite (e.g. 'RBAC').
        pytest_output: Combined stdout+stderr from the failed pytest run.
    """
    sys.stderr.write(pytest_output)
    n = _count_failures(pytest_output)
    sys.stderr.write(
        f"\nPush blocked: {n} test failure(s) in {suite_name}. Fix before pushing.\n"
    )


# ---------------------------------------------------------------------------
# pytest availability check
# ---------------------------------------------------------------------------


def _check_pytest_available() -> bool:
    """Return True if pytest is importable from the current interpreter.

    Uses `python -m pytest --version` which exits 0 when pytest is available
    and returns a non-zero code when it is not installed in the current env.

    Returns:
        True if pytest is available; False otherwise.
    """
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--version"],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    """Parse push refs, compute changed files, run triggered test suites.

    Reads git push ref lines from stdin, computes the union of all changed
    files across every ref pair, then conditionally runs test suites based
    on which files changed. Implements D-07, D-10 through D-17.

    Returns:
        0 if all triggered suites pass (or no suites were triggered).
        1 if any triggered suite fails, or if pytest is unavailable.
    """
    stdin_text = sys.stdin.read()
    refs = parse_push_refs(stdin_text)

    if not refs:
        # No refs to push (delete-only push or empty input) — nothing to check.
        return 0

    # Collect the union of changed files across all pushed ref pairs (D-07).
    changed: set[str] = set()
    for local_ref, local_sha, remote_ref, remote_sha in refs:
        changed.update(get_changed_files(remote_sha, local_sha))

    changed_list = list(changed)

    # D-13: No Python files changed → exit immediately with zero latency impact.
    if not any(f.endswith(".py") for f in changed_list):
        sys.stderr.write("[CLAUDE.md] test runner: no Python files changed — skipped\n")
        return 0

    # D-10: Verify pytest is reachable before attempting to run any suite.
    if not _check_pytest_available():
        sys.stderr.write(
            "ERROR: pytest not found. Run: pip install -r requirements.txt\n"
        )
        return 1

    # D-14: Run RBAC first; block immediately on first failure.
    if needs_rbac_tests(changed_list):
        code, output = run_pytest(["tests/", "--ignore=tests/e2e", "-k", "rbac", "-v", "--tb=short"])
        if code != 0:
            report_failure("RBAC", output)
            return 1

    # D-14: Only run docxtpl suite if RBAC passed (or was not triggered).
    if needs_docxtpl_tests(changed_list):
        code, output = run_pytest(["tests/test_master_docx.py", "-v", "--tb=short"])
        if code != 0:
            report_failure("docxtpl", output)
            return 1

    sys.stderr.write("[CLAUDE.md] test runner: pass\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
