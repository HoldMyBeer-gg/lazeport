"""Tests for .claude-hooks/lib/test_runner.py — pre-push test runner engine.

Covers:
  - PUSH-01: RBAC trigger logic (app/**/*.py diff detection)
  - PUSH-02: docxtpl trigger logic (master_docx.py, docx_builder.py, *.docx, templates/)
  - Zero-SHA new-branch path (merge-base computation, no fatal git error)
  - No-Python-change early-exit path
  - pytest dispatch, failure counting, stderr output routing
  - pytest availability check
  - main() integration with mocked subprocess
"""
import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Module loader helper
# ---------------------------------------------------------------------------


def _load_test_runner():
    """Load test_runner.py from .claude-hooks/lib/ via importlib (not a package)."""
    spec = importlib.util.spec_from_file_location(
        "test_runner",
        Path(__file__).parent.parent / ".claude-hooks" / "lib" / "test_runner.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# parse_push_refs tests
# ---------------------------------------------------------------------------


def test_parse_push_refs_single_line():
    """Single ref line is parsed into a one-element list of 4-tuples."""
    tr = _load_test_runner()
    result = tr.parse_push_refs(
        "refs/heads/main abc123 refs/heads/main def456\n"
    )
    assert result == [("refs/heads/main", "abc123", "refs/heads/main", "def456")]


def test_parse_push_refs_empty():
    """Empty stdin returns an empty list."""
    tr = _load_test_runner()
    assert tr.parse_push_refs("") == []


def test_parse_push_refs_multiple_lines():
    """Two ref lines are parsed into a two-element list."""
    tr = _load_test_runner()
    stdin = (
        "refs/heads/main abc111 refs/heads/main def222\n"
        "refs/heads/feat bbb333 refs/heads/feat ccc444\n"
    )
    result = tr.parse_push_refs(stdin)
    assert len(result) == 2
    assert result[0] == ("refs/heads/main", "abc111", "refs/heads/main", "def222")
    assert result[1] == ("refs/heads/feat", "bbb333", "refs/heads/feat", "ccc444")


# ---------------------------------------------------------------------------
# trigger logic: needs_rbac_tests
# ---------------------------------------------------------------------------


def test_needs_rbac_tests_true_on_app_py():
    """A file under app/ with .py extension triggers RBAC tests."""
    tr = _load_test_runner()
    assert tr.needs_rbac_tests(["app/services/auth.py"]) is True


def test_needs_rbac_tests_true_on_nested_app_py():
    """A deeply nested app/**/*.py file triggers RBAC tests."""
    tr = _load_test_runner()
    assert tr.needs_rbac_tests(["app/api/admin.py"]) is True


def test_needs_rbac_tests_false_on_vue():
    """A Vue component does not trigger RBAC tests."""
    tr = _load_test_runner()
    assert tr.needs_rbac_tests(["frontend/src/views/Login.vue"]) is False


def test_needs_rbac_tests_false_on_root_py():
    """A .py file at repo root (not under app/) does not trigger RBAC tests."""
    tr = _load_test_runner()
    assert tr.needs_rbac_tests(["conftest.py"]) is False


def test_needs_rbac_tests_false_on_tests_py():
    """A file under tests/ does not trigger RBAC tests (only app/ prefix matters)."""
    tr = _load_test_runner()
    assert tr.needs_rbac_tests(["tests/test_auth.py"]) is False


# ---------------------------------------------------------------------------
# trigger logic: needs_docxtpl_tests
# ---------------------------------------------------------------------------


def test_needs_docxtpl_tests_true_on_master_docx_py():
    """master_docx.py triggers docxtpl tests."""
    tr = _load_test_runner()
    assert tr.needs_docxtpl_tests(["app/services/master_docx.py"]) is True


def test_needs_docxtpl_tests_true_on_docx_builder_py():
    """docx_builder.py triggers docxtpl tests."""
    tr = _load_test_runner()
    assert tr.needs_docxtpl_tests(["app/services/docx_builder.py"]) is True


def test_needs_docxtpl_tests_true_on_docx_file():
    """Any *.docx file triggers docxtpl tests."""
    tr = _load_test_runner()
    assert tr.needs_docxtpl_tests(["reports/output.docx"]) is True


def test_needs_docxtpl_tests_true_on_templates_prefix():
    """Any file under templates/ triggers docxtpl tests."""
    tr = _load_test_runner()
    assert tr.needs_docxtpl_tests(["templates/master.docx"]) is True


def test_needs_docxtpl_tests_false_on_unrelated():
    """An unrelated Python file does not trigger docxtpl tests."""
    tr = _load_test_runner()
    assert tr.needs_docxtpl_tests(["app/services/auth.py"]) is False


# ---------------------------------------------------------------------------
# output: report_failure / _count_failures
# ---------------------------------------------------------------------------


def test_report_failure_writes_stderr(capsys):
    """report_failure writes pytest output and block message to stderr."""
    tr = _load_test_runner()
    tr.report_failure("RBAC", "2 failed, 8 passed in 1.2s")
    captured = capsys.readouterr()
    assert "2 failed, 8 passed" in captured.err
    assert "Push blocked: 2 test failure(s) in RBAC" in captured.err
    assert captured.out == ""


def test_count_failures_parses_pytest_output():
    """_count_failures returns the integer count from pytest summary line."""
    tr = _load_test_runner()
    assert tr._count_failures("2 failed, 8 passed in 1.2s") == 2


def test_count_failures_no_match_returns_one():
    """_count_failures returns 1 when no failure count is found in the output."""
    tr = _load_test_runner()
    assert tr._count_failures("error during collection") == 1


# ---------------------------------------------------------------------------
# pytest availability
# ---------------------------------------------------------------------------


def test_check_pytest_available_true():
    """_check_pytest_available returns True when subprocess returns exit code 0."""
    tr = _load_test_runner()
    mock_result = MagicMock(returncode=0)
    with patch("subprocess.run", return_value=mock_result):
        assert tr._check_pytest_available() is True


def test_check_pytest_available_false_exits(capsys):
    """main() returns 1 and writes 'pytest not found' when pytest is unavailable."""
    tr = _load_test_runner()

    # Simulate: pytest --version check fails, but we also need get_changed_files
    # to return Python files so main() reaches the availability check.
    version_fail = MagicMock(returncode=1, stdout="", stderr="")
    diff_result = MagicMock(returncode=0, stdout="app/services/auth.py\n", stderr="")

    def side_effect(cmd, **kwargs):
        if "--version" in cmd:
            return version_fail
        return diff_result

    stdin_text = "refs/heads/main abc123 refs/heads/main def456\n"
    with patch("subprocess.run", side_effect=side_effect):
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.read.return_value = stdin_text
            result = tr.main()

    assert result == 1
    captured = capsys.readouterr()
    assert "pytest not found" in captured.err


# ---------------------------------------------------------------------------
# diff computation: get_changed_files / _get_default_branch
# ---------------------------------------------------------------------------


def test_zero_sha_uses_merge_base():
    """When remote_sha is all zeros, get_changed_files calls git symbolic-ref then merge-base."""
    tr = _load_test_runner()
    ZERO_SHA = "0" * 40
    local_sha = "abc123"

    symbolic_result = MagicMock(returncode=0, stdout="refs/remotes/origin/main\n", stderr="")
    merge_base_result = MagicMock(returncode=0, stdout="base_sha\n", stderr="")
    diff_result = MagicMock(returncode=0, stdout="app/services/auth.py\n", stderr="")

    call_args_list = []

    def side_effect(cmd, **kwargs):
        call_args_list.append(cmd)
        if "symbolic-ref" in cmd:
            return symbolic_result
        if "merge-base" in cmd:
            return merge_base_result
        if "diff" in cmd:
            return diff_result
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=side_effect):
        files = tr.get_changed_files(ZERO_SHA, local_sha)

    # Verify that symbolic-ref was called (local, no network) and merge-base was called
    called_commands = [" ".join(c) for c in call_args_list]
    assert any("symbolic-ref" in c for c in called_commands), (
        f"Expected symbolic-ref call, got: {called_commands}"
    )
    assert any("merge-base" in c for c in called_commands), (
        f"Expected merge-base call, got: {called_commands}"
    )
    # Must NOT pass the zero SHA directly to git diff
    assert not any(ZERO_SHA in c for c in called_commands), (
        f"Zero SHA must not be passed to git diff: {called_commands}"
    )
    assert "app/services/auth.py" in files


def test_get_default_branch_parses_symbolic_ref():
    """_get_default_branch parses 'refs/remotes/origin/HEAD' output to extract branch name."""
    tr = _load_test_runner()
    mock_result = MagicMock(returncode=0, stdout="refs/remotes/origin/main\n", stderr="")
    with patch("subprocess.run", return_value=mock_result):
        branch = tr._get_default_branch()
    assert branch == "main"


def test_get_default_branch_fallback_to_main():
    """_get_default_branch returns 'main' when symbolic-ref command fails."""
    tr = _load_test_runner()
    mock_result = MagicMock(returncode=1, stdout="", stderr="error")
    with patch("subprocess.run", return_value=mock_result):
        branch = tr._get_default_branch()
    assert branch == "main"


# ---------------------------------------------------------------------------
# main() integration (mocked subprocess)
# ---------------------------------------------------------------------------


def _make_process(returncode=0, stdout="", stderr=""):
    """Convenience factory for CompletedProcess-like mock objects."""
    return MagicMock(returncode=returncode, stdout=stdout, stderr=stderr)


def test_no_python_files_skip():
    """main() with only .vue files changed exits 0 without invoking pytest."""
    tr = _load_test_runner()

    diff_result = _make_process(stdout="frontend/src/views/Login.vue\n")

    run_calls = []

    def side_effect(cmd, **kwargs):
        run_calls.append(cmd)
        return diff_result

    stdin_text = "refs/heads/main abc123 refs/heads/main def456\n"
    with patch("subprocess.run", side_effect=side_effect):
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.read.return_value = stdin_text
            result = tr.main()

    assert result == 0
    # No pytest invocation should have occurred
    for call in run_calls:
        assert "pytest" not in " ".join(call), (
            f"pytest must not be called when no Python files changed: {run_calls}"
        )


def test_rbac_failure_blocks_push(capsys):
    """main() returns 1 and writes to stderr when RBAC pytest exits non-zero."""
    tr = _load_test_runner()

    diff_result = _make_process(stdout="app/services/auth.py\n")
    version_ok = _make_process(stdout="pytest 9.0.2")
    rbac_fail = _make_process(returncode=1, stdout="1 failed, 5 passed in 0.5s\n")

    def side_effect(cmd, **kwargs):
        if "--version" in cmd:
            return version_ok
        if "diff" in cmd:
            return diff_result
        if "pytest" in " ".join(cmd):
            return rbac_fail
        return _make_process()

    stdin_text = "refs/heads/main abc123 refs/heads/main def456\n"
    with patch("subprocess.run", side_effect=side_effect):
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.read.return_value = stdin_text
            result = tr.main()

    assert result == 1
    captured = capsys.readouterr()
    assert "Push blocked" in captured.err


def test_rbac_pass_docxtpl_fail_blocks(capsys):
    """main() returns 1 when RBAC passes but docxtpl suite fails."""
    tr = _load_test_runner()

    # Changed files trigger both RBAC and docxtpl
    diff_result = _make_process(stdout="app/services/master_docx.py\n")
    version_ok = _make_process(stdout="pytest 9.0.2")
    rbac_pass = _make_process(returncode=0, stdout="5 passed in 0.3s\n")
    docxtpl_fail = _make_process(returncode=1, stdout="1 failed, 2 passed in 0.2s\n")

    pytest_calls = []

    def side_effect(cmd, **kwargs):
        if "--version" in cmd:
            return version_ok
        if "diff" in cmd:
            return diff_result
        if "pytest" in " ".join(cmd):
            pytest_calls.append(cmd)
            if "rbac" in " ".join(cmd):
                return rbac_pass
            return docxtpl_fail
        return _make_process()

    stdin_text = "refs/heads/main abc123 refs/heads/main def456\n"
    with patch("subprocess.run", side_effect=side_effect):
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.read.return_value = stdin_text
            result = tr.main()

    assert result == 1
    captured = capsys.readouterr()
    assert "Push blocked" in captured.err


def test_both_pass_returns_zero():
    """main() returns 0 when both RBAC and docxtpl suites pass."""
    tr = _load_test_runner()

    diff_result = _make_process(stdout="app/services/master_docx.py\n")
    version_ok = _make_process(stdout="pytest 9.0.2")
    all_pass = _make_process(returncode=0, stdout="5 passed in 0.3s\n")

    def side_effect(cmd, **kwargs):
        if "--version" in cmd:
            return version_ok
        if "diff" in cmd:
            return diff_result
        return all_pass

    stdin_text = "refs/heads/main abc123 refs/heads/main def456\n"
    with patch("subprocess.run", side_effect=side_effect):
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.read.return_value = stdin_text
            result = tr.main()

    assert result == 0


def test_rbac_fail_skips_docxtpl():
    """main() does NOT invoke docxtpl pytest when RBAC suite fails (block on first failure)."""
    tr = _load_test_runner()

    # master_docx.py triggers both suites
    diff_result = _make_process(stdout="app/services/master_docx.py\n")
    version_ok = _make_process(stdout="pytest 9.0.2")
    rbac_fail = _make_process(returncode=1, stdout="2 failed, 3 passed in 0.4s\n")

    pytest_call_count = [0]
    pytest_cmds = []

    def side_effect(cmd, **kwargs):
        if "--version" in cmd:
            return version_ok
        if "diff" in cmd:
            return diff_result
        if "pytest" in " ".join(cmd):
            pytest_call_count[0] += 1
            pytest_cmds.append(list(cmd))
            return rbac_fail
        return _make_process()

    stdin_text = "refs/heads/main abc123 refs/heads/main def456\n"
    with patch("subprocess.run", side_effect=side_effect):
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.read.return_value = stdin_text
            result = tr.main()

    assert result == 1
    # Only one pytest invocation: RBAC. docxtpl must have been skipped.
    assert pytest_call_count[0] == 1, (
        f"Expected 1 pytest call (RBAC only), got {pytest_call_count[0]}: {pytest_cmds}"
    )
    # The single call must have been the RBAC suite (-k rbac)
    assert "rbac" in " ".join(pytest_cmds[0]), (
        f"The single pytest call should be RBAC, got: {pytest_cmds}"
    )
