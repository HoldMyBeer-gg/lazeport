"""Tests for .claude-hooks/lib/static_checks.py — CLAUDE.md compliance engine.

Covers:
  - STATIC-02: bare except detection (6 real tests, Wave 0)
  - INFRA-01: violation message format
  - INFRA-04: staged-index-not-working-tree invariant
  - STATIC-01: CDN URL detection
  - STATIC-03: i18n locale completeness
  - STATIC-04: Python test-file pairing
"""
import os
import subprocess

import pytest


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def git_repo(tmp_path):
    """Create a minimal git repo with an initial commit for testing."""
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    # Create initial commit so HEAD exists
    (tmp_path / "README.md").write_text("init\n")
    subprocess.run(["git", "add", "README.md"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "init", "--no-gpg-sign"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    return tmp_path


def run_checks(repo_path) -> tuple[int, str]:
    """Run static_checks.py --staged in the given repo. Returns (exit_code, stderr)."""
    script = os.path.join(
        os.path.dirname(__file__), "..", ".claude-hooks", "lib", "static_checks.py"
    )
    result = subprocess.run(
        ["python3", script, "--staged"],
        cwd=repo_path,
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stderr


# ---------------------------------------------------------------------------
# STATIC-02 + INFRA-01 + INFRA-04 — real tests (Wave 0)
# ---------------------------------------------------------------------------


def test_bare_except_blocked(git_repo):
    """A staged .py file with `except: pass` must exit non-zero and mention Rule 11."""
    bad = git_repo / "bad.py"
    bad.write_text("try:\n    x = 1\nexcept:\n    pass\n")
    subprocess.run(["git", "add", "bad.py"], cwd=git_repo, check=True, capture_output=True)

    returncode, stderr = run_checks(git_repo)

    assert returncode == 1, f"Expected exit 1, got {returncode}. stderr: {stderr}"
    assert "Rule 11" in stderr, f"Expected 'Rule 11' in stderr. Got: {stderr}"


def test_bare_except_exception_pass_blocked(git_repo):
    """A staged .py file with `except Exception: pass` must exit non-zero and mention Rule 11."""
    bad2 = git_repo / "bad2.py"
    bad2.write_text("try:\n    x = 1\nexcept Exception:\n    pass\n")
    subprocess.run(["git", "add", "bad2.py"], cwd=git_repo, check=True, capture_output=True)

    returncode, stderr = run_checks(git_repo)

    assert returncode == 1, f"Expected exit 1, got {returncode}. stderr: {stderr}"
    assert "Rule 11" in stderr, f"Expected 'Rule 11' in stderr. Got: {stderr}"


def test_bare_except_in_docstring_not_blocked(git_repo):
    """A staged .py file where `except: pass` appears only inside a docstring must exit 0."""
    ok = git_repo / "ok.py"
    ok.write_text('def foo():\n    """Do not use except: pass"""\n    return 1\n')
    subprocess.run(["git", "add", "ok.py"], cwd=git_repo, check=True, capture_output=True)

    returncode, stderr = run_checks(git_repo)

    assert returncode == 0, f"Expected exit 0, got {returncode}. stderr: {stderr}"


def test_bare_except_unstaged_not_detected(git_repo):
    """Writing `except: pass` to working tree without staging it must not trigger a violation.

    Proves the script reads git show :path, not open().
    """
    clean = git_repo / "clean.py"
    clean.write_text("x = 1\n")
    subprocess.run(["git", "add", "clean.py"], cwd=git_repo, check=True, capture_output=True)

    # Write a dirty file but do NOT stage it
    dirty = git_repo / "dirty.py"
    dirty.write_text("try:\n    x = 1\nexcept:\n    pass\n")
    # dirty.py is intentionally NOT added to the index

    returncode, stderr = run_checks(git_repo)

    assert returncode == 0, f"Expected exit 0, got {returncode}. stderr: {stderr}"


def test_staged_index_not_working_tree(git_repo):
    """Stage a clean file, then dirty the working tree without re-staging. Must exit 0.

    This verifies the script reads the staged index content, not the file on disk.
    """
    module = git_repo / "module.py"
    module.write_text("x = 1\n")
    subprocess.run(["git", "add", "module.py"], cwd=git_repo, check=True, capture_output=True)

    # Overwrite on disk but do NOT re-stage
    module.write_text("try:\n    x = 1\nexcept:\n    pass\n")

    returncode, stderr = run_checks(git_repo)

    assert returncode == 0, f"Expected exit 0 (staged version is clean), got {returncode}. stderr: {stderr}"


def test_violation_message_format(git_repo):
    """Violation output must include rule number, file path, line number, and remediation hint."""
    bad = git_repo / "bad.py"
    bad.write_text("try:\n    x = 1\nexcept:\n    pass\n")
    subprocess.run(["git", "add", "bad.py"], cwd=git_repo, check=True, capture_output=True)

    returncode, stderr = run_checks(git_repo)

    assert returncode == 1
    assert "Rule 11" in stderr, f"Missing 'Rule 11' in: {stderr}"
    assert "bad.py" in stderr, f"Missing file path 'bad.py' in: {stderr}"
    # Line number: the except is on line 3
    assert "3" in stderr, f"Missing line number in: {stderr}"
    # Remediation hint must mention logging
    assert "log" in stderr, f"Missing remediation hint ('log') in: {stderr}"


# ---------------------------------------------------------------------------
# STATIC-01 — CDN URL checks
# ---------------------------------------------------------------------------


def test_cdn_url_blocked(git_repo):
    """A staged .vue file with a CDN URL must exit 1 mentioning Rule 2.1.1."""
    components_dir = git_repo / "frontend" / "src" / "components"
    components_dir.mkdir(parents=True, exist_ok=True)
    chart_vue = components_dir / "Chart.vue"
    chart_vue.write_text(
        "<template><div></div></template>\n"
        '<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>\n'
    )
    subprocess.run(
        ["git", "add", "frontend/src/components/Chart.vue"],
        cwd=git_repo,
        check=True,
        capture_output=True,
    )

    returncode, stderr = run_checks(git_repo)

    assert returncode == 1, f"Expected exit 1, got {returncode}. stderr: {stderr}"
    assert "Rule 2.1.1" in stderr, f"Expected 'Rule 2.1.1' in stderr. Got: {stderr}"


def test_cdn_compliance_ignore_skipped(git_repo):
    """A CDN URL on a line with compliance-ignore comment must not block (exit 0)."""
    components_dir = git_repo / "frontend" / "src" / "components"
    components_dir.mkdir(parents=True, exist_ok=True)
    safe_vue = components_dir / "Safe.vue"
    safe_vue.write_text(
        "<template><div></div></template>\n"
        '<!-- compliance-ignore --><script src="https://cdn.jsdelivr.net/npm/chart.js"></script>\n'
    )
    subprocess.run(
        ["git", "add", "frontend/src/components/Safe.vue"],
        cwd=git_repo,
        check=True,
        capture_output=True,
    )

    returncode, stderr = run_checks(git_repo)

    assert returncode == 0, f"Expected exit 0, got {returncode}. stderr: {stderr}"


def test_cdn_unstaged_not_detected(git_repo):
    """A CDN URL only in the unstaged working tree must not trigger a violation (exit 0)."""
    components_dir = git_repo / "frontend" / "src" / "components"
    components_dir.mkdir(parents=True, exist_ok=True)

    # Stage a clean file
    clean_vue = components_dir / "Clean.vue"
    clean_vue.write_text("<template><div>Hello</div></template>\n")
    subprocess.run(
        ["git", "add", "frontend/src/components/Clean.vue"],
        cwd=git_repo,
        check=True,
        capture_output=True,
    )

    # Write a CDN file but do NOT stage it
    dirty_vue = components_dir / "Dirty.vue"
    dirty_vue.write_text(
        "<template><div></div></template>\n"
        '<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>\n'
    )
    # Dirty.vue intentionally NOT staged

    returncode, stderr = run_checks(git_repo)

    assert returncode == 0, f"Expected exit 0, got {returncode}. stderr: {stderr}"


# ---------------------------------------------------------------------------
# STATIC-03 — i18n completeness checks
# ---------------------------------------------------------------------------


def test_i18n_missing_locale_blocked(git_repo):
    """Staging en.json with a new key while a locale file is not staged must exit 1."""
    locales_dir = git_repo / "frontend" / "src" / "i18n" / "locales"
    locales_dir.mkdir(parents=True, exist_ok=True)

    # Commit initial en.json so HEAD has it
    en_json = locales_dir / "en.json"
    en_json.write_text('{"hello": "Hi"}\n')
    subprocess.run(
        ["git", "add", "frontend/src/i18n/locales/en.json"],
        cwd=git_repo,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "commit", "-m", "add en.json", "--no-gpg-sign"],
        cwd=git_repo,
        check=True,
        capture_output=True,
    )

    # Stage en.json with a new key "bye"
    en_json.write_text('{"hello": "Hi", "bye": "Bye"}\n')
    subprocess.run(
        ["git", "add", "frontend/src/i18n/locales/en.json"],
        cwd=git_repo,
        check=True,
        capture_output=True,
    )
    # Do NOT stage any other locale file

    returncode, stderr = run_checks(git_repo)

    assert returncode == 1, f"Expected exit 1, got {returncode}. stderr: {stderr}"
    assert "de.json" in stderr, f"Expected 'de.json' in stderr. Got: {stderr}"
    assert "Rule 3" in stderr, f"Expected 'Rule 3' in stderr. Got: {stderr}"


def test_i18n_reformat_not_blocked(git_repo):
    """Staging en.json with no new keys (reformat/reorder only) must exit 0."""
    locales_dir = git_repo / "frontend" / "src" / "i18n" / "locales"
    locales_dir.mkdir(parents=True, exist_ok=True)

    # Commit initial en.json
    en_json = locales_dir / "en.json"
    en_json.write_text('{"a": "1", "b": "2"}\n')
    subprocess.run(
        ["git", "add", "frontend/src/i18n/locales/en.json"],
        cwd=git_repo,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "commit", "-m", "add en.json", "--no-gpg-sign"],
        cwd=git_repo,
        check=True,
        capture_output=True,
    )

    # Rewrite en.json with same keys, different order (reformat only)
    en_json.write_text('{"b": "2", "a": "1"}\n')
    subprocess.run(
        ["git", "add", "frontend/src/i18n/locales/en.json"],
        cwd=git_repo,
        check=True,
        capture_output=True,
    )

    returncode, stderr = run_checks(git_repo)

    assert returncode == 0, f"Expected exit 0, got {returncode}. stderr: {stderr}"


def test_i18n_all_locales_staged_passes(git_repo):
    """Staging all 5 locale files with a new key must exit 0."""
    locales_dir = git_repo / "frontend" / "src" / "i18n" / "locales"
    locales_dir.mkdir(parents=True, exist_ok=True)

    # Commit initial en.json
    en_json = locales_dir / "en.json"
    en_json.write_text('{"hello": "Hi"}\n')
    subprocess.run(
        ["git", "add", "frontend/src/i18n/locales/en.json"],
        cwd=git_repo,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "commit", "-m", "add en.json", "--no-gpg-sign"],
        cwd=git_repo,
        check=True,
        capture_output=True,
    )

    # Stage en.json with new key "bye"
    en_json.write_text('{"hello": "Hi", "bye": "Bye"}\n')
    subprocess.run(
        ["git", "add", "frontend/src/i18n/locales/en.json"],
        cwd=git_repo,
        check=True,
        capture_output=True,
    )

    # Stage all other locale files with the "bye" key
    locale_contents = {
        "de.json": '{"hello": "Hallo", "bye": "Tschuess"}\n',
        "es-419.json": '{"hello": "Hola", "bye": "Adios"}\n',
        "he.json": '{"hello": "Shalom", "bye": "Lehitraot"}\n',
        "zh-CN.json": '{"hello": "Nihao", "bye": "Zaijian"}\n',
    }
    for filename, content in locale_contents.items():
        locale_file = locales_dir / filename
        locale_file.write_text(content)
        subprocess.run(
            ["git", "add", f"frontend/src/i18n/locales/{filename}"],
            cwd=git_repo,
            check=True,
            capture_output=True,
        )

    returncode, stderr = run_checks(git_repo)

    assert returncode == 0, f"Expected exit 0, got {returncode}. stderr: {stderr}"


# ---------------------------------------------------------------------------
# STATIC-04 — Python test coverage pairing
# ---------------------------------------------------------------------------


def test_new_module_without_test_blocked(git_repo):
    """Staging a new app/ .py file without a test counterpart must exit 1 citing Rule 6."""
    services_dir = git_repo / "app" / "services"
    services_dir.mkdir(parents=True, exist_ok=True)

    newmod = services_dir / "newmod.py"
    newmod.write_text("x = 1\n")
    subprocess.run(
        ["git", "add", "app/services/newmod.py"],
        cwd=git_repo,
        check=True,
        capture_output=True,
    )

    returncode, stderr = run_checks(git_repo)

    assert returncode == 1, f"Expected exit 1, got {returncode}. stderr: {stderr}"
    assert "Rule 6" in stderr, f"Expected 'Rule 6' in stderr. Got: {stderr}"
    assert "test_newmod.py" in stderr, f"Expected 'test_newmod.py' in stderr. Got: {stderr}"


def test_new_module_with_prior_test_passes(git_repo):
    """Staging a new app/ module is not blocked when its test already exists on disk from a prior commit."""
    services_dir = git_repo / "app" / "services"
    services_dir.mkdir(parents=True, exist_ok=True)
    tests_dir = git_repo / "tests"
    tests_dir.mkdir(parents=True, exist_ok=True)

    # Commit test file first (prior commit)
    test_file = tests_dir / "test_anothermod.py"
    test_file.write_text("def test_it(): pass\n")
    subprocess.run(
        ["git", "add", "tests/test_anothermod.py"],
        cwd=git_repo,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "commit", "-m", "add test_anothermod", "--no-gpg-sign"],
        cwd=git_repo,
        check=True,
        capture_output=True,
    )

    # Now stage the new module — test exists on disk from prior commit
    anothermod = services_dir / "anothermod.py"
    anothermod.write_text("x = 1\n")
    subprocess.run(
        ["git", "add", "app/services/anothermod.py"],
        cwd=git_repo,
        check=True,
        capture_output=True,
    )

    returncode, stderr = run_checks(git_repo)

    assert returncode == 0, f"Expected exit 0, got {returncode}. stderr: {stderr}"


def test_modified_module_with_existing_test_warns(git_repo):
    """Modified app/ .py file with a test on disk but not staged must warn only (exit 0)."""
    services_dir = git_repo / "app" / "services"
    services_dir.mkdir(parents=True, exist_ok=True)
    tests_dir = git_repo / "tests"
    tests_dir.mkdir(parents=True, exist_ok=True)

    # Commit the production module
    existing_py = services_dir / "existing.py"
    existing_py.write_text("x = 1\n")
    subprocess.run(
        ["git", "add", "app/services/existing.py"],
        cwd=git_repo,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "commit", "-m", "add existing.py", "--no-gpg-sign"],
        cwd=git_repo,
        check=True,
        capture_output=True,
    )

    # Write test file on disk (not committed, just needs to exist)
    test_existing = tests_dir / "test_existing.py"
    test_existing.write_text("def test_it(): pass\n")

    # Modify the production module and stage it
    existing_py.write_text("x = 2\n")
    subprocess.run(
        ["git", "add", "app/services/existing.py"],
        cwd=git_repo,
        check=True,
        capture_output=True,
    )

    returncode, stderr = run_checks(git_repo)

    # Warning only, commit is not blocked
    assert returncode == 0, f"Expected exit 0, got {returncode}. stderr: {stderr}"


def test_init_py_excluded(git_repo):
    """Staging __init__.py must not trigger the test-pairing check (exit 0)."""
    api_dir = git_repo / "app" / "api"
    api_dir.mkdir(parents=True, exist_ok=True)

    init_py = api_dir / "__init__.py"
    init_py.write_text("# init\n")
    subprocess.run(
        ["git", "add", "app/api/__init__.py"],
        cwd=git_repo,
        check=True,
        capture_output=True,
    )

    returncode, stderr = run_checks(git_repo)

    assert returncode == 0, f"Expected exit 0, got {returncode}. stderr: {stderr}"
