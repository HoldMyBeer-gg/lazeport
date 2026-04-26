#!/usr/bin/env python3
"""Static checks engine for CLAUDE.md compliance enforcement.

Reads the git staged index (via `git show :path`) to analyse only the content
that is about to be committed. Never opens files from the working tree.

Checks implemented:
  - STATIC-01 / Rule 2.1.1: External CDN URLs in frontend/template files
  - STATIC-02 / Rule 11: Bare / silent exception handlers (`except: pass`,
    `except ExcType: pass`)
  - STATIC-03 / Rule 3: i18n locale completeness when en.json gains new keys
  - STATIC-04 / Rule 6: Python test-file pairing for new modules in app/
"""
import argparse
import ast
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CDN_EXTENSIONS = {".html", ".vue", ".ts", ".js", ".css"}

# Regex matching external CDN references in script/link tags and import/require statements.
# Covers the most common CDNs that CLAUDE.md Rule 2.1.1 forbids.
CDN_PATTERNS = re.compile(
    r"""(?x)
    (
        <(?:script|link)[^>]+(?:src|href)=["'][^"']*
        (?:jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|
           cdn\.skypack\.dev|esm\.sh|jspm\.dev|
           googleapis\.com/ajax|bootstrapcdn\.com)
        [^"']*["']
    |
        (?:import|require)\s*\(?["'][^"']*
        (?:jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|
           cdn\.skypack\.dev|esm\.sh|jspm\.dev|
           googleapis\.com/ajax|bootstrapcdn\.com)
        [^"']*["']
    |
        (?:fetch|import)\s*\(\s*["']https?://
        (?:cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com)
        [^"']*["']
    )
    """,
    re.IGNORECASE,
)

# Lines containing this marker are exempt from CDN detection (explicit opt-out).
COMPLIANCE_IGNORE = re.compile(r"compliance-ignore")

LOCALE_DIR = "frontend/src/i18n/locales"
EN_JSON = f"{LOCALE_DIR}/en.json"
LOCALE_FILES = {
    "de.json": f"{LOCALE_DIR}/de.json",
    "es-419.json": f"{LOCALE_DIR}/es-419.json",
    "he.json": f"{LOCALE_DIR}/he.json",
    "zh-CN.json": f"{LOCALE_DIR}/zh-CN.json",
}

EXCLUDED_PY_BASENAMES = {"__init__.py", "conftest.py"}
EXCLUDED_PY_DIR_PREFIXES = ("tests/", "migrations/", "alembic/", ".claude-hooks/")
# Only Python files under these directory prefixes are considered production modules
# that require a corresponding test file (Rule 6).
PRODUCTION_PY_DIR_PREFIXES = ("app/",)


# ---------------------------------------------------------------------------
# Violation dataclass
# ---------------------------------------------------------------------------


@dataclass
class Violation:
    """Represents a single CLAUDE.md rule violation detected in a staged file."""

    rule: str
    file: str
    line: int | None
    found: str
    fix: str
    is_warning: bool = field(default=False)


# ---------------------------------------------------------------------------
# Git helper functions
# ---------------------------------------------------------------------------


def _get_repo_root() -> str:
    """Return the absolute path to the repository root."""
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def get_staged_files() -> list[str]:
    """Return a list of staged file paths (added, copied, modified, or renamed)."""
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        capture_output=True,
        text=True,
    )
    return [line for line in result.stdout.splitlines() if line]


def get_staged_file_statuses() -> dict[str, str]:
    """Return a mapping of staged file path to its status character (A/C/M/R/D)."""
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-status", "--diff-filter=ACMRD"],
        capture_output=True,
        text=True,
    )
    statuses: dict[str, str] = {}
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            status_char = parts[0].strip()
            path = parts[-1].strip()
            statuses[path] = status_char
    return statuses


def read_staged_file(path: str) -> str | None:
    """Read the staged (index) version of a file via `git show :<path>`.

    Returns the file content as a string, or None if the path is not in the
    staged index (e.g., the file was deleted or git show failed).
    Never reads from the working tree.
    """
    result = subprocess.run(
        ["git", "show", f":{path}"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        return None
    return result.stdout


# ---------------------------------------------------------------------------
# STATIC-02 / Rule 11: Bare / silent exception handlers
# ---------------------------------------------------------------------------


def check_bare_except(staged_files: list[str]) -> list[Violation]:
    """Detect bare `except: pass` and `except SomeType: pass` in staged Python files.

    Uses AST walking so that the pattern appearing only in a docstring or a
    comment string literal is NOT flagged — only real exception handlers with a
    single `pass` statement body are violations.
    """
    violations: list[Violation] = []

    py_files = [f for f in staged_files if f.endswith(".py")]

    for path in py_files:
        source = read_staged_file(path)
        if source is None:
            # File removed from index or read failed — skip gracefully.
            continue

        try:
            tree = ast.parse(source, filename=path)
        except SyntaxError:
            # Cannot analyse a file with syntax errors; skip it and let Python
            # surface the syntax error at commit time.
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            # Only flag handlers whose *entire* body is a single `pass`.
            if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                if node.type is None:
                    found_text = "bare `except: pass`"
                else:
                    try:
                        exc_name = ast.unparse(node.type)
                    except Exception:  # noqa: BLE001 — ast.unparse failure is non-critical
                        exc_name = "<unknown>"
                    found_text = f"`except {exc_name}: pass`"

                violations.append(
                    Violation(
                        rule="11",
                        file=path,
                        line=node.lineno,
                        found=found_text,
                        fix=(
                            "Add `log.exception('...')` (or at minimum `log.error(...)`) "
                            "before or instead of `pass`. "
                            "Silent exception handlers hide real errors."
                        ),
                    )
                )

    return violations


# ---------------------------------------------------------------------------
# i18n helper functions
# ---------------------------------------------------------------------------


def _flatten_keys(obj: dict, prefix: str = "") -> set[str]:
    """Recursively flatten a nested JSON object into dot-separated key paths.

    For example, {"a": {"b": "1"}} yields {"a", "a.b"}.

    Args:
        obj: Parsed JSON object (dict) to flatten.
        prefix: Accumulated key prefix from parent recursion.

    Returns:
        Set of dot-separated key strings.
    """
    keys: set[str] = set()
    for k, v in obj.items():
        full_key = f"{prefix}.{k}" if prefix else k
        keys.add(full_key)
        if isinstance(v, dict):
            keys |= _flatten_keys(v, full_key)
    return keys


def _get_json_keys(content: str) -> set[str]:
    """Parse JSON content and return its flattened key set.

    Returns an empty set if the content is not valid JSON.

    Args:
        content: JSON string to parse.

    Returns:
        Set of dot-separated key strings, or empty set on parse error.
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return set()
    if not isinstance(data, dict):
        return set()
    return _flatten_keys(data)


# ---------------------------------------------------------------------------
# Test-pairing helper functions
# ---------------------------------------------------------------------------


def _is_production_py(path: str) -> bool:
    """Return True if path is a production Python module that requires a test counterpart.

    Only considers files under PRODUCTION_PY_DIR_PREFIXES (e.g. app/).
    Excludes __init__.py, conftest.py, and files under tests/, migrations/,
    alembic/, and .claude-hooks/ directories.

    Args:
        path: Repo-relative file path.

    Returns:
        True if the file should be paired with a test, False otherwise.
    """
    p = Path(path)
    if p.suffix != ".py":
        return False
    if p.name in EXCLUDED_PY_BASENAMES:
        return False
    if any(path.startswith(prefix) for prefix in EXCLUDED_PY_DIR_PREFIXES):
        return False
    # Only flag files that live under a known production directory prefix.
    if not any(path.startswith(prefix) for prefix in PRODUCTION_PY_DIR_PREFIXES):
        return False
    return True


def _expected_test_path(path: str) -> str:
    """Return the expected test file path for a given production module path.

    For example, 'app/services/auth.py' -> 'tests/test_auth.py'.

    Args:
        path: Repo-relative path to the production module.

    Returns:
        Repo-relative path to the expected test file.
    """
    return f"tests/test_{Path(path).stem}.py"


# ---------------------------------------------------------------------------
# STATIC-01 / Rule 2.1.1: External CDN URL detection
# ---------------------------------------------------------------------------


def check_cdn_urls(staged_files: list[str]) -> list[Violation]:
    """Detect external CDN URL references in staged frontend and template files.

    Scans .html, .vue, .ts, .js, and .css files in the staged index for
    references to known public CDNs (jsdelivr, unpkg, cdnjs, etc.). Lines
    marked with 'compliance-ignore' are exempt.

    STATIC-01 / Rule 2.1.1: All dependencies must be installed locally via
    npm/package managers and bundled — never loaded from external CDNs.

    Args:
        staged_files: List of repo-relative paths currently in the staged index.

    Returns:
        List of Violation objects, one per offending line.
    """
    violations: list[Violation] = []

    candidate_files = [f for f in staged_files if Path(f).suffix in CDN_EXTENSIONS]

    for path in candidate_files:
        content = read_staged_file(path)
        if content is None:
            # File removed from index or unreadable — skip gracefully.
            continue

        for lineno, line in enumerate(content.splitlines(), start=1):
            # Lines with the compliance-ignore marker are explicitly opted out.
            if COMPLIANCE_IGNORE.search(line):
                continue
            if CDN_PATTERNS.search(line):
                violations.append(
                    Violation(
                        rule="2.1.1",
                        file=path,
                        line=lineno,
                        found=line.strip(),
                        fix=(
                            "Install the library locally via pnpm and import from node_modules. "
                            "Never load from external CDNs."
                        ),
                    )
                )

    return violations


# ---------------------------------------------------------------------------
# STATIC-03 / Rule 3: i18n locale completeness
# ---------------------------------------------------------------------------


def check_i18n_completeness(staged_files: list[str]) -> list[Violation]:
    """Verify that all locale files are updated when en.json gains new translation keys.

    Compares the staged en.json against the HEAD-committed en.json to compute
    newly added keys. If new keys are found, all four non-English locale files
    must be staged; each must also contain all new keys.

    A reformat-only change (same keys, different order or whitespace) produces
    no violations.

    STATIC-03 / Rule 3: Never assume English fallback — all locales must be
    updated with genuine translations when new keys are added.

    Args:
        staged_files: List of repo-relative paths currently in the staged index.

    Returns:
        List of Violation objects for any locale file that is missing or
        that lacks newly added keys.
    """
    if EN_JSON not in staged_files:
        return []

    en_content = read_staged_file(EN_JSON)
    if en_content is None:
        return []

    # Retrieve the previous committed version of en.json for key-set comparison.
    # If HEAD does not yet have en.json (initial commit scenario), fall back to
    # an empty JSON object so all keys in the staged version are treated as new.
    prev_result = subprocess.run(
        ["git", "show", f"HEAD:{EN_JSON}"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    prev_content = prev_result.stdout if prev_result.returncode == 0 else "{}"

    new_keys = _get_json_keys(en_content) - _get_json_keys(prev_content)

    if not new_keys:
        # Reformat-only or no change in keys — nothing to enforce.
        return []

    violations: list[Violation] = []

    for locale_name, locale_path in LOCALE_FILES.items():
        if locale_path not in staged_files:
            violations.append(
                Violation(
                    rule="3",
                    file=locale_path,
                    line=None,
                    found=(
                        f"en.json adds {len(new_keys)} new key(s) "
                        f"but {locale_name} is not staged"
                    ),
                    fix=f"Stage {locale_path} with genuine translations for the new keys.",
                )
            )
        else:
            locale_content = read_staged_file(locale_path)
            if locale_content is None:
                # Staged but unreadable — treat same as missing.
                violations.append(
                    Violation(
                        rule="3",
                        file=locale_path,
                        line=None,
                        found=f"Could not read staged content of {locale_name}",
                        fix=f"Ensure {locale_path} is correctly staged with all new keys.",
                    )
                )
                continue
            missing = new_keys - _get_json_keys(locale_content)
            for key in sorted(missing):
                violations.append(
                    Violation(
                        rule="3",
                        file=locale_path,
                        line=None,
                        found=(
                            f"Key '{key}' present in staged en.json "
                            f"but absent from {locale_name}"
                        ),
                        fix=(
                            f"Add a genuine translation for '{key}' to {locale_name}. "
                            "Do not copy the English string verbatim."
                        ),
                    )
                )

    return violations


# ---------------------------------------------------------------------------
# STATIC-04 / Rule 6: Python test-file pairing
# ---------------------------------------------------------------------------


def check_test_pairing(
    staged_files: list[str], statuses: dict[str, str]
) -> list[Violation]:
    """Ensure new Python modules in app/ are accompanied by a corresponding test file.

    For newly added (status 'A') production Python modules: hard-block the commit
    if no test file is staged AND no test file already exists on disk from a prior
    commit. The on-disk check prevents false positives when the test was committed
    separately before the module itself.

    For modified (status 'M' or other) production Python modules: emit a warning
    (is_warning=True) if no test file is staged and none exists on disk, but do
    not block the commit.

    Excludes __init__.py, conftest.py, and files under tests/, migrations/,
    alembic/, and .claude-hooks/ directories.

    STATIC-04 / Rule 6: All Python code changes must have corresponding unit tests.

    Args:
        staged_files: List of repo-relative paths currently in the staged index.
        statuses: Mapping of repo-relative path to git status character (A/M/C/R/D).

    Returns:
        List of Violation objects (hard violations or warnings).
    """
    violations: list[Violation] = []
    repo_root = _get_repo_root()

    for path in staged_files:
        if not _is_production_py(path):
            continue

        status = statuses.get(path, "M")
        expected_test = _expected_test_path(path)
        test_staged = expected_test in staged_files
        test_on_disk = os.path.exists(os.path.join(repo_root, expected_test))

        if status == "A":
            # Hard-block: new module must have a test staged OR already on disk.
            if not test_staged and not test_on_disk:
                violations.append(
                    Violation(
                        rule="6",
                        file=path,
                        line=None,
                        found=f"New module {path!r} has no corresponding test file staged",
                        fix=(
                            f"Create {expected_test} with at least one test for the new "
                            "module and stage it in the same commit."
                        ),
                    )
                )
        else:
            # Warn only: modified module without test file is suspicious but not blocked.
            if not test_staged and not test_on_disk:
                violations.append(
                    Violation(
                        rule="6",
                        file=path,
                        line=None,
                        found=f"Modified module {path!r} has no test file at {expected_test}",
                        fix=(
                            f"Consider adding tests in {expected_test}. "
                            "(Warning only -- commit is not blocked for existing modules.)"
                        ),
                        is_warning=True,
                    )
                )

    return violations


# ---------------------------------------------------------------------------
# Violation formatter
# ---------------------------------------------------------------------------


def _rule_title(rule: str) -> str:
    """Return a short human-readable title for a CLAUDE.md rule number."""
    titles = {
        "11": "No silent exception handlers",
        "2.1.1": "No external CDNs",
        "3": "i18n completeness",
        "6": "Python test coverage",
    }
    return titles.get(rule, f"Rule {rule}")


def format_violation(v: Violation) -> str:
    """Format a Violation into a human-readable multi-line string for stderr output."""
    title = _rule_title(v.rule)
    warning_suffix = " (WARNING -- not blocking)" if v.is_warning else ""
    location = f"{v.file}:{v.line}" if v.line is not None else v.file
    lines = [
        f"[CLAUDE.md] Rule {v.rule}: {title}{warning_suffix}",
        f"  File:  {location}",
        f"  Found: {v.found}",
        f"  Fix:   {v.fix}",
        f"  Ref:   CLAUDE.md Rule {v.rule}",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    """Run all static checks against the staged git index. Returns an exit code.

    Exit codes:
      0 — no hard violations (commit may proceed)
      1 — one or more hard violations found (commit blocked)
      2 — usage error (--staged flag not supplied)
    """
    parser = argparse.ArgumentParser(
        description="CLAUDE.md static checks engine — analyse the git staged index."
    )
    parser.add_argument(
        "--staged",
        action="store_true",
        help="Analyse files in the git staged index (required).",
    )
    args = parser.parse_args()

    if not args.staged:
        print(
            "Usage: static_checks.py --staged\n"
            "This script is meant to be called from a git pre-commit hook.",
            file=sys.stderr,
        )
        return 2

    staged_files = get_staged_files()
    statuses = get_staged_file_statuses()

    if not staged_files:
        return 0

    violations: list[Violation] = []
    violations += check_bare_except(staged_files)
    violations += check_cdn_urls(staged_files)
    violations += check_i18n_completeness(staged_files)
    violations += check_test_pairing(staged_files, statuses)

    for v in violations:
        print(format_violation(v), file=sys.stderr)
        print("", file=sys.stderr)  # blank line between violations

    hard_violations = [v for v in violations if not v.is_warning]
    warning_violations = [v for v in violations if v.is_warning]

    if hard_violations:
        print(
            f"Commit blocked. Fix {len(hard_violations)} violation(s) above, then re-commit.",
            file=sys.stderr,
        )
        return 1

    if warning_violations:
        print(
            f"{len(warning_violations)} warning(s) above. Commit is not blocked.",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
