"""Unit tests for scripts/ensure_postgres_password.py."""
from __future__ import annotations

import importlib.util
import logging
import os
from pathlib import Path

import pytest

# Load script from repo root (scripts/ not a package)
_SCRIPT_DIR = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location(
    "ensure_postgres_password",
    _SCRIPT_DIR / "scripts" / "ensure_postgres_password.py",
)
assert _SPEC and _SPEC.loader
_module = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_module)
main = _module.main


def test_creates_postgres_password_file_with_required_keys(tmp_path: Path) -> None:
    """When file does not exist, creates it with POSTGRES_PASSWORD, USER, DB, DATABASE_URL."""

    with pytest.MonkeyPatch.context() as m:
        m.setenv("DATA_DIR", str(tmp_path))
        main()
    pw_file = tmp_path / ".postgres_password"
    assert pw_file.exists()
    content = pw_file.read_text()
    assert "POSTGRES_PASSWORD=" in content
    assert "POSTGRES_USER=lazeport" in content
    assert "POSTGRES_DB=lazeport" in content
    assert "DATABASE_URL=postgresql://lazeport:" in content
    assert "@db:5432/lazeport" in content
    # Password is URL-safe (no special chars that break connection strings)
    lines = [l for l in content.strip().split("\n") if l.startswith("POSTGRES_PASSWORD=")]
    assert len(lines) == 1
    password = lines[0].split("=", 1)[1].strip()
    assert len(password) >= 24
    assert " " not in password


def test_idempotent_does_not_overwrite_existing_file(tmp_path: Path) -> None:
    """When file already exists, does not overwrite it."""

    existing = tmp_path / ".postgres_password"
    existing.write_text("POSTGRES_PASSWORD=existing\nPOSTGRES_USER=u\nPOSTGRES_DB=d\nDATABASE_URL=url\n")
    try:
        existing.chmod(0o600)
    except PermissionError:
        logging.getLogger(__name__).debug("chmod 600 skipped in test (non-POSIX filesystem)")
    with pytest.MonkeyPatch.context() as m:
        m.setenv("DATA_DIR", str(tmp_path))
        main()
    assert existing.read_text() == "POSTGRES_PASSWORD=existing\nPOSTGRES_USER=u\nPOSTGRES_DB=d\nDATABASE_URL=url\n"


def test_sets_file_mode_600(tmp_path: Path) -> None:
    """New file is created with mode 0o600 on POSIX filesystems."""

    with pytest.MonkeyPatch.context() as m:
        m.setenv("DATA_DIR", str(tmp_path))
        main()
    pw_file = tmp_path / ".postgres_password"
    # On filesystems that don't support POSIX permissions (e.g. Windows bind
    # mounts), chmod is a no-op and the mode check is meaningless — skip.
    try:
        pw_file.chmod(0o644)
        mode_after = os.stat(pw_file).st_mode & 0o777
        if mode_after != 0o644:
            pytest.skip("filesystem does not support POSIX chmod")
        # Restore and re-run to test the actual script behavior
        pw_file.unlink()
        m.setenv("DATA_DIR", str(tmp_path))
        main()
    except PermissionError:
        pytest.skip("filesystem does not support POSIX chmod")
    mode = os.stat(pw_file).st_mode
    assert (mode & 0o777) == 0o600
