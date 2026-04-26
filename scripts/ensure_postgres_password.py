#!/usr/bin/env python3
"""
Ensure data/.postgres_password exists with random POSTGRES_PASSWORD and DATABASE_URL.
Same pattern as data/.admin_password (generated on first run, chmod 600).
Used by Docker Compose init service before starting Postgres.
"""
from __future__ import annotations

import logging
import os
import secrets
from pathlib import Path

log = logging.getLogger(__name__)


def main() -> None:
    # When run in init container: /app/data is mounted from host ./data
    data_dir = Path(os.environ.get("DATA_DIR", "/app/data"))
    pw_file = data_dir / ".postgres_password"
    if pw_file.exists():
        return
    data_dir.mkdir(parents=True, exist_ok=True)
    password = secrets.token_urlsafe(24)
    user = "lazeport"
    db = "lazeport"
    # URL-safe password; no extra escaping needed for token_urlsafe output
    database_url = f"postgresql://{user}:{password}@db:5432/{db}"
    content = f"""POSTGRES_PASSWORD={password}
POSTGRES_USER={user}
POSTGRES_DB={db}
DATABASE_URL={database_url}
"""
    pw_file.write_text(content)
    try:
        pw_file.chmod(0o600)
    except PermissionError:
        log.warning("chmod 600 failed for %s (filesystem may not support POSIX permissions)", pw_file)


if __name__ == "__main__":
    main()
