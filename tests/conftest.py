"""Pytest fixtures and config."""
import logging
import os
import pytest

log = logging.getLogger(__name__)

os.environ.setdefault("AUTH_DISABLED", "1")
os.environ.setdefault("SESSION_SECRET_KEY", "test-secret")
os.environ.setdefault("APP_SECRET_KEY", "test-app-secret")
os.environ.setdefault("DB_ADAPTER", "sql")
os.environ.setdefault("DATABASE_URL", "sqlite:///./data/test.db")


def pytest_configure(config):
    """Assign a per-worker SQLite file when running under pytest-xdist.

    Each xdist worker is a separate process. Without this hook every worker
    would share ./data/test.db and collide on drop_all/init calls.
    The worker ID (gw0, gw1, …) is injected by xdist via PYTEST_XDIST_WORKER.
    Single-process runs (no -n flag) keep the original test.db path.
    """
    worker_id = os.environ.get("PYTEST_XDIST_WORKER", "")
    suffix = f"_{worker_id}" if worker_id else ""
    os.environ["DATABASE_URL"] = f"sqlite:///./data/test{suffix}.db"


def pytest_sessionfinish(session, exitstatus):
    """Remove per-worker SQLite files after the session ends."""
    worker_id = os.environ.get("PYTEST_XDIST_WORKER", "")
    if not worker_id:
        return
    db_path = f"./data/test_{worker_id}.db"
    try:
        os.remove(db_path)
    except FileNotFoundError:
        log.debug("Worker DB file already absent at cleanup: %s", db_path)


@pytest.fixture(autouse=True)
def reset_env_for_llm(monkeypatch):
    """Ensure tests don't accidentally use real API keys; individual tests set what they need."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)
    monkeypatch.setenv("AUTH_DISABLED", "1")
    monkeypatch.setenv("SESSION_SECRET_KEY", "test-secret")
    monkeypatch.setenv("APP_SECRET_KEY", "test-app-secret")
    monkeypatch.setenv("DB_ADAPTER", "sql")
    # Preserve the worker-specific DATABASE_URL set by pytest_configure above.
    monkeypatch.setenv("DATABASE_URL", os.environ["DATABASE_URL"])


@pytest.fixture(autouse=True)
def offline_dns(monkeypatch):
    """
    Deterministic resolver for the SSRF guard so tests never touch real DNS.

    'localhost' -> loopback, '*.internal.test' -> private, '*.unresolvable.test'
    -> lookup failure, anything else -> a public address. Tests that need finer
    control override app.validation._resolve_host themselves.
    """
    import socket

    def _resolve(host, port):
        if host == "localhost":
            return ["127.0.0.1"]
        if host.endswith(".internal.test"):
            return ["10.0.0.5"]
        if host.endswith(".unresolvable.test"):
            raise socket.gaierror(8, "nodename nor servname provided, or not known")
        return ["93.184.216.34"]

    monkeypatch.setattr("app.validation._resolve_host", _resolve)


@pytest.fixture(autouse=True)
def init_db():
    """Initialize fresh database for each test."""
    from app.db import get_adapter
    from sqlmodel import SQLModel

    adapter = get_adapter()
    if hasattr(adapter, "engine"):
        SQLModel.metadata.drop_all(adapter.engine)
    adapter.init()
