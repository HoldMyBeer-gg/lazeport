import importlib
import pytest

import app.config
import app.db as db_module


def _reload_db_with_adapter(monkeypatch, adapter: str):
    monkeypatch.setenv("DB_ADAPTER", adapter)
    importlib.reload(app.config)
    importlib.reload(db_module)


def _reset_db_adapter(monkeypatch):
    monkeypatch.setenv("DB_ADAPTER", "sql")
    importlib.reload(app.config)
    importlib.reload(db_module)


def test_get_adapter_unknown_raises(monkeypatch):
    _reload_db_with_adapter(monkeypatch, "unknown")
    with pytest.raises(ValueError, match="Unknown DB_ADAPTER"):
        db_module.get_adapter()
    _reset_db_adapter(monkeypatch)


def test_get_adapter_dynamo_not_implemented(monkeypatch):
    _reload_db_with_adapter(monkeypatch, "dynamo")
    with pytest.raises(NotImplementedError):
        db_module.get_adapter()
    _reset_db_adapter(monkeypatch)


def test_get_adapter_gcp_not_implemented(monkeypatch):
    _reload_db_with_adapter(monkeypatch, "gcp")
    with pytest.raises(NotImplementedError):
        db_module.get_adapter()
    _reset_db_adapter(monkeypatch)
