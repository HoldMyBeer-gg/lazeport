from __future__ import annotations

from app.config import settings
from app.db.adapter import StorageAdapter
from app.db.sql_adapter import SQLAdapter

_ADAPTER: StorageAdapter | None = None


def get_adapter() -> StorageAdapter:
    global _ADAPTER
    if _ADAPTER:
        return _ADAPTER
    adapter = settings.db_adapter
    if adapter in ("sql", "sqlite", "postgres"):
        _ADAPTER = SQLAdapter()
        return _ADAPTER
    if adapter == "dynamo":
        raise NotImplementedError("Dynamo adapter not implemented yet.")
    if adapter == "gcp":
        raise NotImplementedError("GCP adapter not implemented yet.")
    raise ValueError(f"Unknown DB_ADAPTER={adapter}")
