from unittest.mock import MagicMock, patch, call

import pytest
from sqlalchemy.exc import ProgrammingError

from app.db import get_adapter
from app.db import models
from app.db.sql_adapter import SQLAdapter


# User table columns that existed in original schema. All other User fields must be in SQLAdapter.USER_MIGRATION_COLUMN_DEFS so existing SQLite DBs get the column. When adding a new User field, add it to USER_MIGRATION_COLUMN_DEFS or this test fails.
_CORE_USER_COLUMNS = {"id", "email", "name", "role", "provider", "created_at", "last_login", "is_active"}


def test_user_migration_columns_sync():
    """Ensure every User model field that needs SQLite backfill is in USER_MIGRATION_COLUMN_DEFS.
    Prevents adding a new User column without adding the migration (e.g. llm_extra_instructions).
    """
    user_fields = set(models.User.model_fields)
    migration_cols = set(SQLAdapter.USER_MIGRATION_COLUMN_DEFS.keys())
    expected_migrated = user_fields - _CORE_USER_COLUMNS
    assert migration_cols == expected_migrated, (
        "User model and SQLAdapter.USER_MIGRATION_COLUMN_DEFS out of sync. "
        "When you add a new field to User, add it to SQLAdapter.USER_MIGRATION_COLUMN_DEFS in app/db/sql_adapter.py. "
        f"Missing in migration: {expected_migrated - migration_cols}. "
        f"Extra in migration: {migration_cols - expected_migrated}."
    )


def test_user_updates_and_lookup():
    adapter = get_adapter()
    user = adapter.upsert_user(email="u@example.com", name="User", provider="local")
    updated = adapter.set_user_name(user.id, "Renamed")
    assert updated is not None
    assert updated.name == "Renamed"
    fetched = adapter.get_user_by_id(user.id)
    assert fetched is not None
    assert fetched.name == "Renamed"


def test_user_profile_default_finding_template_roundtrip():
    """Round-trip default_finding_template via update_user_profile and get_user_by_id.
    Ensures the column exists and is read/written (catches missing migration column).
    """
    adapter = get_adapter()
    user = adapter.upsert_user(email="dft@example.com", name="DFT User", provider="local")
    updated = adapter.update_user_profile(user.id, default_finding_template="web-app")
    assert updated is not None
    assert getattr(updated, "default_finding_template", None) == "web-app"
    fetched = adapter.get_user_by_id(user.id)
    assert fetched is not None
    assert getattr(fetched, "default_finding_template", "") == "web-app"
    # Clearing to empty string also works
    adapter.update_user_profile(user.id, default_finding_template="")
    fetched2 = adapter.get_user_by_id(user.id)
    assert getattr(fetched2, "default_finding_template", None) == ""


def test_user_profile_llm_extra_instructions_roundtrip():
    """Round-trip llm_extra_instructions via update_user_profile and get_user_by_id.
    Ensures the column exists and is read/written (catches missing migration column).
    """
    adapter = get_adapter()
    user = adapter.upsert_user(email="llm-inst@example.com", name="LLM User", provider="local")
    instructions = "Use British English. Prefer short sentences."
    updated = adapter.update_user_profile(user.id, llm_extra_instructions=instructions)
    assert updated is not None
    assert getattr(updated, "llm_extra_instructions", None) == instructions
    fetched = adapter.get_user_by_id(user.id)
    assert fetched is not None
    assert getattr(fetched, "llm_extra_instructions", "") == instructions


def test_user_2fa_adapter_methods():
    """Round-trip update_user_2fa and disable_user_2fa via adapter."""
    from datetime import datetime

    adapter = get_adapter()
    user = adapter.upsert_user(email="2fa-adapter@example.com", name="2FA User", provider="local")

    # Enable 2FA
    updated = adapter.update_user_2fa(
        user.id,
        twofa_secret="encrypted_secret",
        twofa_enabled=True,
        twofa_backup_codes='["hash1","hash2"]',
        twofa_configured_at=datetime.utcnow(),
    )
    assert updated is not None
    fetched = adapter.get_user_by_id(user.id)
    assert fetched is not None
    assert fetched.twofa_enabled is True
    assert fetched.twofa_secret == "encrypted_secret"
    assert fetched.twofa_backup_codes == '["hash1","hash2"]'
    assert fetched.twofa_configured_at is not None

    # Disable 2FA
    disabled = adapter.disable_user_2fa(user.id)
    assert disabled is not None
    fetched2 = adapter.get_user_by_id(user.id)
    assert fetched2 is not None
    assert fetched2.twofa_enabled is False
    assert fetched2.twofa_secret == ""
    assert fetched2.twofa_backup_codes == ""
    assert fetched2.twofa_configured_at is None


def test_list_clients_filters_by_query():
    adapter = get_adapter()
    adapter.create_client("Acme Corporation")
    adapter.create_client("Beta LLC")
    results = list(adapter.list_clients(query="acme"))
    assert len(results) == 1
    assert results[0].name == "Acme Corporation"


def test_list_applications_filters_by_query():
    adapter = get_adapter()
    adapter.create_application("Public Web", type="web")
    adapter.create_application("Mobile App", type="ios")
    results = list(adapter.list_applications(query="mobile"))
    assert len(results) == 1
    assert results[0].name == "Mobile App"


def test_update_report_summaries_and_delete_missing():
    adapter = get_adapter()
    client = adapter.create_client("Summary Team")
    app_row = adapter.create_application("Summary App")
    report = adapter.create_report("Report", client_id=client.id, application_id=app_row.id)
    updated = adapter.update_report_summaries(
        report.id,
        summary_executive="exec",
        summary_technical="tech",
        summary_recommendations="rec",
    )
    assert updated is not None
    assert updated.summary_executive == "exec"
    assert updated.summary_technical == "tech"
    assert updated.summary_recommendations == "rec"
    assert adapter.delete_report("00000000-0000-0000-0000-000000000123") is False


def test_tag_crud_and_assignment():
    adapter = get_adapter()
    org_id = adapter.ensure_system_org()

    # Create tags
    tag1 = adapter.create_tag(org_id, "OWASP Top 10")
    assert tag1.name == "OWASP Top 10"
    assert tag1.organization_id == org_id

    tag2 = adapter.create_tag(org_id, "PCI DSS")
    assert tag2.name == "PCI DSS"

    # Create duplicate returns existing
    tag1_dup = adapter.create_tag(org_id, "OWASP Top 10")
    assert tag1_dup.id == tag1.id

    # List tags
    all_tags = list(adapter.list_tags(org_id))
    assert len(all_tags) >= 2

    # Auto-suggest query
    filtered = list(adapter.list_tags(org_id, query="owasp"))
    assert any(t.name == "OWASP Top 10" for t in filtered)

    # Get by name
    found = adapter.get_tag_by_name(org_id, "PCI DSS")
    assert found is not None
    assert found.id == tag2.id

    # Assign tag to entity
    client = adapter.create_client("Tag Team")
    et = adapter.add_entity_tag(tag1.id, "client", client.id)
    assert et.tag_id == tag1.id
    assert et.entity_type == "client"
    assert et.entity_id == client.id

    # Idempotent assign
    et2 = adapter.add_entity_tag(tag1.id, "client", client.id)
    assert et2.id == et.id

    # List entity tags
    entity_tags = list(adapter.list_entity_tags("client", client.id))
    assert len(entity_tags) == 1
    assert entity_tags[0].name == "OWASP Top 10"

    # List entities by tag
    entities = list(adapter.list_entities_by_tag(tag1.id, entity_type="client"))
    assert len(entities) >= 1
    assert any(e.entity_id == client.id for e in entities)

    # Remove entity tag
    assert adapter.remove_entity_tag(tag1.id, "client", client.id) is True
    assert adapter.remove_entity_tag(tag1.id, "client", client.id) is False  # already removed
    assert len(list(adapter.list_entity_tags("client", client.id))) == 0

    # Delete tag cascades
    adapter.add_entity_tag(tag2.id, "client", client.id)
    assert adapter.delete_tag(tag2.id) is True
    assert adapter.get_tag(tag2.id) is None
    assert len(list(adapter.list_entity_tags("client", client.id))) == 0


def test_tag_name_validation_in_adapter():
    adapter = get_adapter()
    org_id = adapter.ensure_system_org()

    # Valid tag names
    tag_valid = adapter.create_tag(org_id, "v1.0 Release")
    assert tag_valid.name == "v1.0 Release"

    tag_valid2 = adapter.create_tag(org_id, "Simple")
    assert tag_valid2.name == "Simple"


def test_ensure_report_client_id_column_is_idempotent():
    """_ensure_report_client_id_column must not fail on a fresh DB (client_id already exists)."""
    adapter = get_adapter()
    # On a fresh test DB, report table already has client_id — method should be a no-op.
    adapter._ensure_report_client_id_column()
    # Verify reports still work after the (no-op) migration.
    org_client = adapter.create_client("Migration Test Client")
    report = adapter.create_report("Migration Test Report", client_id=org_client.id)
    assert report.client_id == org_client.id


# ── _safe_create_all PostgreSQL AUTOCOMMIT path ───────────────────────────────

def _pg_programming_error(msg: str) -> ProgrammingError:
    """Build a ProgrammingError whose .orig carries *msg*, matching the real psycopg2 shape."""
    orig = Exception(msg)
    return ProgrammingError(msg, None, orig)


def test_safe_create_all_pg_uses_autocommit():
    """On a non-SQLite URL, _safe_create_all must obtain an AUTOCOMMIT engine variant."""
    adapter = SQLAdapter.__new__(SQLAdapter)
    adapter.db_url = "postgresql://user:pw@localhost/testdb"

    ac_engine = MagicMock()
    mock_engine = MagicMock()
    mock_engine.execution_options.return_value = ac_engine

    # table.create() succeeds silently for every table
    with patch.object(SQLAdapter, "_safe_create_all", wraps=None):
        pass  # just confirming the method exists

    adapter.engine = mock_engine

    # Patch sorted_tables to a single fake table so the loop is exercised
    fake_table = MagicMock()
    fake_table.create.return_value = None

    with patch("app.db.sql_adapter.SQLModel") as mock_sqlmodel:
        mock_sqlmodel.metadata.sorted_tables = [fake_table]
        adapter._safe_create_all()

    mock_engine.execution_options.assert_called_once_with(isolation_level="AUTOCOMMIT")
    fake_table.create.assert_called_once_with(ac_engine, checkfirst=True)


def test_safe_create_all_pg_ignores_already_exists():
    """On PostgreSQL, an 'already exists' ProgrammingError is swallowed (orphaned index)."""
    adapter = SQLAdapter.__new__(SQLAdapter)
    adapter.db_url = "postgresql://user:pw@localhost/testdb"

    ac_engine = MagicMock()
    mock_engine = MagicMock()
    mock_engine.execution_options.return_value = ac_engine
    adapter.engine = mock_engine

    fake_table = MagicMock()
    fake_table.create.side_effect = _pg_programming_error(
        'relation "ix_team_organization_id" already exists'
    )

    with patch("app.db.sql_adapter.SQLModel") as mock_sqlmodel:
        mock_sqlmodel.metadata.sorted_tables = [fake_table]
        # Must NOT raise
        adapter._safe_create_all()


def test_safe_create_all_pg_reraises_other_errors():
    """On PostgreSQL, a ProgrammingError unrelated to 'already exists' is re-raised."""
    adapter = SQLAdapter.__new__(SQLAdapter)
    adapter.db_url = "postgresql://user:pw@localhost/testdb"

    ac_engine = MagicMock()
    mock_engine = MagicMock()
    mock_engine.execution_options.return_value = ac_engine
    adapter.engine = mock_engine

    fake_table = MagicMock()
    fake_table.create.side_effect = _pg_programming_error(
        'relation "organization" does not exist'
    )

    with patch("app.db.sql_adapter.SQLModel") as mock_sqlmodel:
        mock_sqlmodel.metadata.sorted_tables = [fake_table]
        with pytest.raises(ProgrammingError):
            adapter._safe_create_all()


def test_ensure_report_fk_references_team_is_noop_on_sqlite():
    """_ensure_report_fk_references_team must be a no-op on SQLite (SQLite has no named FKs)."""
    adapter = get_adapter()
    # Should not raise; the live SQLite test DB is already correct.
    adapter._ensure_report_fk_references_team()
    # Verify reports still work after the no-op.
    client = adapter.create_client("FK Migration Client")
    report = adapter.create_report("FK Migration Report", client_id=client.id)
    assert report.client_id == client.id


def test_ensure_report_fk_references_team_pg_fixes_bad_fk(monkeypatch):
    """On PostgreSQL, if client_id FK references 'client' it should be repointed to 'team'."""
    adapter = SQLAdapter.__new__(SQLAdapter)
    adapter.db_url = "postgresql://user:pw@localhost/testdb"

    mock_conn = MagicMock()
    mock_conn.__enter__ = lambda s: mock_conn
    mock_conn.__exit__ = MagicMock(return_value=False)

    # First query returns 'client' (wrong referenced table)
    mock_conn.exec_driver_sql.side_effect = [
        MagicMock(fetchone=lambda: ("client",)),          # table_name check
        MagicMock(scalar=lambda: "report_team_id_fkey"),  # constraint name
        MagicMock(),                                       # DROP CONSTRAINT
        MagicMock(),                                       # UPDATE orphaned rows
        MagicMock(),                                       # ADD CONSTRAINT
        MagicMock(),                                       # commit
    ]

    mock_engine = MagicMock()
    mock_engine.connect.return_value = mock_conn
    adapter.engine = mock_engine

    adapter._ensure_report_fk_references_team()

    calls = [str(c) for c in mock_conn.exec_driver_sql.call_args_list]
    assert any("DROP CONSTRAINT" in c for c in calls)
    assert any("UPDATE report SET client_id = NULL" in c for c in calls)
    assert any("REFERENCES team" in c for c in calls)


def test_ensure_report_fk_references_team_pg_noop_when_correct(monkeypatch):
    """On PostgreSQL, if client_id FK already references 'team' nothing is changed."""
    adapter = SQLAdapter.__new__(SQLAdapter)
    adapter.db_url = "postgresql://user:pw@localhost/testdb"

    mock_conn = MagicMock()
    mock_conn.__enter__ = lambda s: mock_conn
    mock_conn.__exit__ = MagicMock(return_value=False)

    # First query returns 'team' (already correct)
    mock_conn.exec_driver_sql.return_value = MagicMock(fetchone=lambda: ("team",))

    mock_engine = MagicMock()
    mock_engine.connect.return_value = mock_conn
    adapter.engine = mock_engine

    adapter._ensure_report_fk_references_team()

    # Only one exec_driver_sql call (the initial check); no DROP/ADD
    assert mock_conn.exec_driver_sql.call_count == 1


def test_safe_create_all_sqlite_does_not_use_autocommit():
    """On SQLite, _safe_create_all must NOT call execution_options (SQLite has no AUTOCOMMIT)."""
    adapter = SQLAdapter.__new__(SQLAdapter)
    adapter.db_url = "sqlite:///test.db"

    mock_engine = MagicMock()
    adapter.engine = mock_engine

    fake_table = MagicMock()
    fake_table.create.return_value = None

    with patch("app.db.sql_adapter.SQLModel") as mock_sqlmodel:
        mock_sqlmodel.metadata.sorted_tables = [fake_table]
        adapter._safe_create_all()

    mock_engine.execution_options.assert_not_called()
    fake_table.create.assert_called_once_with(mock_engine, checkfirst=True)
