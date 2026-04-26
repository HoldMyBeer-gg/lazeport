from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Dict, Iterable, Optional

from sqlmodel import Session, SQLModel, create_engine, delete, select

from app.config import settings
from app.db import models
from app.db.models import SYSTEM_ORG_ID


class SQLAdapter:
    def __init__(self, db_url: str | None = None) -> None:
        self.db_url = db_url or settings.db_url
        if self.db_url.startswith("sqlite:///"):
            path = self.db_url.replace("sqlite:///", "", 1)
            dir_path = os.path.dirname(path)
            if dir_path:
                os.makedirs(dir_path, exist_ok=True)
        self.engine = create_engine(self.db_url, echo=False)

    def init(self) -> None:
        self._safe_create_all()
        self._ensure_user_columns()
        self._ensure_user_session_version_column()
        self._ensure_default_finding_template_column()
        self._ensure_finding_columns()
        self._ensure_client_columns()
        self._ensure_organization_columns()
        self._ensure_report_client_id_column()
        self._ensure_report_nullable_client_app()
        self._ensure_report_fk_references_team()

    def _safe_create_all(self) -> None:
        """Create all tables, safe to call on a database that may already be partially initialised.

        SQLAlchemy's create_all(checkfirst=True) checks table existence before issuing CREATE TABLE,
        but it still emits separate CREATE INDEX statements that fail with DuplicateTable when an
        index was left behind by a previous interrupted startup.

        On PostgreSQL, DDL runs inside a transaction. If CREATE INDEX fails with "already exists",
        PostgreSQL rolls back the *entire* transaction — including the preceding CREATE TABLE — leaving
        the table non-existent even though the error was swallowed. Fix: use AUTOCOMMIT so each DDL
        statement is its own transaction; a failed CREATE INDEX no longer rolls back CREATE TABLE.

        On SQLite there are no transactions around DDL, so the original per-table catch is fine.
        """
        from sqlalchemy.exc import ProgrammingError

        if not self.db_url.startswith("sqlite:"):
            # PostgreSQL: AUTOCOMMIT ensures CREATE TABLE commits before CREATE INDEX runs.
            ac_engine = self.engine.execution_options(isolation_level="AUTOCOMMIT")
            for table in SQLModel.metadata.sorted_tables:
                try:
                    table.create(ac_engine, checkfirst=True)
                except ProgrammingError as exc:
                    if "already exists" not in str(exc.orig):
                        raise
                    # Index from a previous partial run — table itself was already committed.
            return

        for table in SQLModel.metadata.sorted_tables:
            try:
                table.create(self.engine, checkfirst=True)
            except ProgrammingError as exc:
                if "already exists" not in str(exc.orig):
                    raise
                # An index (or other object) from a previous partial run exists — safe to ignore.

    # SQLite backfill: columns added to User after initial schema. When adding a new User profile field, add it here so existing DBs get the column. Keep in sync with app.db.models.User; test_user_migration_columns_sync enforces this.
    USER_MIGRATION_COLUMN_DEFS = {
        "password_hash": "TEXT DEFAULT ''",  # nosec B105
        "contact_email": "TEXT DEFAULT ''",
        "phone": "TEXT DEFAULT ''",
        "title": "TEXT DEFAULT ''",
        "theme": "TEXT DEFAULT 'dark'",
        "company_name": "TEXT DEFAULT ''",
        "department_name": "TEXT DEFAULT ''",
        "default_master_template": "TEXT DEFAULT 'master'",
        "default_finding_template": "TEXT DEFAULT ''",
        "openai_api_key_encrypted": "TEXT DEFAULT ''",
        "ai_key_provider": "TEXT DEFAULT ''",
        "llm_extra_instructions": "TEXT DEFAULT ''",
        "twofa_secret": "TEXT DEFAULT ''",
        "twofa_enabled": "INTEGER DEFAULT 0",
        "twofa_backup_codes": "TEXT DEFAULT ''",
        "twofa_configured_at": "TEXT DEFAULT NULL",
        "session_version": "INTEGER DEFAULT 0",
    }

    def _ensure_user_columns(self) -> None:
        if not self.db_url.startswith("sqlite:"):
            return
        with self.engine.connect() as conn:
            result = conn.exec_driver_sql("PRAGMA table_info(user)")
            columns = {row[1] for row in result.fetchall()}
            for name, ddl in self.USER_MIGRATION_COLUMN_DEFS.items():
                if name not in columns:
                    conn.exec_driver_sql(f"ALTER TABLE user ADD COLUMN {name} {ddl}")

    def _ensure_user_session_version_column(self) -> None:
        """Add session_version column to user table for session invalidation (MED-6 fix)."""
        with self.engine.connect() as conn:
            if self.db_url.startswith("sqlite:"):
                result = conn.exec_driver_sql("PRAGMA table_info(user)")
                columns = {row[1] for row in result.fetchall()}
                has_column = "session_version" in columns
            else:
                result = conn.exec_driver_sql(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.columns "
                    "WHERE table_name='user' AND column_name='session_version')"
                )
                has_column = result.scalar()
            if not has_column:
                # "user" is a reserved word in PostgreSQL — must be quoted
                conn.exec_driver_sql('ALTER TABLE "user" ADD COLUMN session_version INTEGER DEFAULT 0')
                conn.commit()

    def _ensure_default_finding_template_column(self) -> None:
        """Add default_finding_template to user and settings tables (SQLite + PostgreSQL)."""
        with self.engine.connect() as conn:
            if self.db_url.startswith("sqlite:"):
                user_cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(user)").fetchall()}
                if "default_finding_template" not in user_cols:
                    conn.exec_driver_sql("ALTER TABLE user ADD COLUMN default_finding_template TEXT DEFAULT ''")
                settings_cols = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(settings)").fetchall()}
                if "default_finding_template" not in settings_cols:
                    conn.exec_driver_sql("ALTER TABLE settings ADD COLUMN default_finding_template TEXT DEFAULT ''")
            else:
                has_user_col = conn.exec_driver_sql(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.columns "
                    "WHERE table_name='user' AND column_name='default_finding_template')"
                ).scalar()
                if not has_user_col:
                    conn.exec_driver_sql('ALTER TABLE "user" ADD COLUMN default_finding_template TEXT DEFAULT \'\'')
                has_settings_col = conn.exec_driver_sql(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.columns "
                    "WHERE table_name='settings' AND column_name='default_finding_template')"
                ).scalar()
                if not has_settings_col:
                    conn.exec_driver_sql("ALTER TABLE settings ADD COLUMN default_finding_template TEXT DEFAULT ''")
            conn.commit()

    def _ensure_finding_columns(self) -> None:
        """Add metadata_json column to existing finding tables for scanner metadata."""
        if not self.db_url.startswith("sqlite:"):
            return
        with self.engine.connect() as conn:
            result = conn.exec_driver_sql("PRAGMA table_info(finding)")
            columns = {row[1] for row in result.fetchall()}
            if "metadata_json" not in columns:
                conn.exec_driver_sql("ALTER TABLE finding ADD COLUMN metadata_json TEXT DEFAULT ''")
            if "validation_guidance" not in columns:
                conn.exec_driver_sql("ALTER TABLE finding ADD COLUMN validation_guidance TEXT DEFAULT ''")
            if "jira_issue_key" not in columns:
                conn.exec_driver_sql("ALTER TABLE finding ADD COLUMN jira_issue_key TEXT DEFAULT ''")
            if "jira_issue_url" not in columns:
                conn.exec_driver_sql("ALTER TABLE finding ADD COLUMN jira_issue_url TEXT DEFAULT ''")

    def _ensure_client_columns(self) -> None:
        """Add is_active, settings_json to team table (MED-40: soft-delete clients)."""
        if not self.db_url.startswith("sqlite:"):
            return
        with self.engine.connect() as conn:
            result = conn.exec_driver_sql("PRAGMA table_info(team)")
            columns = {row[1] for row in result.fetchall()}
            if "is_active" not in columns:
                conn.exec_driver_sql("ALTER TABLE team ADD COLUMN is_active INTEGER DEFAULT 1")
            if "settings_json" not in columns:
                conn.exec_driver_sql("ALTER TABLE team ADD COLUMN settings_json TEXT DEFAULT ''")
            conn.commit()

    def _ensure_organization_columns(self) -> None:
        """Add severity_criteria column to organization table and populate defaults."""
        with self.engine.connect() as conn:
            # Check if column exists (different query for SQLite vs PostgreSQL)
            if self.db_url.startswith("sqlite:"):
                result = conn.exec_driver_sql("PRAGMA table_info(organization)")
                columns = {row[1] for row in result.fetchall()}
                has_column = "severity_criteria" in columns
            else:
                # PostgreSQL: query information_schema
                result = conn.exec_driver_sql(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='organization' AND column_name='severity_criteria')"
                )
                has_column = result.scalar()

            if not has_column:
                conn.exec_driver_sql("ALTER TABLE organization ADD COLUMN severity_criteria TEXT DEFAULT NULL")
                conn.commit()

        # Populate severity_criteria for orgs that have null/empty values (handles both new and existing columns)
        from app.services.master_docx import parse_severity_criteria_markdown
        default_criteria = parse_severity_criteria_markdown()
        if default_criteria:
            import json as _json
            default_json = _json.dumps(default_criteria)
            with self.engine.connect() as conn:
                # Different parameter binding for SQLite vs PostgreSQL
                if self.db_url.startswith("sqlite:"):
                    conn.exec_driver_sql(
                        "UPDATE organization SET severity_criteria = ? WHERE severity_criteria IS NULL OR severity_criteria = ''",
                        (default_json,)
                    )
                else:
                    # PostgreSQL uses %s for parameters
                    conn.exec_driver_sql(
                        "UPDATE organization SET severity_criteria = %s WHERE severity_criteria IS NULL OR severity_criteria = ''",
                        (default_json,)
                    )
                conn.commit()

    def _ensure_report_client_id_column(self) -> None:
        """Rename report.team_id → report.client_id if the old column name still exists."""
        with self.engine.connect() as conn:
            if self.db_url.startswith("sqlite:"):
                result = conn.exec_driver_sql("PRAGMA table_info(report)")
                columns = {row[1] for row in result.fetchall()}
                if "team_id" in columns and "client_id" not in columns:
                    conn.exec_driver_sql("ALTER TABLE report RENAME COLUMN team_id TO client_id")
                    conn.commit()
            else:
                has_team_id = conn.exec_driver_sql(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.columns "
                    "WHERE table_name='report' AND column_name='team_id')"
                ).scalar()
                has_client_id = conn.exec_driver_sql(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.columns "
                    "WHERE table_name='report' AND column_name='client_id')"
                ).scalar()
                if has_team_id and not has_client_id:
                    conn.exec_driver_sql("ALTER TABLE report RENAME COLUMN team_id TO client_id")
                    conn.commit()

    def _ensure_report_nullable_client_app(self) -> None:
        """Make report.client_id and report.application_id nullable (report-first flow)."""
        if self.db_url.startswith("sqlite:"):
            with self.engine.connect() as conn:
                result = conn.exec_driver_sql("PRAGMA table_info(report)")
                rows = result.fetchall()
                if not rows:
                    return  # Fresh DB, create_all already used new schema
                columns = {row[1]: row[3] for row in rows}  # name -> notnull
                client_notnull = columns.get("client_id", 0)
                if client_notnull == 0:
                    return  # Already migrated
                conn.exec_driver_sql("PRAGMA foreign_keys=OFF")
                conn.exec_driver_sql("""
                    CREATE TABLE report_new (
                        id TEXT NOT NULL PRIMARY KEY,
                        organization_id TEXT NOT NULL,
                        client_id TEXT,
                        application_id TEXT,
                        name VARCHAR NOT NULL,
                        summary_executive TEXT NOT NULL DEFAULT '',
                        summary_technical TEXT NOT NULL DEFAULT '',
                        summary_recommendations TEXT NOT NULL DEFAULT '',
                        created_at DATETIME,
                        created_by TEXT,
                        FOREIGN KEY(organization_id) REFERENCES organization(id),
                        FOREIGN KEY(client_id) REFERENCES team(id),
                        FOREIGN KEY(application_id) REFERENCES application(id),
                        FOREIGN KEY(created_by) REFERENCES user(id)
                    )
                """)
                conn.exec_driver_sql("""
                    INSERT INTO report_new
                    SELECT id, organization_id, client_id, application_id, name,
                           summary_executive, summary_technical, summary_recommendations,
                           created_at, created_by
                    FROM report
                """)
                conn.exec_driver_sql("DROP TABLE report")
                conn.exec_driver_sql("ALTER TABLE report_new RENAME TO report")
                conn.exec_driver_sql("PRAGMA foreign_keys=ON")
                conn.commit()
        else:
            # PostgreSQL: ALTER COLUMN (only if column is NOT NULL)
            with self.engine.connect() as conn:
                r = conn.exec_driver_sql(
                    "SELECT is_nullable FROM information_schema.columns WHERE table_name='report' AND column_name='client_id'"
                ).fetchone()
                if r and r[0] == "NO":
                    conn.exec_driver_sql("ALTER TABLE report ALTER COLUMN client_id DROP NOT NULL")
                r = conn.exec_driver_sql(
                    "SELECT is_nullable FROM information_schema.columns WHERE table_name='report' AND column_name='application_id'"
                ).fetchone()
                if r and r[0] == "NO":
                    conn.exec_driver_sql("ALTER TABLE report ALTER COLUMN application_id DROP NOT NULL")
                conn.commit()

    def _ensure_report_fk_references_team(self) -> None:
        """Fix report.client_id FK if it wrongly references 'client' instead of 'team'.

        Caused by the f2ad24c rename commit which briefly changed foreign_key="team.id" to
        "client.id" in the SQLAlchemy model.  On PostgreSQL the constraint was written into the
        DB with that wrong reference; this migration detects and corrects it.
        """
        if self.db_url.startswith("sqlite:"):
            return
        with self.engine.connect() as conn:
            row = conn.exec_driver_sql(
                """
                SELECT ccu.table_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                    ON tc.constraint_name = kcu.constraint_name
                    AND tc.table_schema = kcu.table_schema
                JOIN information_schema.constraint_column_usage ccu
                    ON tc.constraint_name = ccu.constraint_name
                    AND tc.table_schema = ccu.table_schema
                WHERE tc.constraint_type = 'FOREIGN KEY'
                  AND tc.table_name = 'report'
                  AND kcu.column_name = 'client_id'
                LIMIT 1
                """
            ).fetchone()
            if row and row[0] == "client":
                # Drop the bad constraint (name may be report_team_id_fkey or report_client_id_fkey)
                bad_name = conn.exec_driver_sql(
                    """
                    SELECT tc.constraint_name
                    FROM information_schema.table_constraints tc
                    JOIN information_schema.key_column_usage kcu
                        ON tc.constraint_name = kcu.constraint_name
                        AND tc.table_schema = kcu.table_schema
                    WHERE tc.constraint_type = 'FOREIGN KEY'
                      AND tc.table_name = 'report'
                      AND kcu.column_name = 'client_id'
                    LIMIT 1
                    """
                ).scalar()
                conn.exec_driver_sql(f'ALTER TABLE report DROP CONSTRAINT "{bad_name}"')
                # NULL out any client_id values that don't exist in team (orphaned from old 'client' table)
                conn.exec_driver_sql(
                    "UPDATE report SET client_id = NULL "
                    "WHERE client_id IS NOT NULL "
                    "AND client_id NOT IN (SELECT id FROM team)"
                )
                conn.exec_driver_sql(
                    "ALTER TABLE report ADD CONSTRAINT report_client_id_fkey "
                    "FOREIGN KEY (client_id) REFERENCES team(id)"
                )
                conn.commit()

    def _session(self) -> Session:
        return Session(self.engine)

    # Users
    def get_user_by_email(self, email: str) -> Optional[models.User]:
        with self._session() as session:
            stmt = select(models.User).where(models.User.email == email)
            return session.exec(stmt).first()

    def get_user_by_id(self, user_id: str) -> Optional[models.User]:
        with self._session() as session:
            return session.get(models.User, user_id)

    def upsert_user(
        self,
        *,
        email: str,
        name: str,
        provider: str,
        role: str = "user",
    ) -> models.User:
        with self._session() as session:
            stmt = select(models.User).where(models.User.email == email)
            user = session.exec(stmt).first()
            if user:
                user.name = name or user.name
                user.provider = provider or user.provider
                user.last_login = datetime.utcnow()
            else:
                user = models.User(
                    email=email,
                    name=name or "",
                    role=role,
                    provider=provider,
                    last_login=datetime.utcnow(),
                )
                session.add(user)
            session.commit()
            session.refresh(user)
            return user

    def list_users(self) -> Iterable[models.User]:
        with self._session() as session:
            return list(session.exec(select(models.User)).all())

    def get_users_by_ids(self, user_ids: list[str]) -> dict[str, models.User]:
        if not user_ids:
            return {}
        with self._session() as session:
            stmt = select(models.User).where(models.User.id.in_(user_ids))
            users = session.exec(stmt).all()
            return {u.id: u for u in users}

    def set_user_role(self, user_id: str, role: str) -> Optional[models.User]:
        with self._session() as session:
            user = session.get(models.User, user_id)
            if not user:
                return None
            user.role = role
            session.commit()
            session.refresh(user)
            return user

    def set_user_active(self, user_id: str, is_active: bool) -> Optional[models.User]:
        with self._session() as session:
            user = session.get(models.User, user_id)
            if not user:
                return None
            user.is_active = is_active
            session.commit()
            session.refresh(user)
            return user

    def set_user_password_hash(self, user_id: str, password_hash: str) -> Optional[models.User]:
        with self._session() as session:
            user = session.get(models.User, user_id)
            if not user:
                return None
            user.password_hash = password_hash
            session.commit()
            session.refresh(user)
            return user

    def increment_user_session_version(self, user_id: str) -> None:
        """Increment session_version to invalidate all existing sessions for the user."""
        with self._session() as session:
            db_user = session.get(models.User, user_id)
            if db_user:
                db_user.session_version = (db_user.session_version or 0) + 1
                session.commit()

    def update_user_2fa(
        self,
        user_id: str,
        *,
        twofa_secret: Optional[str] = None,
        twofa_enabled: Optional[bool] = None,
        twofa_backup_codes: Optional[str] = None,
        twofa_configured_at: Optional[datetime] = None,
    ) -> Optional[models.User]:
        with self._session() as session:
            user = session.get(models.User, user_id)
            if not user:
                return None
            if twofa_secret is not None:
                user.twofa_secret = twofa_secret
            if twofa_enabled is not None:
                user.twofa_enabled = twofa_enabled
            if twofa_backup_codes is not None:
                user.twofa_backup_codes = twofa_backup_codes
            if twofa_configured_at is not None:
                user.twofa_configured_at = twofa_configured_at
            session.commit()
            session.refresh(user)
            return user

    def disable_user_2fa(self, user_id: str) -> Optional[models.User]:
        with self._session() as session:
            user = session.get(models.User, user_id)
            if not user:
                return None
            user.twofa_secret = ""
            user.twofa_enabled = False
            user.twofa_backup_codes = ""
            user.twofa_configured_at = None
            session.commit()
            session.refresh(user)
            return user

    def verify_and_consume_backup_code(self, user_id: str, backup_code: str) -> bool:
        """Atomically verify a backup code and remove it from the user's list. Returns True if valid."""
        from sqlalchemy import text
        from app.services import twofa

        with self._session() as session:
            if self.db_url.startswith("sqlite:"):
                session.exec(text("BEGIN IMMEDIATE"))
            user = session.get(models.User, user_id)
            if not user:
                return False
            verified, updated_codes = twofa.verify_backup_code(backup_code, user.twofa_backup_codes or "")
            if verified:
                user.twofa_backup_codes = updated_codes
                session.commit()
                return True
            session.rollback()
            return False

    def update_user_profile(
        self,
        user_id: str,
        *,
        contact_email: str | None = None,
        phone: str | None = None,
        title: str | None = None,
        theme: str | None = None,
        company_name: str | None = None,
        department_name: str | None = None,
        default_master_template: str | None = None,
        default_finding_template: str | None = None,
        ai_key_provider: str | None = None,
        llm_extra_instructions: str | None = None,
    ) -> Optional[models.User]:
        with self._session() as session:
            user = session.get(models.User, user_id)
            if not user:
                return None
            if contact_email is not None:
                user.contact_email = contact_email
            if phone is not None:
                user.phone = phone
            if title is not None:
                user.title = title
            if theme is not None:
                user.theme = theme
            if company_name is not None:
                user.company_name = company_name
            if department_name is not None:
                user.department_name = department_name
            if default_master_template is not None:
                user.default_master_template = default_master_template
            if default_finding_template is not None:
                user.default_finding_template = default_finding_template
            if ai_key_provider is not None:
                user.ai_key_provider = ai_key_provider
            if llm_extra_instructions is not None:
                user.llm_extra_instructions = llm_extra_instructions
            session.commit()
            session.refresh(user)
            return user

    def set_user_name(self, user_id: str, name: str) -> Optional[models.User]:
        with self._session() as session:
            user = session.get(models.User, user_id)
            if not user:
                return None
            user.name = name
            session.commit()
            session.refresh(user)
            return user

    def get_user_openai_api_key(self, user_id: str) -> Optional[str]:
        return self.get_user_provider_api_key(user_id, "openai")

    def get_user_provider_api_key(self, user_id: str, provider: str) -> Optional[str]:
        from app.services.crypto import decrypt_text
        with self._session() as session:
            user = session.get(models.User, user_id)
            if not user or not getattr(user, "openai_api_key_encrypted", None):
                return None
            try:
                raw = decrypt_text(user.openai_api_key_encrypted)
            except Exception:
                return None

            # Legacy format: single plaintext key = OpenAI key only.
            try:
                parsed = json.loads(raw)
            except Exception:
                parsed = None
            if isinstance(parsed, dict):
                key = parsed.get((provider or "").strip().lower())
                if isinstance(key, str) and key.strip():
                    return key.strip()
                return None
            if (provider or "").strip().lower() == "openai":
                return str(raw or "").strip() or None
            return None

    def set_user_openai_api_key(self, user_id: str, api_key: Optional[str]) -> bool:
        return self.set_user_provider_api_key(user_id, "openai", api_key)

    def set_user_provider_api_key(self, user_id: str, provider: str, api_key: Optional[str]) -> bool:
        from app.services.crypto import encrypt_text, decrypt_text
        p = (provider or "").strip().lower()
        if not p:
            return False
        with self._session() as session:
            user = session.get(models.User, user_id)
            if not user:
                return False

            key_map: Dict[str, str] = {}
            enc = getattr(user, "openai_api_key_encrypted", None) or ""
            if enc:
                try:
                    existing_raw = decrypt_text(enc)
                    try:
                        parsed = json.loads(existing_raw)
                    except Exception:
                        parsed = None
                    if isinstance(parsed, dict):
                        key_map = {
                            str(k).strip().lower(): str(v).strip()
                            for k, v in parsed.items()
                            if isinstance(v, str) and str(v).strip()
                        }
                    elif str(existing_raw or "").strip():
                        # Legacy single-key storage -> OpenAI slot.
                        key_map["openai"] = str(existing_raw).strip()
                except Exception:
                    key_map = {}

            if api_key is None or (isinstance(api_key, str) and not api_key.strip()):
                key_map.pop(p, None)
            else:
                key_map[p] = api_key.strip()

            if key_map:
                user.openai_api_key_encrypted = encrypt_text(json.dumps(key_map))
            else:
                user.openai_api_key_encrypted = ""
            session.commit()
            return True

    # Settings
    def get_settings(self) -> models.Settings:
        with self._session() as session:
            settings_row = session.get(models.Settings, 1)
            if settings_row:
                return settings_row
            settings_row = models.Settings(id=1)
            session.add(settings_row)
            session.commit()
            session.refresh(settings_row)
            return settings_row

    def upsert_settings(self, values: Dict[str, str]) -> models.Settings:
        with self._session() as session:
            settings_row = session.get(models.Settings, 1)
            if not settings_row:
                settings_row = models.Settings(id=1)
                session.add(settings_row)
            for key in ("org_name", "author_name", "author_email", "author_phone", "author_title", "voice_style", "company_name", "department_name", "theme", "default_master_template", "default_finding_template"):
                if key in values and values[key] is not None:
                    setattr(settings_row, key, values[key])
            session.commit()
            session.refresh(settings_row)
            return settings_row

    # Teams (formerly Clients) / Applications / Reports

    def _get_default_org_id(self) -> str:
        """Temporary helper: Get System organization ID until we implement full org context."""
        with self._session() as session:
            org = session.exec(select(models.Organization).where(models.Organization.slug == "system")).first()
            if org:
                return org.id
            # Create System org if it doesn't exist
            org = models.Organization(
                id=SYSTEM_ORG_ID,
                name="System",
                slug="system",
                settings="{}",
                is_active=True
            )
            session.add(org)
            session.commit()
            return org.id

    def ensure_system_org(self) -> str:
        """Public wrapper to ensure System org exists with the canonical ID."""
        return self._get_default_org_id()

    # ── Teams ────────────────────────────────────────────────────────────────
    def list_clients(self, query: str | None = None, organization_id: str | None = None, include_inactive: bool = False) -> Iterable[models.Team]:
        with self._session() as session:
            stmt = select(models.Team)
            if organization_id:
                stmt = stmt.where(models.Team.organization_id == organization_id)
            if not include_inactive:
                stmt = stmt.where(models.Team.is_active == True)
            if query:
                stmt = stmt.where(models.Team.name.ilike(f"%{query}%"))
            stmt = stmt.order_by(models.Team.name.asc())
            return list(session.exec(stmt).all())

    def create_client(self, name: str, organization_id: str | None = None) -> models.Team:
        with self._session() as session:
            if not organization_id:
                organization_id = self._get_default_org_id()
            client = models.Team(name=name, organization_id=organization_id)
            session.add(client)
            session.commit()
            session.refresh(client)
            return client

    def update_client(self, client_id: str, name: str) -> Optional[models.Team]:
        with self._session() as session:
            client = session.get(models.Team, client_id)
            if not client:
                return None
            client.name = name
            session.commit()
            session.refresh(client)
            return client

    def delete_client(self, client_id: str) -> bool:
        with self._session() as session:
            client = session.get(models.Team, client_id)
            if not client:
                return False
            client.is_active = False
            session.commit()
            return True

    def get_client(self, client_id: str) -> Optional[models.Team]:
        if not client_id:
            return None
        with self._session() as session:
            return session.get(models.Team, client_id)

    # ── Applications ─────────────────────────────────────────────────────────
    def list_applications(self, query: str | None = None, organization_id: str | None = None) -> Iterable[models.Application]:
        with self._session() as session:
            stmt = select(models.Application)
            if organization_id:
                stmt = stmt.where(models.Application.organization_id == organization_id)
            if query:
                stmt = stmt.where(models.Application.name.ilike(f"%{query}%"))
            stmt = stmt.order_by(models.Application.name.asc())
            return list(session.exec(stmt).all())

    def create_application(self, name: str, type: str | None = None, description: str = "", organization_id: str | None = None) -> models.Application:
        with self._session() as session:
            if not organization_id:
                organization_id = self._get_default_org_id()
            app = models.Application(name=name, type=type, description=description, organization_id=organization_id)
            session.add(app)
            session.commit()
            session.refresh(app)
            return app

    def update_application(self, app_id: str, name: str, type: str | None = None, description: str = "") -> Optional[models.Application]:
        with self._session() as session:
            app = session.get(models.Application, app_id)
            if not app:
                return None
            app.name = name
            if type is not None:
                app.type = type
            app.description = description
            session.commit()
            session.refresh(app)
            return app

    def delete_application(self, app_id: str) -> bool:
        with self._session() as session:
            app = session.get(models.Application, app_id)
            if not app:
                return False
            session.delete(app)
            session.commit()
            return True

    def get_application(self, app_id: str) -> Optional[models.Application]:
        if not app_id:
            return None
        with self._session() as session:
            return session.get(models.Application, app_id)

    # ── Reports ──────────────────────────────────────────────────────────────
    def list_reports(self, client_id: str | None = None, application_id: str | None = None, organization_id: str | None = None, query: str | None = None, tag_name: str | None = None) -> Iterable[models.Report]:
        with self._session() as session:
            stmt = select(models.Report)
            if client_id:
                stmt = stmt.where(models.Report.client_id == client_id)
            if application_id:
                stmt = stmt.where(models.Report.application_id == application_id)
            if organization_id:
                stmt = stmt.where(models.Report.organization_id == organization_id)
            if query:
                stmt = stmt.where(models.Report.name.ilike(f"%{query}%"))
            if tag_name and organization_id:
                # Subquery: find report IDs that have this tag
                tag_sub = (
                    select(models.EntityTag.entity_id)
                    .join(models.Tag, models.Tag.id == models.EntityTag.tag_id)
                    .where(
                        models.Tag.organization_id == organization_id,
                        models.Tag.name == tag_name,
                        models.EntityTag.entity_type == "report",
                    )
                )
                stmt = stmt.where(models.Report.id.in_(tag_sub))
            stmt = stmt.order_by(models.Report.created_at.desc())
            return list(session.exec(stmt).all())

    def get_report(self, report_id: str) -> Optional[models.Report]:
        with self._session() as session:
            return session.get(models.Report, report_id)

    def create_report(
        self,
        name: str,
        organization_id: str | None = None,
        created_by: str | None = None,
        client_id: str | None = None,
        application_id: str | None = None,
    ) -> models.Report:
        with self._session() as session:
            if not organization_id:
                organization_id = self._get_default_org_id()
            report = models.Report(
                name=name,
                organization_id=organization_id,
                created_by=created_by,
                client_id=client_id,
                application_id=application_id,
            )
            session.add(report)
            session.commit()
            session.refresh(report)
            return report

    def update_report(self, report_id: str, **updates: str | None) -> Optional[models.Report]:
        """Update report fields. Only provided keys are updated. Pass client_id=None or application_id=None to unassign."""
        allowed = {"name", "client_id", "application_id"}
        with self._session() as session:
            report = session.get(models.Report, report_id)
            if not report:
                return None
            for key, value in updates.items():
                if key in allowed:
                    setattr(report, key, value)
            session.commit()
            session.refresh(report)
            return report

    def update_report_summaries(
        self,
        report_id: str,
        summary_executive: str | None = None,
        summary_technical: str | None = None,
        summary_recommendations: str | None = None,
    ) -> Optional[models.Report]:
        with self._session() as session:
            report = session.get(models.Report, report_id)
            if not report:
                return None
            if summary_executive is not None:
                report.summary_executive = summary_executive
            if summary_technical is not None:
                report.summary_technical = summary_technical
            if summary_recommendations is not None:
                report.summary_recommendations = summary_recommendations
            session.commit()
            session.refresh(report)
            return report

    def delete_report(self, report_id: str) -> bool:
        """Delete a report and all child rows that FK-reference it.

        Findings, ReportShares, and BurpImportSessions all carry a non-cascading
        foreign key to report.id.  PostgreSQL enforces these constraints, so we
        must remove the child rows explicitly before removing the parent row.
        All deletions run inside a single transaction so the operation is atomic.
        """
        with self._session() as session:
            report = session.get(models.Report, report_id)
            if not report:
                return False
            # Delete child rows that reference this report (FK, no DB-level cascade).
            session.exec(delete(models.BurpImportSession).where(models.BurpImportSession.report_id == report_id))
            session.exec(delete(models.ReportShare).where(models.ReportShare.report_id == report_id))
            session.exec(delete(models.Finding).where(models.Finding.report_id == report_id))
            session.delete(report)
            session.commit()
            return True

    # Report Shares
    def list_report_shares(self, report_id: str) -> list[models.ReportShare]:
        with self._session() as session:
            stmt = select(models.ReportShare).where(models.ReportShare.report_id == report_id)
            stmt = stmt.order_by(models.ReportShare.created_at.desc())
            return list(session.exec(stmt).all())

    def get_report_share(self, report_id: str, user_id: str) -> Optional[models.ReportShare]:
        with self._session() as session:
            stmt = select(models.ReportShare).where(
                (models.ReportShare.report_id == report_id) &
                (models.ReportShare.user_id == user_id)
            )
            return session.exec(stmt).first()

    def create_report_share(
        self,
        report_id: str,
        user_id: str,
        shared_by: str,
    ) -> models.ReportShare:
        with self._session() as session:
            share = models.ReportShare(report_id=report_id, user_id=user_id, shared_by=shared_by)
            session.add(share)
            session.commit()
            session.refresh(share)
            return share

    def delete_report_share(self, report_id: str, user_id: str) -> bool:
        with self._session() as session:
            stmt = select(models.ReportShare).where(
                (models.ReportShare.report_id == report_id) &
                (models.ReportShare.user_id == user_id)
            )
            share = session.exec(stmt).first()
            if not share:
                return False
            session.delete(share)
            session.commit()
            return True

    # Findings
    def create_finding(
        self,
        *,
        report_id: str,
        title: str,
        content_json: str,
        notes: str,
        template: str,
        organization_id: str | None = None,
        metadata_json: str = "",
        evidence_payload: str = "",
    ) -> models.Finding:
        with self._session() as session:
            if not organization_id:
                organization_id = self._get_default_org_id()
            finding = models.Finding(
                organization_id=organization_id,
                report_id=report_id,
                title=title or "",
                content_json=content_json or "",
                notes=notes or "",
                template=template or "",
                evidence_payload=evidence_payload or "",
                metadata_json=metadata_json or "",
            )
            session.add(finding)
            session.commit()
            session.refresh(finding)
            return finding

    def get_finding(self, finding_id: str) -> Optional[models.Finding]:
        with self._session() as session:
            return session.get(models.Finding, finding_id)

    def get_findings_by_ids(self, finding_ids: list[str]) -> list[models.Finding]:
        if not finding_ids:
            return []
        with self._session() as session:
            stmt = select(models.Finding).where(models.Finding.id.in_(finding_ids))
            return list(session.exec(stmt).all())

    def update_finding(
        self,
        finding_id: str,
        *,
        title: str = None,
        content_json: str = None,
        notes: str = None,
        template: str = None,
        evidence_payload: str = None,
        metadata_json: str = None,
        validation_guidance: str = None,
        jira_issue_key: str = None,
        jira_issue_url: str = None,
    ) -> Optional[models.Finding]:
        with self._session() as session:
            finding = session.get(models.Finding, finding_id)
            if not finding:
                return None
            if title is not None:
                finding.title = title or ""
            if content_json is not None:
                finding.content_json = content_json or ""
            if notes is not None:
                finding.notes = notes or ""
            if template is not None:
                finding.template = template or ""
            if evidence_payload is not None:
                finding.evidence_payload = evidence_payload
            if metadata_json is not None:
                finding.metadata_json = metadata_json
            if validation_guidance is not None:
                finding.validation_guidance = validation_guidance
            if jira_issue_key is not None:
                finding.jira_issue_key = jira_issue_key or ""
            if jira_issue_url is not None:
                finding.jira_issue_url = jira_issue_url or ""
            session.commit()
            session.refresh(finding)
            return finding

    def delete_finding(self, finding_id: str) -> bool:
        with self._session() as session:
            finding = session.get(models.Finding, finding_id)
            if not finding:
                return False
            session.delete(finding)
            session.commit()
            return True

    def atomic_set_jira_link(
        self,
        finding_id: str,
        jira_issue_key: str,
        jira_issue_url: str,
    ) -> tuple[bool, Optional[str]]:
        """Atomically set Jira link if not already set (prevents race condition).
        
        Returns:
            (success: bool, existing_key: Optional[str])
            - (True, None) if link was set successfully
            - (False, existing_key) if link was already set by another request
        """
        from sqlalchemy import text
        
        with self._session() as session:
            # For SQLite: Use IMMEDIATE transaction to acquire write lock immediately (MED-26 fix)
            if self.db_url.startswith("sqlite:"):
                session.exec(text("BEGIN IMMEDIATE"))
            
            finding = session.get(models.Finding, finding_id)
            if not finding:
                return (False, None)
            
            # Check if already linked (race condition check)
            if finding.jira_issue_key:
                return (False, finding.jira_issue_key)
            
            # Not linked yet, safe to update
            finding.jira_issue_key = jira_issue_key
            finding.jira_issue_url = jira_issue_url
            session.add(finding)
            session.commit()
            return (True, None)

    def list_findings(self, report_id: str) -> Iterable[models.Finding]:
        with self._session() as session:
            stmt = select(models.Finding).where(models.Finding.report_id == report_id)
            stmt = stmt.order_by(models.Finding.created_at.desc())
            return list(session.exec(stmt).all())

    def list_findings_bulk(self, report_ids: list[str]) -> Iterable[models.Finding]:
        if not report_ids:
            return []
        with self._session() as session:
            stmt = select(models.Finding).where(models.Finding.report_id.in_(report_ids))
            stmt = stmt.order_by(models.Finding.report_id, models.Finding.created_at.desc())
            return list(session.exec(stmt).all())

    # Finding templates
    def list_finding_templates(self, organization_id: str | None = None) -> Iterable[models.FindingTemplate]:
        with self._session() as session:
            stmt = select(models.FindingTemplate)
            if organization_id:
                stmt = stmt.where(
                    models.FindingTemplate.organization_id == organization_id
                )
            stmt = stmt.order_by(models.FindingTemplate.name.asc())
            return list(session.exec(stmt).all())

    def create_finding_template(self, name: str, content: str, organization_id: str | None = None) -> models.FindingTemplate:
        with self._session() as session:
            if not organization_id:
                organization_id = self._get_default_org_id()
            t = models.FindingTemplate(name=name, content=content, organization_id=organization_id)
            session.add(t)
            session.commit()
            session.refresh(t)
            return t

    def get_finding_template(self, template_id: str) -> Optional[models.FindingTemplate]:
        with self._session() as session:
            return session.get(models.FindingTemplate, template_id)

    def update_finding_template(self, template_id: str, name: str, content: str) -> Optional[models.FindingTemplate]:
        with self._session() as session:
            t = session.get(models.FindingTemplate, template_id)
            if not t:
                return None
            t.name = name
            t.content = content
            session.commit()
            session.refresh(t)
            return t

    def delete_finding_template(self, template_id: str) -> bool:
        with self._session() as session:
            t = session.get(models.FindingTemplate, template_id)
            if not t:
                return False
            session.delete(t)
            session.commit()
            return True

    # Master templates
    def list_master_templates(self, organization_id: str) -> Iterable[models.MasterTemplate]:
        with self._session() as session:
            stmt = select(models.MasterTemplate).where(
                models.MasterTemplate.organization_id == organization_id
            ).order_by(models.MasterTemplate.name.asc())
            return list(session.exec(stmt).all())

    def get_master_template(self, name: str, organization_id: str) -> Optional[models.MasterTemplate]:
        with self._session() as session:
            stmt = select(models.MasterTemplate).where(
                models.MasterTemplate.name == name,
                models.MasterTemplate.organization_id == organization_id
            )
            return session.exec(stmt).first()

    def create_master_template(self, name: str, content: bytes, organization_id: str | None = None) -> models.MasterTemplate:
        with self._session() as session:
            if not organization_id:
                organization_id = self._get_default_org_id()
            template = models.MasterTemplate(name=name, content=content, organization_id=organization_id)
            session.add(template)
            session.commit()
            session.refresh(template)
            return template

    def update_master_template(self, name: str, content: bytes, organization_id: str) -> Optional[models.MasterTemplate]:
        with self._session() as session:
            stmt = select(models.MasterTemplate).where(
                models.MasterTemplate.name == name,
                models.MasterTemplate.organization_id == organization_id
            )
            template = session.exec(stmt).first()
            if not template:
                return None
            template.content = content
            template.updated_at = datetime.utcnow()
            session.commit()
            session.refresh(template)
            return template

    def delete_master_template(self, name: str, organization_id: str) -> bool:
        with self._session() as session:
            stmt = select(models.MasterTemplate).where(
                models.MasterTemplate.name == name,
                models.MasterTemplate.organization_id == organization_id
            )
            template = session.exec(stmt).first()
            if not template:
                return False
            session.delete(template)
            session.commit()
            return True

    # Bootstrap secret
    def get_bootstrap_secret(self) -> Optional[models.BootstrapAdminSecret]:
        with self._session() as session:
            return session.get(models.BootstrapAdminSecret, 1)

    def set_bootstrap_secret(self, encrypted_password: str) -> models.BootstrapAdminSecret:
        with self._session() as session:
            row = session.get(models.BootstrapAdminSecret, 1)
            if not row:
                row = models.BootstrapAdminSecret(id=1, encrypted_password=encrypted_password)
                session.add(row)
            else:
                row.encrypted_password = encrypted_password
            session.commit()
            session.refresh(row)
            return row

    # Connectors
    def list_connectors(self, organization_id: str | None = None) -> Iterable[models.Connector]:
        with self._session() as session:
            stmt = select(models.Connector)
            if organization_id:
                stmt = stmt.where(models.Connector.organization_id == organization_id)
            stmt = stmt.order_by(models.Connector.created_at.desc())
            return list(session.exec(stmt).all())

    def get_connector(self, connector_id: str) -> Optional[models.Connector]:
        with self._session() as session:
            return session.get(models.Connector, connector_id)

    def get_connector_by_type(self, connector_type: str, organization_id: str) -> Optional[models.Connector]:
        """Get an enabled connector by type for a specific organization.
        
        This method enforces organization boundaries to prevent cross-org connector access.
        """
        with self._session() as session:
            stmt = select(models.Connector).where(
                models.Connector.type == connector_type,
                models.Connector.enabled == True,
                models.Connector.organization_id == organization_id
            )
            return session.exec(stmt).first()

    def create_connector(self, type: str, name: str, config: str, organization_id: str | None = None) -> models.Connector:
        with self._session() as session:
            if not organization_id:
                organization_id = self._get_default_org_id()
            connector = models.Connector(type=type, name=name, config=config, organization_id=organization_id)
            session.add(connector)
            session.commit()
            session.refresh(connector)
            return connector

    def update_connector(self, connector_id: str, name: str, config: str, enabled: bool) -> Optional[models.Connector]:
        with self._session() as session:
            connector = session.get(models.Connector, connector_id)
            if not connector:
                return None
            connector.name = name
            connector.config = config
            connector.enabled = enabled
            connector.updated_at = datetime.utcnow()
            session.commit()
            session.refresh(connector)
            return connector

    def delete_connector(self, connector_id: str) -> bool:
        with self._session() as session:
            connector = session.get(models.Connector, connector_id)
            if not connector:
                return False
            session.delete(connector)
            session.commit()
            return True

    # Organizations
    def list_organizations(self) -> list[models.Organization]:
        with self._session() as session:
            return list(session.exec(select(models.Organization)).all())

    def get_organization(self, org_id: str) -> Optional[models.Organization]:
        with self._session() as session:
            return session.get(models.Organization, org_id)

    def get_organization_by_slug(self, slug: str) -> Optional[models.Organization]:
        with self._session() as session:
            stmt = select(models.Organization).where(models.Organization.slug == slug)
            return session.exec(stmt).first()

    def create_organization(self, name: str, slug: str, settings: str = "{}") -> models.Organization:
        with self._session() as session:
            org = models.Organization(name=name, slug=slug, settings=settings)
            session.add(org)
            session.commit()
            session.refresh(org)
            return org

    def update_organization(
        self,
        org_id: str,
        name: str | None = None,
        slug: str | None = None,
        settings: str | None = None,
        severity_criteria: str | None = None
    ) -> Optional[models.Organization]:
        with self._session() as session:
            org = session.get(models.Organization, org_id)
            if not org:
                return None
            if name is not None:
                org.name = name
            if slug is not None:
                org.slug = slug
            if settings is not None:
                org.settings = settings
            if severity_criteria is not None:
                org.severity_criteria = severity_criteria
            org.updated_at = datetime.utcnow()
            session.commit()
            session.refresh(org)
            return org

    def delete_organization(self, org_id: str) -> bool:
        with self._session() as session:
            org = session.get(models.Organization, org_id)
            if not org:
                return False
            session.delete(org)
            session.commit()
            return True

    # Organization Members
    def list_organization_members(self, org_id: str) -> list[models.OrganizationMember]:
        with self._session() as session:
            stmt = select(models.OrganizationMember).where(
                models.OrganizationMember.organization_id == org_id
            )
            return list(session.exec(stmt).all())

    def get_organization_member(self, org_id: str, user_id: str) -> Optional[models.OrganizationMember]:
        with self._session() as session:
            stmt = (
                select(models.OrganizationMember)
                .where(models.OrganizationMember.organization_id == org_id)
                .where(models.OrganizationMember.user_id == user_id)
            )
            return session.exec(stmt).first()

    def create_organization_member(
        self,
        org_id: str,
        user_id: str,
        role: str,
        invited_by: str | None = None
    ) -> models.OrganizationMember:
        with self._session() as session:
            member = models.OrganizationMember(
                organization_id=org_id,
                user_id=user_id,
                role=role,
                invited_by=invited_by
            )
            session.add(member)
            session.commit()
            session.refresh(member)
            return member

    def update_organization_member_role(
        self,
        org_id: str,
        user_id: str,
        role: str
    ) -> Optional[models.OrganizationMember]:
        with self._session() as session:
            member = self.get_organization_member(org_id, user_id)
            if not member:
                return None
            stmt = (
                select(models.OrganizationMember)
                .where(models.OrganizationMember.organization_id == org_id)
                .where(models.OrganizationMember.user_id == user_id)
            )
            member = session.exec(stmt).first()
            if member:
                member.role = role
                session.commit()
                session.refresh(member)
            return member

    def delete_organization_member(self, org_id: str, user_id: str) -> bool:
        with self._session() as session:
            stmt = (
                select(models.OrganizationMember)
                .where(models.OrganizationMember.organization_id == org_id)
                .where(models.OrganizationMember.user_id == user_id)
            )
            member = session.exec(stmt).first()
            if not member:
                return False
            session.delete(member)
            session.commit()
            return True

    def get_user_organizations(self, user_id: str) -> list[models.Organization]:
        with self._session() as session:
            stmt = (
                select(models.Organization)
                .join(models.OrganizationMember)
                .where(models.OrganizationMember.user_id == user_id)
                .order_by(models.OrganizationMember.joined_at.asc(), models.Organization.id.asc())
            )
            return list(session.exec(stmt).all())

    # Org OIDC & Domains
    def get_org_by_domain(self, domain: str) -> Optional[models.Organization]:
        domain_clean = domain.strip().lower()
        if not domain_clean:
            return None
        with self._session() as session:
            stmt = (
                select(models.Organization)
                .join(models.OrgDomain)
                .where(models.OrgDomain.domain == domain_clean)
            )
            return session.exec(stmt).first()

    def get_org_oidc_config(self, org_id: str, provider_id: str) -> Optional[models.OrgOidcConfig]:
        with self._session() as session:
            stmt = select(models.OrgOidcConfig).where(
                (models.OrgOidcConfig.organization_id == org_id) &
                (models.OrgOidcConfig.provider_id == provider_id)
            )
            return session.exec(stmt).first()

    def list_org_oidc_configs(self, org_id: str) -> list[models.OrgOidcConfig]:
        with self._session() as session:
            stmt = select(models.OrgOidcConfig).where(
                models.OrgOidcConfig.organization_id == org_id
            )
            return list(session.exec(stmt).all())

    def upsert_org_oidc_config(
        self,
        org_id: str,
        provider_id: str,
        provider_label: str,
        issuer: str,
        client_id: str,
        client_secret_encrypted: str,
    ) -> models.OrgOidcConfig:
        with self._session() as session:
            existing = session.exec(
                select(models.OrgOidcConfig).where(
                    (models.OrgOidcConfig.organization_id == org_id) &
                    (models.OrgOidcConfig.provider_id == provider_id)
                )
            ).first()
            if existing:
                existing.provider_label = provider_label
                existing.issuer = issuer
                existing.client_id = client_id
                existing.client_secret_encrypted = client_secret_encrypted
                existing.updated_at = datetime.utcnow()
                session.add(existing)
                session.commit()
                session.refresh(existing)
                return existing
            config = models.OrgOidcConfig(
                organization_id=org_id,
                provider_id=provider_id,
                provider_label=provider_label,
                issuer=issuer,
                client_id=client_id,
                client_secret_encrypted=client_secret_encrypted,
            )
            session.add(config)
            session.commit()
            session.refresh(config)
            return config

    def delete_org_oidc_config(self, org_id: str, provider_id: str) -> bool:
        with self._session() as session:
            stmt = select(models.OrgOidcConfig).where(
                (models.OrgOidcConfig.organization_id == org_id) &
                (models.OrgOidcConfig.provider_id == provider_id)
            )
            config = session.exec(stmt).first()
            if not config:
                return False
            session.delete(config)
            session.commit()
            return True

    def list_org_domains(self, org_id: str) -> list[models.OrgDomain]:
        with self._session() as session:
            stmt = select(models.OrgDomain).where(
                models.OrgDomain.organization_id == org_id
            )
            return list(session.exec(stmt).all())

    def add_org_domain(self, org_id: str, domain: str) -> models.OrgDomain:
        domain_clean = domain.strip().lower()
        if not domain_clean or "@" in domain_clean:
            raise ValueError("Invalid domain")
        with self._session() as session:
            existing = session.exec(
                select(models.OrgDomain).where(models.OrgDomain.domain == domain_clean)
            ).first()
            if existing:
                if existing.organization_id != org_id:
                    raise ValueError(f"Domain {domain_clean} is already used by another org")
                return existing
            d = models.OrgDomain(organization_id=org_id, domain=domain_clean)
            session.add(d)
            session.commit()
            session.refresh(d)
            return d

    def remove_org_domain(self, org_id: str, domain: str) -> bool:
        domain_clean = domain.strip().lower()
        with self._session() as session:
            stmt = select(models.OrgDomain).where(
                (models.OrgDomain.organization_id == org_id) &
                (models.OrgDomain.domain == domain_clean)
            )
            d = session.exec(stmt).first()
            if not d:
                return False
            session.delete(d)
            session.commit()
            return True

    # Organization Invites
    def get_org_invite_by_hash(self, token_hash: str) -> Optional[models.OrganizationInvite]:
        with self._session() as session:
            stmt = select(models.OrganizationInvite).where(models.OrganizationInvite.token_hash == token_hash)
            return session.exec(stmt).first()

    def get_org_invite_by_email(self, org_id: str, email: str) -> Optional[models.OrganizationInvite]:
        with self._session() as session:
            stmt = select(models.OrganizationInvite).where(
                (models.OrganizationInvite.organization_id == org_id) &
                (models.OrganizationInvite.email == email)
            )
            return session.exec(stmt).first()

    def create_org_invite(
        self,
        org_id: str,
        email: str,
        role: str,
        token_hash: str,
        expires_at: datetime,
        invited_by: str | None = None,
        user_id: str | None = None,
    ) -> models.OrganizationInvite:
        with self._session() as session:
            invite = models.OrganizationInvite(
                organization_id=org_id,
                email=email,
                role=role,
                token_hash=token_hash,
                expires_at=expires_at,
                invited_by=invited_by,
                user_id=user_id,
            )
            session.add(invite)
            session.commit()
            session.refresh(invite)
            return invite

    def update_org_invite(
        self,
        invite_id: str,
        token_hash: str,
        expires_at: datetime,
        role: str,
        invited_by: str | None = None,
        user_id: str | None = None,
    ) -> Optional[models.OrganizationInvite]:
        with self._session() as session:
            invite = session.get(models.OrganizationInvite, invite_id)
            if not invite:
                return None
            invite.token_hash = token_hash
            invite.expires_at = expires_at
            invite.used_at = None
            invite.role = role
            invite.invited_by = invited_by
            if user_id:
                invite.user_id = user_id
            session.commit()
            session.refresh(invite)
            return invite

    def mark_org_invite_used(self, invite_id: str) -> Optional[models.OrganizationInvite]:
        with self._session() as session:
            invite = session.get(models.OrganizationInvite, invite_id)
            if not invite:
                return None
            invite.used_at = datetime.utcnow()
            session.commit()
            session.refresh(invite)
            return invite

    # Audit Logs
    def list_audit_logs(self, org_id: str, limit: int = 100, offset: int = 0) -> list[models.AuditLog]:
        with self._session() as session:
            stmt = (
                select(models.AuditLog)
                .where(models.AuditLog.organization_id == org_id)
                .order_by(models.AuditLog.timestamp.desc())
                .offset(offset)
                .limit(limit)
            )
            return list(session.exec(stmt).all())

    def get_audit_log(self, log_id: str) -> Optional[models.AuditLog]:
        with self._session() as session:
            return session.get(models.AuditLog, log_id)

    def create_audit_log(
        self,
        organization_id: str,
        user_id: str,
        action: str,
        resource_type: str,
        resource_id: str | None = None,
        details: str = "",
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> models.AuditLog:
        with self._session() as session:
            log_entry = models.AuditLog(
                organization_id=organization_id,
                user_id=user_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                details=details,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            session.add(log_entry)
            session.commit()
            session.refresh(log_entry)
            return log_entry

    # API Keys
    def list_api_keys(self, user_id: str) -> Iterable[models.ApiKey]:
        with self._session() as session:
            stmt = select(models.ApiKey).where(models.ApiKey.user_id == user_id)
            return list(session.exec(stmt).all())

    def create_api_key(
        self,
        user_id: str,
        name: str,
        key_hash: str,
        prefix: str,
        expires_at: datetime | None = None,
    ) -> models.ApiKey:
        with self._session() as session:
            key = models.ApiKey(
                user_id=user_id,
                name=name,
                key_hash=key_hash,
                prefix=prefix,
                expires_at=expires_at,
            )
            session.add(key)
            session.commit()
            session.refresh(key)
            return key

    def delete_api_key(self, user_id: str, key_id: str) -> bool:
        with self._session() as session:
            key = session.get(models.ApiKey, key_id)
            if not key or key.user_id != user_id:
                return False
            session.delete(key)
            session.commit()
            return True

    def get_api_key_by_hash(self, key_hash: str) -> Optional[models.ApiKey]:
        with self._session() as session:
            stmt = select(models.ApiKey).where(models.ApiKey.key_hash == key_hash)
            return session.exec(stmt).first()

    def update_api_key_last_used(self, key_id: str) -> None:
        with self._session() as session:
            key = session.get(models.ApiKey, key_id)
            if key:
                key.last_used_at = datetime.utcnow()
                session.commit()

    # Login Attempts (Rate Limiting)
    def create_login_attempt(self, identifier: str, ip_address: str | None = None, success: bool = False) -> models.LoginAttempt:
        with self._session() as session:
            attempt = models.LoginAttempt(
                identifier=identifier,
                ip_address=ip_address,
                success=success,
            )
            session.add(attempt)
            session.commit()
            session.refresh(attempt)
            return attempt

    def get_login_attempts(self, identifier: str, since: datetime) -> list[models.LoginAttempt]:
        with self._session() as session:
            stmt = (
                select(models.LoginAttempt)
                .where(
                    models.LoginAttempt.identifier == identifier,
                    models.LoginAttempt.attempted_at >= since,
                    models.LoginAttempt.success == False,
                )
                .order_by(models.LoginAttempt.attempted_at.desc())
            )
            return list(session.exec(stmt).all())

    def clear_login_attempts(self, identifier: str) -> None:
        with self._session() as session:
            stmt = (
                select(models.LoginAttempt)
                .where(models.LoginAttempt.identifier == identifier)
            )
            attempts = session.exec(stmt).all()
            for attempt in attempts:
                session.delete(attempt)
            session.commit()

    # ── Tags ─────────────────────────────────────────────────────────────────
    def list_tags(self, organization_id: str, query: str | None = None) -> Iterable[models.Tag]:
        with self._session() as session:
            stmt = select(models.Tag).where(models.Tag.organization_id == organization_id)
            if query:
                stmt = stmt.where(models.Tag.name.ilike(f"%{query}%"))
            stmt = stmt.order_by(models.Tag.name.asc())
            return list(session.exec(stmt).all())

    def get_tag(self, tag_id: str) -> Optional[models.Tag]:
        with self._session() as session:
            return session.get(models.Tag, tag_id)

    def get_tag_by_name(self, organization_id: str, name: str) -> Optional[models.Tag]:
        with self._session() as session:
            stmt = select(models.Tag).where(
                models.Tag.organization_id == organization_id,
                models.Tag.name == name,
            )
            return session.exec(stmt).first()

    def create_tag(self, organization_id: str, name: str, created_by: str | None = None) -> models.Tag:
        """Create a tag. Returns existing tag if name already exists in org (case-insensitive match)."""
        from sqlalchemy import func
        with self._session() as session:
            # MED-8: Check for existing tag with case-insensitive comparison
            stmt = select(models.Tag).where(
                models.Tag.organization_id == organization_id,
                func.lower(models.Tag.name) == func.lower(name),
            )
            existing = session.exec(stmt).first()
            if existing:
                return existing
            tag = models.Tag(organization_id=organization_id, name=name, created_by=created_by)
            session.add(tag)
            session.commit()
            session.refresh(tag)
            return tag

    def delete_tag(self, tag_id: str) -> bool:
        """Delete a tag and all its entity associations."""
        with self._session() as session:
            tag = session.get(models.Tag, tag_id)
            if not tag:
                return False
            # Delete all entity_tag rows for this tag
            stmt = select(models.EntityTag).where(models.EntityTag.tag_id == tag_id)
            for et in session.exec(stmt).all():
                session.delete(et)
            session.delete(tag)
            session.commit()
            return True

    def add_entity_tag(self, tag_id: str, entity_type: str, entity_id: str, created_by: str | None = None) -> models.EntityTag:
        """Add a tag to an entity. Idempotent: returns existing if already assigned."""
        with self._session() as session:
            stmt = select(models.EntityTag).where(
                models.EntityTag.tag_id == tag_id,
                models.EntityTag.entity_type == entity_type,
                models.EntityTag.entity_id == entity_id,
            )
            existing = session.exec(stmt).first()
            if existing:
                return existing
            et = models.EntityTag(tag_id=tag_id, entity_type=entity_type, entity_id=entity_id, created_by=created_by)
            session.add(et)
            session.commit()
            session.refresh(et)
            return et

    def remove_entity_tag(self, tag_id: str, entity_type: str, entity_id: str) -> bool:
        with self._session() as session:
            stmt = select(models.EntityTag).where(
                models.EntityTag.tag_id == tag_id,
                models.EntityTag.entity_type == entity_type,
                models.EntityTag.entity_id == entity_id,
            )
            et = session.exec(stmt).first()
            if not et:
                return False
            session.delete(et)
            session.commit()
            return True

    def list_entity_tags(self, entity_type: str, entity_id: str) -> Iterable[models.Tag]:
        """List all tags applied to a specific entity."""
        with self._session() as session:
            stmt = (
                select(models.Tag)
                .join(models.EntityTag, models.EntityTag.tag_id == models.Tag.id)
                .where(
                    models.EntityTag.entity_type == entity_type,
                    models.EntityTag.entity_id == entity_id,
                )
                .order_by(models.Tag.name.asc())
            )
            return list(session.exec(stmt).all())

    def list_entities_by_tag(self, tag_id: str, entity_type: str | None = None) -> Iterable[models.EntityTag]:
        """List all entity associations for a tag, optionally filtered by entity_type."""
        with self._session() as session:
            stmt = select(models.EntityTag).where(models.EntityTag.tag_id == tag_id)
            if entity_type:
                stmt = stmt.where(models.EntityTag.entity_type == entity_type)
            return list(session.exec(stmt).all())

    def get_entity_ids_by_tag_name(self, organization_id: str, tag_name: str, entity_type: str) -> list[str]:
        """Resolve a tag name to a list of entity IDs of the given type."""
        with self._session() as session:
            stmt = (
                select(models.EntityTag.entity_id)
                .join(models.Tag, models.Tag.id == models.EntityTag.tag_id)
                .where(
                    models.Tag.organization_id == organization_id,
                    models.Tag.name == tag_name,
                    models.EntityTag.entity_type == entity_type,
                )
            )
            return list(session.exec(stmt).all())

    # Trends filter presets
    def list_trends_presets(
        self, user_id: str, organization_id: str
    ) -> Iterable[models.TrendsFilterPreset]:
        with self._session() as session:
            stmt = select(models.TrendsFilterPreset).where(
                models.TrendsFilterPreset.user_id == user_id,
                models.TrendsFilterPreset.organization_id == organization_id,
            ).order_by(models.TrendsFilterPreset.name)
            return list(session.exec(stmt).all())

    def create_trends_preset(
        self, user_id: str, organization_id: str, name: str, filters: str
    ) -> models.TrendsFilterPreset:
        # Replace existing preset with same name (user+org scoped)
        with self._session() as session:
            existing = session.exec(
                select(models.TrendsFilterPreset).where(
                    models.TrendsFilterPreset.user_id == user_id,
                    models.TrendsFilterPreset.organization_id == organization_id,
                    models.TrendsFilterPreset.name == name,
                )
            ).first()
            if existing:
                session.delete(existing)
                session.commit()
            preset = models.TrendsFilterPreset(
                user_id=user_id,
                organization_id=organization_id,
                name=name.strip()[:255],
                filters=filters or "{}",
            )
            session.add(preset)
            session.commit()
            session.refresh(preset)
            return preset

    def delete_trends_preset(self, preset_id: str, user_id: str) -> bool:
        with self._session() as session:
            preset = session.get(models.TrendsFilterPreset, preset_id)
            if not preset or preset.user_id != user_id:
                return False
            session.delete(preset)
            session.commit()
            return True

    # Burp Import Sessions
    def get_burp_session_by_report_and_hash(
        self, report_id: str, content_hash: str
    ) -> Optional[models.BurpImportSession]:
        with self._session() as session:
            stmt = select(models.BurpImportSession).where(
                models.BurpImportSession.report_id == report_id,
                models.BurpImportSession.content_hash == content_hash,
            )
            return session.exec(stmt).first()

    def create_burp_import_session(
        self, report_id: str, content_hash: str, file_name: str, tasks_json: str
    ) -> models.BurpImportSession:
        """
        Create a new import session.
        
        MED-31: If a race condition occurs (duplicate report_id + content_hash),
        returns the existing session instead of raising an error.
        """
        from sqlalchemy.exc import IntegrityError
        
        with self._session() as session:
            sess = models.BurpImportSession(
                report_id=report_id,
                content_hash=content_hash,
                file_name=file_name,
                tasks_json=tasks_json,
            )
            session.add(sess)
            try:
                session.commit()
                session.refresh(sess)
                return sess
            except IntegrityError:
                # Race condition: another request created this session first (MED-31)
                session.rollback()
                # Fetch and return the existing session
                existing = self.get_burp_session_by_report_and_hash(report_id, content_hash)
                if existing:
                    return existing
                # Should never happen, but re-raise if we can't find it
                raise

    def get_burp_import_session(self, session_id: str) -> Optional[models.BurpImportSession]:
        with self._session() as session:
            return session.get(models.BurpImportSession, session_id)

    def list_burp_sessions_for_report(
        self, report_id: str
    ) -> list[models.BurpImportSession]:
        with self._session() as session:
            stmt = select(models.BurpImportSession).where(
                models.BurpImportSession.report_id == report_id
            ).order_by(models.BurpImportSession.created_at.desc())
            return list(session.exec(stmt).all())

    def update_burp_session_tasks_atomic(
        self, session_id: str, task_updates: dict[int, dict]
    ) -> Optional[models.BurpImportSession]:
        """Atomically update multiple tasks with transaction-level locking.
        
        MED-1 fix: Prevents race conditions between concurrent enqueue and PATCH operations.
        Uses IMMEDIATE transaction mode for SQLite to lock during read-modify-write.
        
        Args:
            session_id: The burp session ID
            task_updates: Dict mapping task_index -> fields to update (e.g., {0: {"status": "generating"}})
        
        Returns:
            Updated session or None if not found
        """
        import json as _json
        from sqlalchemy import text
        
        with self._session() as session:
            # For SQLite: Use IMMEDIATE transaction to acquire write lock immediately
            if self.db_url.startswith("sqlite:"):
                session.exec(text("BEGIN IMMEDIATE"))
            
            sess = session.get(models.BurpImportSession, session_id)
            
            if not sess:
                return None
            
            tasks = _json.loads(sess.tasks_json) if sess.tasks_json else []
            
            # Apply updates
            for task_idx, updates in task_updates.items():
                if 0 <= task_idx < len(tasks):
                    tasks[task_idx] = {**tasks[task_idx], **updates}
            
            sess.tasks_json = _json.dumps(tasks)
            session.commit()
            session.refresh(sess)
            return sess

    def update_burp_session_tasks(
        self, session_id: str, tasks_json: str
    ) -> Optional[models.BurpImportSession]:
        with self._session() as session:
            sess = session.get(models.BurpImportSession, session_id)
            if not sess:
                return None
            sess.tasks_json = tasks_json
            session.commit()
            session.refresh(sess)
            return sess

    def update_burp_session_task_status(
        self, session_id: str, task_index: int, status: str, extra: dict | None = None
    ) -> Optional[models.BurpImportSession]:
        """Atomically update a single task's status within a session.

        MED-1 fix: Uses transaction-level locking (IMMEDIATE for SQLite) to prevent
        concurrent read-modify-write race conditions.
        """
        import json as _json
        from sqlalchemy import text
        
        with self._session() as session:
            # For SQLite: Use IMMEDIATE transaction to acquire write lock immediately
            if self.db_url.startswith("sqlite:"):
                session.exec(text("BEGIN IMMEDIATE"))
            
            sess = session.get(models.BurpImportSession, session_id)
            
            if not sess:
                return None
            tasks = _json.loads(sess.tasks_json) if sess.tasks_json else []
            if task_index < 0 or task_index >= len(tasks):
                return None
            update = {"status": status}
            if extra:
                update.update(extra)
            tasks[task_index] = {**tasks[task_index], **update}
            sess.tasks_json = _json.dumps(tasks)
            session.commit()
            session.refresh(sess)
            return sess

    def update_burp_session_task_status_if_generating(
        self, session_id: str, task_index: int, new_status: str, extra: dict | None = None
    ) -> tuple[bool, Optional[models.BurpImportSession]]:
        """Conditionally update task status ONLY if current status is 'generating'.
        
        This prevents Celery workers from overwriting user-initiated status changes
        (e.g., when the user clicks "Skip" while a task is running).
        
        Returns:
            (updated: bool, session: BurpImportSession | None)
            - updated=True if status was updated
            - updated=False if current status was not 'generating' (e.g., user skipped)
        """
        import json as _json
        from sqlalchemy import text
        
        with self._session() as session:
            # MED-17: Use IMMEDIATE transaction to acquire write lock (same as MED-1 fix)
            if self.db_url.startswith("sqlite:"):
                session.exec(text("BEGIN IMMEDIATE"))
            
            sess = session.get(models.BurpImportSession, session_id)
            if not sess:
                return (False, None)
            tasks = _json.loads(sess.tasks_json) if sess.tasks_json else []
            if task_index < 0 or task_index >= len(tasks):
                return (False, None)
            
            # Check current status
            current_status = tasks[task_index].get("status")
            if current_status != "generating":
                # Status changed (e.g., user skipped) - do not overwrite
                return (False, sess)
            
            # Status is still "generating", safe to update
            update = {"status": new_status}
            if extra:
                update.update(extra)
            tasks[task_index] = {**tasks[task_index], **update}
            sess.tasks_json = _json.dumps(tasks)
            session.commit()
            session.refresh(sess)
            return (True, sess)

    def list_burp_sessions_with_pending(
        self, organization_id: str
    ) -> list[models.BurpImportSession]:
        """List Burp import sessions that have pending/generating/failed tasks, for reports in org.
        Tasks stuck in 'generating' for > 3 min are treated as stale and excluded."""
        import time as _time
        stale_ms = 3 * 60 * 1000  # 3 minutes
        now_ms = int(_time.time() * 1000)

        def has_active_work(tasks: list) -> bool:
            for t in tasks:
                status = t.get("status")
                if status in ("pending", "failed"):
                    return True
                if status == "generating":
                    since = t.get("generating_since")
                    # Treat as stale if no timestamp (legacy) or > 3 min old
                    if since and (now_ms - since) < stale_ms:
                        return True
            return False

        with self._session() as session:
            stmt = (
                select(models.BurpImportSession)
                .join(models.Report, models.BurpImportSession.report_id == models.Report.id)
                .where(models.Report.organization_id == organization_id)
                .order_by(models.BurpImportSession.created_at.desc())
            )
            all_sessions = list(session.exec(stmt).all())
        return [s for s in all_sessions if has_active_work(json.loads(s.tasks_json or "[]"))]

    def delete_import_sessions_for_report(self, report_id: str) -> int:
        """Delete all import sessions for a given report. Returns count of deleted sessions."""
        with self._session() as session:
            stmt = delete(models.BurpImportSession).where(models.BurpImportSession.report_id == report_id)
            result = session.exec(stmt)
            session.commit()
            return result.rowcount if hasattr(result, 'rowcount') else 0

    # ── Generation Tasks ────────────────────────────────────────────────────

    def create_generation_task(
        self,
        *,
        user_id: str,
        organization_id: str,
        report_id,
        task_type: str,
        title: str,
        total_steps: int,
    ) -> models.GenerationTask:
        task = models.GenerationTask(
            user_id=user_id,
            organization_id=organization_id,
            report_id=report_id,
            task_type=task_type,
            title=title,
            total_steps=total_steps,
            status="pending",
            current_step=0,
            progress_log="[]",
        )
        with self._session() as session:
            session.add(task)
            session.commit()
            session.refresh(task)
            return task

    def get_generation_task(self, task_id: str):
        with self._session() as session:
            return session.get(models.GenerationTask, task_id)

    def list_generation_tasks(self, user_id: str, *, limit: int = 50, active_only: bool = False):
        from sqlmodel import select as _select
        with self._session() as session:
            stmt = _select(models.GenerationTask).where(
                models.GenerationTask.user_id == user_id
            ).order_by(models.GenerationTask.created_at.desc()).limit(limit)
            tasks = list(session.exec(stmt).all())
        if active_only:
            tasks = [t for t in tasks if t.status in ("pending", "running")]
        return tasks

    def update_generation_task(self, task_id: str, **fields) -> models.GenerationTask | None:
        with self._session() as session:
            task = session.get(models.GenerationTask, task_id)
            if not task:
                return None
            for k, v in fields.items():
                if hasattr(task, k):
                    setattr(task, k, v)
            session.add(task)
            session.commit()
            session.refresh(task)
            return task

    def claim_generation_task(self, task_id: str, celery_task_id: str) -> models.GenerationTask | None:
        """Atomically transition task from 'pending' → 'running'. Returns None if already claimed."""
        from datetime import datetime as _dt
        with self._session() as session:
            task = session.get(models.GenerationTask, task_id)
            if not task or task.status != "pending":
                return None
            task.status = "running"
            task.celery_task_id = celery_task_id
            task.started_at = _dt.utcnow()
            session.add(task)
            session.commit()
            session.refresh(task)
            return task
