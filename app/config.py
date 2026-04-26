import os
from typing import List


class Settings:
    # Placeholder for providers that skip auth (Ollama, some openai-compatible).
    # Not a secret, just for API compatibility. LLM config is per-user in the UI.
    llm_dummy_api_key: str = "ollama"

    # CORS: allow frontend on different origin (dev) or same origin (prod). For prod, add your domain. If frontend is same-origin, CORS isn't needed but doesn't hurt.
    cors_origins_env = os.getenv("CORS_ORIGINS", "")
    cors_origins: List[str] = (
        [origin.strip() for origin in cors_origins_env.split(",") if origin.strip()]
        if cors_origins_env
        else [
            "http://localhost:5173",   # Vite dev server
            "http://localhost:3000",   # Alternative dev port
            "http://127.0.0.1:5173",
            "http://127.0.0.1:3000",
        ]
    )

    # Template directory (relative to project root or absolute)
    templates_dir: str = os.getenv("TEMPLATES_DIR", "templates")

    # Public app URL (used in email links). Example: https://app.example.com
    public_app_url: str = os.getenv("PUBLIC_APP_URL", "").strip()

    # Auth / sessions
    auth_enabled: bool = os.getenv("AUTH_DISABLED", "0").strip() not in ("1", "true", "yes")
    disable_2fa: bool = os.getenv("DISABLE_2FA", "0").strip() in ("1", "true", "yes")
    _DEFAULT_SESSION_SECRET = "change-me-session-secret"  # nosec B105
    _DEFAULT_APP_SECRET = "change-me-app-secret"          # nosec B105
    session_secret_key: str = os.getenv("SESSION_SECRET_KEY", _DEFAULT_SESSION_SECRET)
    app_secret_key: str = os.getenv("APP_SECRET_KEY", _DEFAULT_APP_SECRET)
    session_timeout_minutes: int = int(os.getenv("SESSION_TIMEOUT_MINUTES", "30"))

    # Database / adapter
    db_adapter: str = os.getenv("DB_ADAPTER", "sql").strip().lower()
    db_url: str = os.getenv("DATABASE_URL", "sqlite:///./data/lazeport.db")

    # Email (SMTP) for share notifications
    smtp_host: str = os.getenv("SMTP_HOST", "").strip()
    smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
    smtp_username: str = os.getenv("SMTP_USERNAME", "").strip()
    smtp_password: str = os.getenv("SMTP_PASSWORD", "").strip()
    smtp_from: str = os.getenv("SMTP_FROM", "").strip()
    smtp_use_tls: bool = os.getenv("SMTP_USE_TLS", "1").strip() not in ("0", "false", "no")

    # Log level for local debugging (e.g. LOG_LEVEL=DEBUG)
    log_level: str = os.getenv("LOG_LEVEL", "INFO").upper()

    # Demo mode: when true, seeds rich sample data for Trends page
    demo_mode: bool = os.getenv("DEMO_MODE", "0").strip() in ("1", "true", "yes")

    # Celery / Redis
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    celery_broker_url: str = os.getenv("CELERY_BROKER_URL", os.getenv("REDIS_URL", "redis://localhost:6379/0"))



settings = Settings()


def get_settings() -> Settings:
    """Get settings instance (for dependency injection)."""
    return settings
