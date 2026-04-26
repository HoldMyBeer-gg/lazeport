"""Tests for app.config."""


def test_settings_has_expected_attrs():
    from app.config import settings
    assert hasattr(settings, "templates_dir")
    assert hasattr(settings, "cors_origins")
    assert hasattr(settings, "session_secret_key")
    assert hasattr(settings, "db_url")
    assert hasattr(settings, "llm_dummy_api_key")
