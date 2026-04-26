"""Test multi-provider API key storage"""
import pytest
from app.db.sql_adapter import SQLAdapter
from app.db.models import User


@pytest.fixture
def adapter():
    """Create a test adapter"""
    adapter = SQLAdapter()
    adapter.init()
    return adapter


@pytest.fixture
def test_user(adapter):
    """Create a test user"""
    user = adapter.upsert_user(
        email="test@example.com",
        name="Test User",
        provider="local"
    )
    return user


def test_multiple_provider_keys(adapter, test_user):
    """Test that multiple provider keys can be stored independently"""
    user_id = test_user.id
    
    # Set OpenAI key
    adapter.set_user_provider_api_key(user_id, "openai", "sk-openai-key-123")
    assert adapter.get_user_provider_api_key(user_id, "openai") == "sk-openai-key-123"
    assert adapter.get_user_provider_api_key(user_id, "anthropic") is None
    
    # Set Anthropic key - should not overwrite OpenAI
    adapter.set_user_provider_api_key(user_id, "anthropic", "sk-ant-key-456")
    assert adapter.get_user_provider_api_key(user_id, "openai") == "sk-openai-key-123"
    assert adapter.get_user_provider_api_key(user_id, "anthropic") == "sk-ant-key-456"
    
    # Set DeepSeek key - should not affect others
    adapter.set_user_provider_api_key(user_id, "deepseek", "sk-deepseek-789")
    assert adapter.get_user_provider_api_key(user_id, "openai") == "sk-openai-key-123"
    assert adapter.get_user_provider_api_key(user_id, "anthropic") == "sk-ant-key-456"
    assert adapter.get_user_provider_api_key(user_id, "deepseek") == "sk-deepseek-789"
    
    # Delete one key - should not affect others
    adapter.set_user_provider_api_key(user_id, "anthropic", None)
    assert adapter.get_user_provider_api_key(user_id, "openai") == "sk-openai-key-123"
    assert adapter.get_user_provider_api_key(user_id, "anthropic") is None
    assert adapter.get_user_provider_api_key(user_id, "deepseek") == "sk-deepseek-789"


def test_legacy_single_key_migration(adapter, test_user):
    """Test that legacy single-key format is properly migrated"""
    from app.services.crypto import encrypt_text
    user_id = test_user.id
    
    # Simulate legacy format: single encrypted string (not JSON)
    with adapter._session() as session:
        user = session.get(User, user_id)
        user.openai_api_key_encrypted = encrypt_text("sk-legacy-openai-key")
        session.commit()
    
    # Should read as OpenAI key
    assert adapter.get_user_provider_api_key(user_id, "openai") == "sk-legacy-openai-key"
    assert adapter.get_user_provider_api_key(user_id, "anthropic") is None
    
    # Setting a new provider key should migrate to multi-provider format
    adapter.set_user_provider_api_key(user_id, "anthropic", "sk-ant-new")
    
    # Both should now work
    assert adapter.get_user_provider_api_key(user_id, "openai") == "sk-legacy-openai-key"
    assert adapter.get_user_provider_api_key(user_id, "anthropic") == "sk-ant-new"
