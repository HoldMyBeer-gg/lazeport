import pytest
from unittest.mock import patch, MagicMock
from app.services.jira import JiraClient, _sanitize_error_message

@pytest.fixture
def jira_client():
    """Fixture for JiraClient."""
    return JiraClient(url="https://test.atlassian.net", email="test@example.com", api_token="test_token")

def test_create_issue_success(jira_client):
    """Test successful Jira issue creation."""
    # Arrange
    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_response.json.return_value = {'key': 'TEST-123'}

    project_key = "TEST"
    summary = "Test Summary"
    description = "Test Description"
    issue_type = "Bug"

    # Act
    with patch('httpx.post', return_value=mock_response) as mock_post:
        success, message, issue_key = jira_client.create_issue(
            project_key=project_key,
            summary=summary,
            description=description,
            issue_type=issue_type
        )

    # Assert
    assert success is True
    assert issue_key == 'TEST-123'
    assert "Created TEST-123" in message
    mock_post.assert_called_once()
    call_args, call_kwargs = mock_post.call_args
    assert call_args[0] == "https://test.atlassian.net/rest/api/3/issue"
    assert call_kwargs['json']['fields']['project']['key'] == project_key
    assert call_kwargs['json']['fields']['summary'] == summary
    assert call_kwargs['json']['fields']['description']['content'][0]['content'][0]['text'] == description
    assert call_kwargs['json']['fields']['issuetype']['name'] == issue_type

def test_test_connection_success(jira_client):
    """Test successful Jira connection."""
    # Arrange
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {'displayName': 'Test User'}

    # Act
    with patch('httpx.get', return_value=mock_response) as mock_get:
        success, message = jira_client.test_connection()

    # Assert
    assert success is True
    assert message == "Connected as Test User"
    mock_get.assert_called_once_with(
        "https://test.atlassian.net/rest/api/3/myself",
        auth=("test@example.com", "test_token"),
        headers={'Accept': 'application/json', 'Content-Type': 'application/json'},
        timeout=10.0,
    )


def test_sanitize_error_message_removes_tokens():
    """Test that _sanitize_error_message removes token-like strings."""
    # Token-like strings (20+ chars)
    assert "[REDACTED]" in _sanitize_error_message("Error: Invalid token abc123def456ghi789jkl012mno345pqr678")
    assert "abc123def456ghi789jkl012mno345pqr678" not in _sanitize_error_message("Error: Invalid token abc123def456ghi789jkl012mno345pqr678")
    
    # Base64-like strings
    assert "[REDACTED]" in _sanitize_error_message("Failed: dGVzdF90b2tlbl92ZXJ5X2xvbmdfYmFzZTY0X3N0cmluZ19oZXJl")
    
    # Authorization headers
    result = _sanitize_error_message("Authorization: Bearer super-secret-token-12345")
    assert "[REDACTED]" in result
    assert "super-secret-token-12345" not in result
    
    # API key patterns
    result = _sanitize_error_message("api_key=mysecretkey123456789")
    assert "[REDACTED]" in result
    assert "mysecretkey123456789" not in result
    
    # Normal short strings should remain
    assert _sanitize_error_message("Connection timeout") == "Connection timeout"
    assert _sanitize_error_message("Invalid project key") == "Invalid project key"


def test_create_issue_sanitizes_api_errors(jira_client):
    """Test that create_issue sanitizes Jira API error messages containing tokens."""
    # Arrange: Mock a Jira API error response with a fake token in the error message
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.text = "Unauthorized: Invalid token abc123def456ghi789jkl012mno345pqr678"
    mock_response.json.return_value = {
        'errorMessages': ["Unauthorized: Invalid token abc123def456ghi789jkl012mno345pqr678"]
    }

    # Act
    with patch('httpx.post', return_value=mock_response):
        success, message, issue_key = jira_client.create_issue(
            project_key="TEST",
            summary="Test",
            description="Test Description"
        )

    # Assert
    assert success is False
    assert issue_key is None
    assert "abc123def456ghi789jkl012mno345pqr678" not in message, "Token should be redacted"
    assert "[REDACTED]" in message, "Should contain redaction marker"


def test_test_connection_sanitizes_exceptions(jira_client):
    """Test that test_connection sanitizes exceptions containing auth details."""
    # Arrange: Simulate an exception with auth token in the message
    exception_with_token = Exception("Connection refused by https://test.atlassian.net with token abc123def456ghi789jkl012mno345pqr678")
    
    # Act
    with patch('httpx.get', side_effect=exception_with_token):
        success, message = jira_client.test_connection()

    # Assert
    assert success is False
    assert "abc123def456ghi789jkl012mno345pqr678" not in message, "Token should be redacted"
    assert "[REDACTED]" in message, "Should contain redaction marker"


def test_list_projects_skips_projects_with_none_key_or_name(jira_client):
    """Test that list_projects skips projects with None key or name without crashing."""
    # Arrange: Mock response with some projects missing key or name
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        'values': [
            {'id': '1', 'key': 'VALID', 'name': 'Valid Project'},
            {'id': '2', 'key': None, 'name': 'Missing Key'},  # Should be skipped
            {'id': '3', 'key': 'VALID2', 'name': None},  # Should be skipped
            {'id': '4', 'key': None, 'name': None},  # Should be skipped
            {'id': '5', 'key': 'GOOD', 'name': 'Good Project'},
        ]
    }
    
    # Act
    with patch('httpx.get', return_value=mock_response):
        projects = jira_client.list_projects()
    
    # Assert
    assert len(projects) == 2, "Should only return projects with valid key and name"
    assert projects[0]['key'] == 'VALID'
    assert projects[0]['name'] == 'Valid Project'
    assert projects[1]['key'] == 'GOOD'
    assert projects[1]['name'] == 'Good Project'


def test_list_projects_with_query_handles_none_values(jira_client):
    """Test that query filtering doesn't crash on None key/name."""
    # Arrange: Mock response with projects where some have None values
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        'values': [
            {'id': '1', 'key': 'TEST', 'name': 'Test Project'},
            {'id': '2', 'key': None, 'name': 'Bad Project'},
            {'id': '3', 'key': 'DEMO', 'name': 'Demo Project'},
        ]
    }
    
    # Act
    with patch('httpx.get', return_value=mock_response):
        projects = jira_client.list_projects(query="test")
    
    # Assert: Should return only VALID project matching query
    assert len(projects) == 1
    assert projects[0]['key'] == 'TEST'
    assert projects[0]['name'] == 'Test Project'
