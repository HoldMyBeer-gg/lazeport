"""Tests for CRIT-1: Task cancellation bug fix.

These tests verify that Celery tasks respect user-initiated status changes
(e.g., skipping a task) and do not overwrite them when completing.
"""
import json
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from app.db.sql_adapter import SQLAdapter
from app.db import models
from app.tasks.burp_import import generate_burp_finding_task


@pytest.fixture
def adapter():
    """Create an in-memory SQLite adapter for testing."""
    adapter = SQLAdapter("sqlite:///:memory:")
    adapter.init()
    return adapter


@pytest.fixture
def sample_session(adapter):
    """Create a sample import session with tasks."""
    # Create org, user, client, app, report
    org = adapter.create_organization(name="Test Org", slug="test-org")
    user = adapter.upsert_user(
        email="test@example.com",
        name="Test User",
        provider="local",
        role="admin"
    )
    adapter.create_organization_member(org_id=org.id, user_id=user.id, role="org_admin")
    client = adapter.create_client(name="Test Team", organization_id=org.id)
    app_obj = adapter.create_application(
        name="Test App",
        organization_id=org.id
    )
    report = adapter.create_report(
        "Test Report",
        organization_id=org.id,
        created_by=user.id,
        client_id=client.id,
        application_id=app_obj.id,
    )
    
    # Create import session with multiple tasks
    tasks = [
        {
            "index": 0,
            "status": "pending",
            "finding": {
                "title": "SQL Injection",
                "severity": "High",
                "notes": "Test finding 0",
                "evidence_payload": json.dumps({
                    "schema_version": "1.0",
                    "source": {
                        "type": "burp_xml",
                        "tool": "Burp Suite",
                        "rule_id": None,
                        "original_severity": "High"
                    },
                    "verbatim_text": [],
                    "locations": [],
                    "artifacts": {},
                    "hash": "abc123"
                })
            }
        },
        {
            "index": 1,
            "status": "pending",
            "finding": {
                "title": "XSS",
                "severity": "Medium",
                "notes": "Test finding 1",
                "evidence_payload": json.dumps({
                    "schema_version": "1.0",
                    "source": {
                        "type": "burp_xml",
                        "tool": "Burp Suite",
                        "rule_id": None,
                        "original_severity": "Medium"
                    },
                    "verbatim_text": [],
                    "locations": [],
                    "artifacts": {},
                    "hash": "def456"
                })
            }
        }
    ]
    
    session = adapter.create_burp_import_session(
        report_id=report.id,
        file_name="test.xml",
        content_hash="hash123",
        tasks_json=json.dumps(tasks)
    )
    
    return session, report, user, org


def test_conditional_update_respects_skip(adapter, sample_session):
    """Test that conditional update does not overwrite 'skipped' status."""
    session, _, _, _ = sample_session
    
    # Set task to "skipped"
    adapter.update_burp_session_task_status(session.id, 0, "skipped")
    
    # Try to update to "completed" (should fail)
    updated, sess = adapter.update_burp_session_task_status_if_generating(
        session.id, 0, "completed"
    )
    
    assert updated is False, "Should not update when status is not 'generating'"
    assert sess is not None, "Should return session even when not updated"
    
    # Verify status is still "skipped"
    tasks = json.loads(sess.tasks_json)
    assert tasks[0]["status"] == "skipped", "Status should remain 'skipped'"


def test_conditional_update_allows_generating_to_completed(adapter, sample_session):
    """Test that conditional update works when status is 'generating'."""
    session, _, _, _ = sample_session
    
    # Set task to "generating"
    adapter.update_burp_session_task_status(session.id, 0, "generating")
    
    # Update to "completed" (should succeed)
    updated, sess = adapter.update_burp_session_task_status_if_generating(
        session.id, 0, "completed"
    )
    
    assert updated is True, "Should update when status is 'generating'"
    assert sess is not None
    
    # Verify status is now "completed"
    tasks = json.loads(sess.tasks_json)
    assert tasks[0]["status"] == "completed", "Status should be 'completed'"


def test_conditional_update_respects_completed(adapter, sample_session):
    """Test that conditional update does not overwrite 'completed' status."""
    session, _, _, _ = sample_session
    
    # Set task to "completed"
    adapter.update_burp_session_task_status(session.id, 0, "completed")
    
    # Try to update to "failed" (should fail)
    updated, sess = adapter.update_burp_session_task_status_if_generating(
        session.id, 0, "failed"
    )
    
    assert updated is False
    tasks = json.loads(sess.tasks_json)
    assert tasks[0]["status"] == "completed", "Status should remain 'completed'"


def test_conditional_update_with_extra_data(adapter, sample_session):
    """Test that conditional update includes extra data when updating."""
    session, _, _, _ = sample_session
    
    # Set task to "generating"
    adapter.update_burp_session_task_status(session.id, 0, "generating")
    
    # Update with extra data
    updated, sess = adapter.update_burp_session_task_status_if_generating(
        session.id, 0, "completed", extra={"finding_id": "abc-123"}
    )
    
    assert updated is True
    tasks = json.loads(sess.tasks_json)
    assert tasks[0]["status"] == "completed"
    assert tasks[0]["finding_id"] == "abc-123", "Extra data should be included"


def test_task_aborts_if_already_skipped(adapter, sample_session):
    """Test that Celery task aborts early if status is 'skipped'."""
    session, _, _, _ = sample_session
    
    # Set task 0 to "skipped"
    adapter.update_burp_session_task_status(session.id, 0, "skipped")
    
    # Mock get_adapter to return our test adapter
    with patch('app.tasks.burp_import.get_adapter', return_value=adapter):
        with patch('app.tasks.burp_import.structure_notes_with_context') as mock_structure:
            result = generate_burp_finding_task(
                session_id=session.id,
                task_index=0
            )
    
    # Task should abort without calling LLM
    mock_structure.assert_not_called()
    assert result["ok"] is True
    assert result.get("aborted") is True
    assert "already skipped" in result.get("reason", "").lower()


def test_task_aborts_if_already_completed(adapter, sample_session):
    """Test that Celery task aborts early if status is 'completed'."""
    session, _, _, _ = sample_session
    
    # Set task 0 to "completed"
    adapter.update_burp_session_task_status(session.id, 0, "completed")
    
    # Mock get_adapter to return our test adapter
    with patch('app.tasks.burp_import.get_adapter', return_value=adapter):
        with patch('app.tasks.burp_import.structure_notes_with_context') as mock_structure:
            result = generate_burp_finding_task(
                session_id=session.id,
                task_index=0
            )
    
    # Task should abort without calling LLM
    mock_structure.assert_not_called()
    assert result["ok"] is True
    assert result.get("aborted") is True
    assert "already completed" in result.get("reason", "").lower()


def test_task_respects_skip_during_execution(adapter, sample_session):
    """Test race condition: user skips task while LLM is running."""
    session, report, _, org = sample_session
    
    # Set task 0 to "generating"
    adapter.update_burp_session_task_status(session.id, 0, "generating")
    
    # Mock get_adapter to return our test adapter
    with patch('app.tasks.burp_import.get_adapter', return_value=adapter):
        # Mock LLM to simulate work, then change status during execution
        def side_effect_skip_during_execution(*args, **kwargs):
            # Simulate user skipping task while LLM is running
            adapter.update_burp_session_task_status(session.id, 0, "skipped")
            
            # Return valid structured data
            return (
                {
                    "Finding Title": "Test Finding",
                    "Severity": "High",
                    "Vulnerability Summary": "Test summary"
                },
                "{}"
            )
        
        with patch('app.tasks.burp_import.structure_notes_with_context') as mock_structure:
            mock_structure.side_effect = side_effect_skip_during_execution
            
            # Run task
            result = generate_burp_finding_task(
                session_id=session.id,
                task_index=0
            )
    
    # Task should complete successfully but not update status
    assert result["ok"] is True
    assert "finding_id" in result
    
    # Verify status is still "skipped" (not overwritten with "completed")
    sess = adapter.get_burp_import_session(session.id)
    tasks = json.loads(sess.tasks_json)
    assert tasks[0]["status"] == "skipped", "Status should remain 'skipped'"


def test_double_enqueue_safe(adapter, sample_session):
    """Test that double-enqueuing the same task is safe."""
    session, _, _, _ = sample_session
    
    # Set task to "completed" (simulating first task completion)
    adapter.update_burp_session_task_status(session.id, 0, "completed")
    
    # Mock get_adapter to return our test adapter
    with patch('app.tasks.burp_import.get_adapter', return_value=adapter):
        with patch('app.tasks.burp_import.structure_notes_with_context') as mock_structure:
            result = generate_burp_finding_task(
                session_id=session.id,
                task_index=0
            )
    
    # Second task should abort
    mock_structure.assert_not_called()
    assert result.get("aborted") is True


def test_session_deleted_during_execution(adapter, sample_session):
    """Test graceful handling when session is deleted mid-execution."""
    session, report, _, org = sample_session
    
    # Mock get_adapter to return our test adapter
    with patch('app.tasks.burp_import.get_adapter', return_value=adapter):
        # Mock structure_notes to delete session during execution
        def side_effect_delete_session(*args, **kwargs):
            # Delete session while task is running
            adapter.delete_import_sessions_for_report(report.id)
            return ({"Finding Title": "Test", "Severity": "High"}, "{}")
        
        with patch('app.tasks.burp_import.structure_notes_with_context') as mock_structure:
            mock_structure.side_effect = side_effect_delete_session
            
            # Task should handle gracefully (finding created, status update fails)
            result = generate_burp_finding_task(
                session_id=session.id,
                task_index=0
            )
    
    # Task completes but can't update status (session deleted)
    # Should not crash
    assert "ok" in result or "error" in result


def test_conditional_update_session_not_found(adapter):
    """Test that conditional update handles non-existent session gracefully."""
    updated, sess = adapter.update_burp_session_task_status_if_generating(
        "nonexistent-session-id",
        0,
        "completed"
    )
    
    assert updated is False
    assert sess is None


def test_conditional_update_task_index_out_of_range(adapter, sample_session):
    """Test that conditional update handles invalid task index gracefully."""
    session, _, _, _ = sample_session
    
    updated, sess = adapter.update_burp_session_task_status_if_generating(
        session.id,
        999,  # Out of range
        "completed"
    )
    
    assert updated is False
    assert sess is None


def test_normal_flow_unchanged(adapter, sample_session):
    """Test that normal flow (pending → generating → completed) still works."""
    session, report, user, org = sample_session
    
    # Set task to "generating"
    adapter.update_burp_session_task_status(session.id, 0, "generating")
    
    # Mock get_adapter to return our test adapter
    with patch('app.tasks.burp_import.get_adapter', return_value=adapter):
        # Mock the LLM
        with patch('app.tasks.burp_import.structure_notes_with_context') as mock_structure:
            mock_structure.return_value = (
                {
                    "Finding Title": "SQL Injection in Login",
                    "Severity": "High",
                    "Vulnerability Summary": "Test summary",
                    "Details": "Test details",
                    "Remediation": "Test remediation"
                },
                "{}"
            )
            
            # Run task
            result = generate_burp_finding_task(
                session_id=session.id,
                task_index=0
            )
    
    # Task should complete successfully
    assert result["ok"] is True
    assert "finding_id" in result
    
    # Verify status is "completed"
    sess = adapter.get_burp_import_session(session.id)
    tasks = json.loads(sess.tasks_json)
    assert tasks[0]["status"] == "completed"
    
    # Verify finding was created
    findings = list(adapter.list_findings(report.id))
    assert len(findings) == 1
    assert findings[0].title == "SQL Injection in Login"


def test_concurrent_skip_operations(adapter, sample_session):
    """Test that concurrent skip operations are handled atomically."""
    session, _, _, _ = sample_session
    
    # Set task to "generating"
    adapter.update_burp_session_task_status(session.id, 0, "generating")
    
    # Simulate two concurrent attempts to change status
    # First sets to "skipped"
    adapter.update_burp_session_task_status(session.id, 0, "skipped")
    
    # Second tries to set to "completed" (should fail)
    updated, sess = adapter.update_burp_session_task_status_if_generating(
        session.id, 0, "completed"
    )
    
    assert updated is False
    tasks = json.loads(sess.tasks_json)
    assert tasks[0]["status"] == "skipped"


def test_task_failure_respects_skip(adapter, sample_session):
    """Test that task failures also respect skip status."""
    session, _, _, _ = sample_session
    
    # Set task to "generating"
    adapter.update_burp_session_task_status(session.id, 0, "generating")
    
    # Mock get_adapter to return our test adapter
    with patch('app.tasks.burp_import.get_adapter', return_value=adapter):
        # Mock structure_notes to raise an exception, but skip during execution
        def side_effect_skip_then_fail(*args, **kwargs):
            # User skips task
            adapter.update_burp_session_task_status(session.id, 0, "skipped")
            # Then task fails
            raise Exception("LLM API error")
        
        with patch('app.tasks.burp_import.structure_notes_with_context') as mock_structure:
            mock_structure.side_effect = side_effect_skip_then_fail
            
            # Run task (will fail)
            result = generate_burp_finding_task(
                session_id=session.id,
                task_index=0
            )
    
    # Task should fail but not overwrite skip
    assert result["ok"] is False
    assert "error" in result
    
    # Verify status is still "skipped" (not "failed")
    sess = adapter.get_burp_import_session(session.id)
    tasks = json.loads(sess.tasks_json)
    assert tasks[0]["status"] == "skipped"


def test_generating_timestamp_preserved(adapter, sample_session):
    """Test that generating_since timestamp is preserved during updates."""
    session, _, _, _ = sample_session
    
    # Set task to "generating" with timestamp
    import time
    timestamp = int(time.time() * 1000)
    adapter.update_burp_session_task_status(
        session.id, 0, "generating",
        extra={"generating_since": timestamp}
    )
    
    # Update to "completed"
    updated, sess = adapter.update_burp_session_task_status_if_generating(
        session.id, 0, "completed"
    )
    
    assert updated is True
    tasks = json.loads(sess.tasks_json)
    assert tasks[0]["status"] == "completed"
    # Timestamp should be preserved in task data
    assert "generating_since" in tasks[0]


def test_multiple_tasks_independent(adapter, sample_session):
    """Test that skipping one task doesn't affect others."""
    session, report, _, _ = sample_session
    
    # Set task 0 to "generating", task 1 to "skipped"
    adapter.update_burp_session_task_status(session.id, 0, "generating")
    adapter.update_burp_session_task_status(session.id, 1, "skipped")
    
    # Update task 0 to "completed" (should succeed)
    updated_0, _ = adapter.update_burp_session_task_status_if_generating(
        session.id, 0, "completed"
    )
    
    # Try to update task 1 to "completed" (should fail)
    updated_1, sess = adapter.update_burp_session_task_status_if_generating(
        session.id, 1, "completed"
    )
    
    assert updated_0 is True, "Task 0 should update"
    assert updated_1 is False, "Task 1 should not update"
    
    tasks = json.loads(sess.tasks_json)
    assert tasks[0]["status"] == "completed"
    assert tasks[1]["status"] == "skipped"


@patch('app.tasks.burp_import.structure_notes_with_context')
def test_pending_to_completed_not_allowed(mock_structure, adapter, sample_session):
    """Test that conditional update only works from 'generating', not 'pending'."""
    session, _, _, _ = sample_session
    
    # Task starts as "pending" (not "generating")
    # Try to update to "completed" (should fail)
    updated, sess = adapter.update_burp_session_task_status_if_generating(
        session.id, 0, "completed"
    )
    
    assert updated is False
    tasks = json.loads(sess.tasks_json)
    assert tasks[0]["status"] == "pending"


def test_task_with_no_evidence_payload(adapter, sample_session):
    """Test that task handles findings with no evidence_payload gracefully."""
    session, report, _, _ = sample_session
    
    # Modify task to have no evidence_payload
    sess = adapter.get_burp_import_session(session.id)
    tasks = json.loads(sess.tasks_json)
    tasks[0]["finding"].pop("evidence_payload", None)
    adapter.update_burp_session_tasks(session.id, json.dumps(tasks))
    
    # Set to generating
    adapter.update_burp_session_task_status(session.id, 0, "generating")
    
    # Mock get_adapter to return our test adapter
    with patch('app.tasks.burp_import.get_adapter', return_value=adapter):
        # Mock LLM
        with patch('app.tasks.burp_import.structure_notes_with_context') as mock_structure:
            mock_structure.return_value = (
                {
                    "Finding Title": "Test",
                    "Severity": "High",
                    "Vulnerability Summary": "Summary"
                },
                "{}"
            )
            
            # Run task
            result = generate_burp_finding_task(
                session_id=session.id,
                task_index=0
            )
    
    # Should complete (evidence_payload built from Burp data)
    assert result["ok"] is True
    
    # Verify status updated to completed
    sess = adapter.get_burp_import_session(session.id)
    tasks = json.loads(sess.tasks_json)
    assert tasks[0]["status"] == "completed"
