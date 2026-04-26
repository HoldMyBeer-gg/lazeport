"""Tests for MED-1: Enqueue vs PATCH Race - Lost Updates.

Tests verify that concurrent task updates don't result in lost updates
due to read-modify-write race conditions.
"""
import pytest
import json
import threading
from app.db import get_adapter


@pytest.fixture
def burp_session_with_tasks():
    """Create burp session with multiple tasks for testing."""
    adapter = get_adapter()
    adapter.init()
    
    # Create org
    org = adapter.create_organization(name="Test Org", slug="test-org-race")
    
    # Create user
    admin = adapter.upsert_user(
        email="admin@test.com",
        name="Admin",
        provider="local",
        role="user"
    )
    adapter.create_organization_member(org.id, admin.id, "org_admin")
    
    # Create client and app
    client = adapter.create_client(name="Test Team", organization_id=org.id)
    app_obj = adapter.create_application(name="Test App", organization_id=org.id)
    
    # Create report
    report = adapter.create_report(
        "Test Report",
        organization_id=org.id,
        created_by=admin.id,
        client_id=client.id,
        application_id=app_obj.id,
    )
    
    # Create burp session with multiple tasks
    tasks = [
        {"index": 0, "title": "Task 0", "status": "pending"},
        {"index": 1, "title": "Task 1", "status": "pending"},
        {"index": 2, "title": "Task 2", "status": "pending"},
        {"index": 3, "title": "Task 3", "status": "pending"},
    ]
    
    session = adapter.create_burp_import_session(
        report_id=report.id,
        content_hash="test_hash_123",
        file_name="test.xml",
        tasks_json=json.dumps(tasks)
    )
    
    return {
        "session_id": session.id,
        "adapter": adapter,
    }


def test_atomic_task_updates_prevent_lost_updates(burp_session_with_tasks):
    """Test that atomic update method prevents lost updates (MED-1 fix)."""
    setup = burp_session_with_tasks
    adapter = setup["adapter"]
    session_id = setup["session_id"]
    
    # Use atomic method to update multiple tasks
    updates = {
        0: {"status": "generating", "generating_since": 123456},
        1: {"status": "generating", "generating_since": 123457},
    }
    
    result = adapter.update_burp_session_tasks_atomic(session_id, updates)
    assert result is not None
    
    # Verify both updates were applied
    session = adapter.get_burp_import_session(session_id)
    tasks = json.loads(session.tasks_json)
    
    assert tasks[0]["status"] == "generating"
    assert tasks[0]["generating_since"] == 123456
    assert tasks[1]["status"] == "generating"
    assert tasks[1]["generating_since"] == 123457
    assert tasks[2]["status"] == "pending"  # Unchanged
    assert tasks[3]["status"] == "pending"  # Unchanged


def test_single_task_update_with_locking(burp_session_with_tasks):
    """Test that single task update uses row locking (MED-1 fix)."""
    setup = burp_session_with_tasks
    adapter = setup["adapter"]
    session_id = setup["session_id"]
    
    # Update single task
    result = adapter.update_burp_session_task_status(session_id, 2, "skipped")
    assert result is not None
    
    # Verify update was applied
    session = adapter.get_burp_import_session(session_id)
    tasks = json.loads(session.tasks_json)
    assert tasks[2]["status"] == "skipped"


def test_concurrent_updates_no_lost_data(burp_session_with_tasks):
    """Test that concurrent updates don't lose each other's changes (MED-1 fix)."""
    setup = burp_session_with_tasks
    adapter = setup["adapter"]
    session_id = setup["session_id"]
    
    errors = []
    
    def update_task_0():
        try:
            adapter.update_burp_session_task_status(session_id, 0, "generating")
        except Exception as e:
            errors.append(f"Task 0 update failed: {e}")
    
    def update_task_1():
        try:
            adapter.update_burp_session_task_status(session_id, 1, "skipped")
        except Exception as e:
            errors.append(f"Task 1 update failed: {e}")
    
    def update_tasks_2_and_3():
        try:
            adapter.update_burp_session_tasks_atomic(session_id, {
                2: {"status": "completed"},
                3: {"status": "failed"}
            })
        except Exception as e:
            errors.append(f"Tasks 2&3 update failed: {e}")
    
    # Run all three operations concurrently
    threads = [
        threading.Thread(target=update_task_0),
        threading.Thread(target=update_task_1),
        threading.Thread(target=update_tasks_2_and_3),
    ]
    
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    # Check for errors
    assert len(errors) == 0, f"Errors occurred: {errors}"
    
    # Verify all updates were preserved (no lost updates)
    session = adapter.get_burp_import_session(session_id)
    tasks = json.loads(session.tasks_json)
    
    assert tasks[0]["status"] == "generating", "Task 0 update should be preserved"
    assert tasks[1]["status"] == "skipped", "Task 1 update should be preserved"
    assert tasks[2]["status"] == "completed", "Task 2 update should be preserved"
    assert tasks[3]["status"] == "failed", "Task 3 update should be preserved"


def test_many_concurrent_single_task_updates(burp_session_with_tasks):
    """Test many concurrent single-task updates all succeed."""
    setup = burp_session_with_tasks
    adapter = setup["adapter"]
    session_id = setup["session_id"]
    
    errors = []
    results = []
    
    def update_task(task_idx, status):
        try:
            result = adapter.update_burp_session_task_status(session_id, task_idx, status)
            results.append((task_idx, result is not None))
        except Exception as e:
            errors.append(f"Task {task_idx} update failed: {e}")
    
    # Update all 4 tasks concurrently
    threads = [
        threading.Thread(target=update_task, args=(0, "generating")),
        threading.Thread(target=update_task, args=(1, "completed")),
        threading.Thread(target=update_task, args=(2, "failed")),
        threading.Thread(target=update_task, args=(3, "skipped")),
    ]
    
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    # Check for errors
    assert len(errors) == 0, f"Errors occurred: {errors}"
    assert len(results) == 4, "All updates should complete"
    
    # Verify all updates succeeded
    for task_idx, success in results:
        assert success, f"Task {task_idx} update should succeed"
    
    # Verify final state
    session = adapter.get_burp_import_session(session_id)
    tasks = json.loads(session.tasks_json)
    
    # All tasks should have been updated
    assert tasks[0]["status"] == "generating"
    assert tasks[1]["status"] == "completed"
    assert tasks[2]["status"] == "failed"
    assert tasks[3]["status"] == "skipped"
