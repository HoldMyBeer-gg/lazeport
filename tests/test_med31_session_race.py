"""Tests for MED-31: Session Hash Race on Concurrent Uploads.

Tests verify that concurrent uploads of the same file content don't create
duplicate sessions due to unique constraint on (report_id, content_hash).
"""
import pytest
import json
import threading
from app.db import get_adapter


@pytest.fixture
def setup_report():
    """Create org, user, client, app, and report for testing."""
    adapter = get_adapter()
    adapter.init()
    
    # Create org
    org = adapter.create_organization(name="Test Org", slug="test-org-session-race")
    
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
    
    return {
        "report_id": report.id,
        "adapter": adapter,
    }


def test_concurrent_session_creation_no_duplicates(setup_report):
    """Test MED-31: Concurrent uploads of same content don't create duplicate sessions."""
    setup = setup_report
    adapter = setup["adapter"]
    report_id = setup["report_id"]
    
    content_hash = "abc123def456"  # Same hash for both uploads
    file_name = "scan.xml"
    
    tasks = [
        {"index": 0, "status": "pending", "finding": {"name": "Finding 1"}},
        {"index": 1, "status": "pending", "finding": {"name": "Finding 2"}},
    ]
    tasks_json = json.dumps(tasks)
    
    created_sessions = []
    errors = []
    
    def create_session():
        try:
            session = adapter.create_burp_import_session(
                report_id=report_id,
                content_hash=content_hash,
                file_name=file_name,
                tasks_json=tasks_json
            )
            created_sessions.append(session)
        except Exception as e:
            errors.append(f"Session creation failed: {e}")
    
    # Simulate concurrent uploads (5 threads trying to create the same session)
    threads = [threading.Thread(target=create_session) for _ in range(5)]
    
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    # Check for errors
    assert len(errors) == 0, f"Errors occurred: {errors}"
    
    # All threads should succeed (no errors)
    assert len(created_sessions) == 5, "All 5 threads should complete"
    
    # All sessions should have the same ID (only one session created in DB)
    session_ids = [s.id for s in created_sessions]
    assert len(set(session_ids)) == 1, "Should only have one unique session ID (MED-31 fix)"
    
    # Verify only one session exists in DB
    sessions = list(adapter.list_burp_sessions_for_report(report_id))
    assert len(sessions) == 1, "Database should contain exactly one session"
    assert sessions[0].content_hash == content_hash


def test_different_content_creates_separate_sessions(setup_report):
    """Test that different content hashes create separate sessions."""
    setup = setup_report
    adapter = setup["adapter"]
    report_id = setup["report_id"]
    
    # Create two sessions with different content hashes
    session1 = adapter.create_burp_import_session(
        report_id=report_id,
        content_hash="hash_111",
        file_name="scan1.xml",
        tasks_json="[]"
    )
    
    session2 = adapter.create_burp_import_session(
        report_id=report_id,
        content_hash="hash_222",
        file_name="scan2.xml",
        tasks_json="[]"
    )
    
    # Should have different IDs
    assert session1.id != session2.id
    
    # Verify both sessions exist in DB
    sessions = list(adapter.list_burp_sessions_for_report(report_id))
    assert len(sessions) == 2
    
    session_hashes = {s.content_hash for s in sessions}
    assert session_hashes == {"hash_111", "hash_222"}


def test_same_hash_different_reports_creates_separate_sessions():
    """Test that same content hash in different reports creates separate sessions."""
    adapter = get_adapter()
    adapter.init()
    
    # Create org
    org = adapter.create_organization(name="Test Org 2", slug="test-org-2-session")
    
    # Create user
    admin = adapter.upsert_user(
        email="admin2@test.com",
        name="Admin",
        provider="local",
        role="user"
    )
    adapter.create_organization_member(org.id, admin.id, "org_admin")
    
    # Create client and app
    client = adapter.create_client(name="Team", organization_id=org.id)
    app_obj = adapter.create_application(name="App", organization_id=org.id)
    
    # Create two different reports
    report1 = adapter.create_report(
        "Report 1",
        organization_id=org.id,
        created_by=admin.id,
        client_id=client.id,
        application_id=app_obj.id,
    )
    
    report2 = adapter.create_report(
        "Report 2",
        organization_id=org.id,
        created_by=admin.id,
        client_id=client.id,
        application_id=app_obj.id,
    )
    
    content_hash = "shared_hash_999"
    
    # Create session for report 1
    session1 = adapter.create_burp_import_session(
        report_id=report1.id,
        content_hash=content_hash,
        file_name="scan.xml",
        tasks_json="[]"
    )
    
    # Create session for report 2 with same hash (should succeed)
    session2 = adapter.create_burp_import_session(
        report_id=report2.id,
        content_hash=content_hash,
        file_name="scan.xml",
        tasks_json="[]"
    )
    
    # Should have different IDs
    assert session1.id != session2.id
    
    # Verify both sessions exist
    sessions1 = list(adapter.list_burp_sessions_for_report(report1.id))
    sessions2 = list(adapter.list_burp_sessions_for_report(report2.id))
    
    assert len(sessions1) == 1
    assert len(sessions2) == 1
    assert sessions1[0].content_hash == content_hash
    assert sessions2[0].content_hash == content_hash
