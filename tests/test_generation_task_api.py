"""
Integration tests for background generation task API endpoints.
Tests RBAC enforcement, validation, and task lifecycle via FastAPI TestClient.
"""
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app.main import app
from app.services.auth import get_current_user
from app.db import get_adapter

_TINY_PNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="

# Fixed user ID shared by all tests that check ownership
_TEST_USER_ID = "user-1"

client = TestClient(app)


def _mock_user():
    """Return a fake user whose id matches the mock task user_id."""
    from app.db import models
    u = MagicMock(spec=models.User)
    u.id = _TEST_USER_ID
    u.email = "test@local"
    u.role = "admin"
    u.name = "Test User"
    u.is_active = True
    return u


def _make_task(task_id="task-1", status="running", task_type="generate_finding"):
    from app.db.models import GenerationTask
    from datetime import datetime
    t = MagicMock(spec=GenerationTask)
    t.id = task_id
    t.user_id = _TEST_USER_ID
    t.organization_id = "org-1"
    t.report_id = "report-1"
    t.finding_id = None
    t.task_type = task_type
    t.title = "Generating: test finding"
    t.status = status
    t.celery_task_id = "celery-123"
    t.current_step = 1
    t.total_steps = 4
    t.progress_log = '["Parsing notes..."]'
    t.result_json = ""
    t.error = ""
    t.created_at = datetime(2026, 1, 1, 12, 0, 0)
    t.started_at = datetime(2026, 1, 1, 12, 0, 1)
    t.finished_at = None
    return t


def _set_mock_user():
    app.dependency_overrides[get_current_user] = _mock_user


def _clear_mock_user():
    app.dependency_overrides.pop(get_current_user, None)


class TestListTasks:
    def setup_method(self):
        _set_mock_user()

    def teardown_method(self):
        _clear_mock_user()

    def test_returns_task_list(self):
        """GET /api/tasks returns tasks for authenticated user."""
        task = _make_task()
        with patch("app.db.sql_adapter.SQLAdapter.list_generation_tasks", return_value=[task]):
            r = client.get("/api/tasks")
        assert r.status_code == 200
        data = r.json()
        assert "tasks" in data
        assert isinstance(data["tasks"], list)

    def test_does_not_include_result_json(self):
        """GET /api/tasks: list response must not include result_json."""
        task = _make_task(status="completed")
        task.result_json = '{"Finding Title": "SQL Injection"}'
        with patch("app.db.sql_adapter.SQLAdapter.list_generation_tasks", return_value=[task]):
            r = client.get("/api/tasks")
        assert r.status_code == 200
        for t in r.json()["tasks"]:
            assert "result_json" not in t


class TestGetTask:
    def setup_method(self):
        _set_mock_user()

    def teardown_method(self):
        _clear_mock_user()

    def test_returns_full_task_with_result(self):
        """GET /api/tasks/{id} returns result_json for the owning user."""
        task = _make_task(status="completed")
        task.result_json = '{"Finding Title": "XSS"}'
        with patch("app.db.sql_adapter.SQLAdapter.get_generation_task", return_value=task):
            r = client.get("/api/tasks/task-1")
        assert r.status_code == 200
        assert "result_json" in r.json()

    def test_404_on_missing_task(self):
        """GET /api/tasks/{id}: 404 if task does not exist."""
        with patch("app.db.sql_adapter.SQLAdapter.get_generation_task", return_value=None):
            r = client.get("/api/tasks/does-not-exist")
        assert r.status_code == 404

    def test_stale_detection(self):
        """GET /api/tasks/{id}: tasks running > 10 min are returned as 'stale'."""
        from datetime import datetime, timedelta
        task = _make_task(status="running")
        task.started_at = datetime.utcnow() - timedelta(minutes=15)
        with patch("app.db.sql_adapter.SQLAdapter.get_generation_task", return_value=task):
            r = client.get("/api/tasks/task-1")
        assert r.status_code == 200
        assert r.json()["status"] == "stale"


class TestCancelTask:
    def setup_method(self):
        _set_mock_user()

    def teardown_method(self):
        _clear_mock_user()

    def test_cancel_running_task(self):
        """DELETE /api/tasks/{id}: marks running task as cancelled."""
        task = _make_task(status="running")
        with patch("app.db.sql_adapter.SQLAdapter.get_generation_task", return_value=task), \
             patch("app.db.sql_adapter.SQLAdapter.update_generation_task", return_value=task), \
             patch("app.celery_app.app.control.revoke"):
            r = client.delete("/api/tasks/task-1")
        assert r.status_code == 204

    def test_cancel_completed_task_is_noop(self):
        """DELETE /api/tasks/{id}: cancelling already-completed task is a no-op (204)."""
        task = _make_task(status="completed")
        with patch("app.db.sql_adapter.SQLAdapter.get_generation_task", return_value=task), \
             patch("app.db.sql_adapter.SQLAdapter.update_generation_task") as mock_update:
            r = client.delete("/api/tasks/task-1")
        assert r.status_code == 204
        mock_update.assert_not_called()

    def test_cancel_404_on_missing(self):
        """DELETE /api/tasks/{id}: 404 if task not found."""
        with patch("app.db.sql_adapter.SQLAdapter.get_generation_task", return_value=None):
            r = client.delete("/api/tasks/missing")
        assert r.status_code == 404


class TestEnqueueStructured:
    def test_invalid_provider_rejected(self):
        """POST /api/generate/structured/async: invalid provider returns 422."""
        r = client.post(
            "/api/generate/structured/async",
            json={
                "report_id": "00000000-0000-0000-0000-000000000001",
                "notes": "SQL injection in login form",
                "template": "## Finding\n{{description}}",
                "llm_provider": "not_a_real_provider",
            },
        )
        assert r.status_code == 422

    def test_empty_notes_rejected(self):
        """POST /api/generate/structured/async: empty notes returns 422."""
        r = client.post(
            "/api/generate/structured/async",
            json={
                "report_id": "00000000-0000-0000-0000-000000000001",
                "notes": "",
                "template": "## Finding",
                "llm_provider": "openai",
            },
        )
        assert r.status_code == 422


class TestEnqueueVision:
    def test_invalid_base64_rejected(self):
        """POST /api/vision/extract-text/async: invalid base64 returns 422."""
        r = client.post(
            "/api/vision/extract-text/async",
            json={
                "image_base64": "not valid base64!@#$",
                "image_mime_type": "image/png",
            },
        )
        assert r.status_code == 422

    def test_empty_image_rejected(self):
        """POST /api/vision/extract-text/async: empty image returns 422."""
        r = client.post(
            "/api/vision/extract-text/async",
            json={
                "image_base64": "",
                "image_mime_type": "image/png",
            },
        )
        assert r.status_code == 422


class TestEnqueueValidation:
    def setup_method(self):
        _set_mock_user()

    def teardown_method(self):
        _clear_mock_user()
        app.dependency_overrides.pop(get_adapter, None)

    def test_enqueues_single_validation(self):
        """POST /api/generate/validation-guidance/async: creates task and returns task_id."""
        mock_adapter = MagicMock()
        mock_report = MagicMock(id="report-1", organization_id="org-1")
        mock_adapter.get_report.return_value = mock_report
        _report_id = "00000000-0000-0000-0000-000000000001"
        mock_finding = MagicMock(id="finding-1", report_id=_report_id, title="SQL Injection")
        mock_adapter.get_finding.return_value = mock_finding
        mock_adapter.get_settings.return_value = MagicMock(org_name="Test")
        mock_gt = MagicMock(id="task-99")
        mock_adapter.create_generation_task.return_value = mock_gt

        mock_user = _mock_user()
        mock_user.ai_key_provider = "openai"
        mock_user.ai_key_encrypted = "encrypted-key"
        mock_user.organization_id = "org-1"
        app.dependency_overrides[get_current_user] = lambda: mock_user
        app.dependency_overrides[get_adapter] = lambda: mock_adapter

        with patch("app.tasks.llm_generation.validate_guidance_task.delay") as mock_delay, \
             patch("app.api.generate._require_llm_config"), \
             patch("app.api.generate._resolve_user_org_id", return_value="org-1"), \
             patch("app.services.field_extraction.user_api_key_for_provider", return_value="sk-test"):
            r = client.post(
                "/api/generate/validation-guidance/async",
                json={
                    "report_id": _report_id,
                    "finding_id": "00000000-0000-0000-0000-000000000002",
                },
            )

        assert r.status_code == 200
        data = r.json()
        assert "task_id" in data
        assert data["status"] == "pending"

    def test_404_on_missing_report(self):
        """POST /api/generate/validation-guidance/async: 404 when report not found."""
        mock_adapter = MagicMock()
        mock_adapter.get_report.return_value = None
        app.dependency_overrides[get_adapter] = lambda: mock_adapter

        r = client.post(
            "/api/generate/validation-guidance/async",
            json={
                "report_id": "00000000-0000-0000-0000-000000000001",
                "finding_id": "00000000-0000-0000-0000-000000000002",
            },
        )
        assert r.status_code == 404

    def test_404_on_missing_finding(self):
        """POST /api/generate/validation-guidance/async: 404 when finding not found."""
        mock_adapter = MagicMock()
        mock_report = MagicMock(id="report-1", organization_id="org-1")
        mock_adapter.get_report.return_value = mock_report
        mock_adapter.get_finding.return_value = None
        app.dependency_overrides[get_adapter] = lambda: mock_adapter

        with patch("app.api.tasks.can_view_report", return_value=True):
            r = client.post(
                "/api/generate/validation-guidance/async",
                json={
                    "report_id": "00000000-0000-0000-0000-000000000001",
                    "finding_id": "00000000-0000-0000-0000-000000000002",
                },
            )
        assert r.status_code == 404


class TestEnqueueValidationAdversarial:
    """Adversarial tests for validation guidance endpoints."""

    def setup_method(self):
        _set_mock_user()

    def teardown_method(self):
        _clear_mock_user()
        app.dependency_overrides.pop(get_adapter, None)

    def test_cross_report_finding_rejected(self):
        """POST /api/generate/validation-guidance/async: finding from different report returns 400."""
        mock_adapter = MagicMock()
        mock_adapter.get_report.return_value = MagicMock(id="report-1", organization_id="org-1")
        # Finding belongs to a different report
        mock_adapter.get_finding.return_value = MagicMock(id="finding-1", report_id="report-OTHER")
        app.dependency_overrides[get_adapter] = lambda: mock_adapter

        with patch("app.api.tasks.can_view_report", return_value=True):
            r = client.post(
                "/api/generate/validation-guidance/async",
                json={
                    "report_id": "00000000-0000-0000-0000-000000000001",
                    "finding_id": "00000000-0000-0000-0000-000000000002",
                },
            )
        assert r.status_code == 400
        assert "does not belong" in r.json()["detail"]

    def test_rbac_denied_returns_403(self):
        """POST /api/generate/validation-guidance/async: user without report access gets 403."""
        mock_adapter = MagicMock()
        mock_adapter.get_report.return_value = MagicMock(id="report-1", organization_id="org-1")
        app.dependency_overrides[get_adapter] = lambda: mock_adapter

        with patch("app.api.tasks.can_view_report", return_value=False):
            r = client.post(
                "/api/generate/validation-guidance/async",
                json={
                    "report_id": "00000000-0000-0000-0000-000000000001",
                    "finding_id": "00000000-0000-0000-0000-000000000002",
                },
            )
        assert r.status_code == 403

    def test_bulk_cross_report_findings_skipped(self):
        """POST /api/generate/validation-guidance/bulk/async: findings from other reports are silently skipped."""
        mock_adapter = MagicMock()
        _report_id = "00000000-0000-0000-0000-000000000001"
        mock_adapter.get_report.return_value = MagicMock(id=_report_id, organization_id="org-1")
        # All findings belong to a different report
        mock_adapter.get_finding.return_value = MagicMock(id="finding-1", report_id="report-OTHER")
        mock_adapter.get_settings.return_value = MagicMock(org_name="Test")
        app.dependency_overrides[get_adapter] = lambda: mock_adapter

        mock_user = _mock_user()
        mock_user.organization_id = "org-1"
        app.dependency_overrides[get_current_user] = lambda: mock_user

        with patch("app.api.generate._require_llm_config"), \
             patch("app.api.generate._resolve_user_org_id", return_value="org-1"), \
             patch("app.services.field_extraction.user_api_key_for_provider", return_value="sk-test"):
            r = client.post(
                "/api/generate/validation-guidance/bulk/async",
                json={
                    "report_id": _report_id,
                    "finding_ids": [
                        "00000000-0000-0000-0000-000000000002",
                        "00000000-0000-0000-0000-000000000003",
                    ],
                },
            )
        assert r.status_code == 200
        # No tasks should be created since all findings belong to wrong report
        assert r.json()["task_ids"] == []

    def test_invalid_uuid_finding_id_rejected(self):
        """POST /api/generate/validation-guidance/async: non-UUID finding_id returns 422."""
        r = client.post(
            "/api/generate/validation-guidance/async",
            json={
                "report_id": "00000000-0000-0000-0000-000000000001",
                "finding_id": "'; DROP TABLE finding; --",
            },
        )
        assert r.status_code == 422

    def test_title_hint_sanitized(self):
        """POST /api/generate/validation-guidance/async: title_hint with XSS is stored but UUID-validated inputs prevent injection."""
        # title_hint is free-text but only stored in task.title (rendered as text in TaskBar, not innerHTML)
        # This test confirms the endpoint accepts it without error — XSS is prevented by Vue's {{ }} escaping
        mock_adapter = MagicMock()
        _report_id = "00000000-0000-0000-0000-000000000001"
        mock_adapter.get_report.return_value = MagicMock(id=_report_id, organization_id="org-1")
        mock_adapter.get_finding.return_value = MagicMock(id="finding-1", report_id=_report_id, title="Test")
        mock_adapter.get_settings.return_value = MagicMock(org_name="Test")
        mock_gt = MagicMock(id="task-99")
        mock_adapter.create_generation_task.return_value = mock_gt

        mock_user = _mock_user()
        mock_user.organization_id = "org-1"
        app.dependency_overrides[get_current_user] = lambda: mock_user
        app.dependency_overrides[get_adapter] = lambda: mock_adapter

        with patch("app.tasks.llm_generation.validate_guidance_task.delay"), \
             patch("app.api.generate._require_llm_config"), \
             patch("app.api.generate._resolve_user_org_id", return_value="org-1"), \
             patch("app.services.field_extraction.user_api_key_for_provider", return_value="sk-test"):
            r = client.post(
                "/api/generate/validation-guidance/async",
                json={
                    "report_id": _report_id,
                    "finding_id": "00000000-0000-0000-0000-000000000002",
                    "title_hint": '<script>alert("xss")</script>',
                },
            )
        assert r.status_code == 200


class TestEnqueueBulkValidation:
    def test_empty_finding_ids_rejected(self):
        """POST /api/generate/validation-guidance/bulk/async: empty finding_ids returns 422."""
        r = client.post(
            "/api/generate/validation-guidance/bulk/async",
            json={
                "report_id": "00000000-0000-0000-0000-000000000001",
                "finding_ids": [],
            },
        )
        assert r.status_code == 422

    def test_too_many_finding_ids_rejected(self):
        """POST /api/generate/validation-guidance/bulk/async: >50 finding_ids returns 422."""
        r = client.post(
            "/api/generate/validation-guidance/bulk/async",
            json={
                "report_id": "00000000-0000-0000-0000-000000000001",
                "finding_ids": [f"00000000-0000-0000-0000-{str(i).zfill(12)}" for i in range(51)],
            },
        )
        assert r.status_code == 422
