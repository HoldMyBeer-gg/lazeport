"""
Unit tests for background LLM generation Celery tasks.
Tests status transitions, progress logging, and error handling.

Note: @app.task(bind=True) tasks expose .run() as a bound method — self is already
the Celery task instance. Call via task.run(...) without a self argument.
Use patch.object(task, 'request') to control self.request.id when needed.
"""
import json
from datetime import datetime
from unittest.mock import MagicMock, patch


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_task(status="pending", task_type="generate_finding"):
    task = MagicMock()
    task.id = "test-task-id"
    task.status = status
    task.task_type = task_type
    task.progress_log = "[]"
    task.finding_id = None
    task.report_id = "report-1"
    task.started_at = None
    task.finished_at = None
    return task


def _make_adapter(task=None):
    adapter = MagicMock()
    t = task or _make_task()
    adapter.claim_generation_task.return_value = t
    adapter.get_generation_task.return_value = t
    adapter.update_generation_task.return_value = t
    adapter.get_settings.return_value = MagicMock(org_name="TestOrg", voice_style="")
    adapter.get_report.return_value = MagicMock(id="report-1", organization_id="org-1")
    return adapter


# ── generate_finding_task ─────────────────────────────────────────────────────

class TestGenerateFindingTask:
    @patch("app.tasks.llm_generation.get_adapter")
    @patch("app.services.structurer.structure_notes_with_context")
    @patch("app.services.severity_rubric.enforce_severity_label", side_effect=lambda s, *a, **kw: s)
    @patch("app.services.field_extraction.derive_table_values", return_value={})
    @patch("app.services.field_extraction.canonicalize_severity_value", side_effect=lambda v: v)
    def test_success_auto_saves_finding(self, mock_canon, mock_derive, mock_enforce, mock_snwc, mock_get_adapter):
        """generate_finding_task: completes and auto-saves finding to DB."""
        from app.tasks.llm_generation import generate_finding_task

        adapter = _make_adapter()
        mock_get_adapter.return_value = adapter
        mock_finding = MagicMock(id="finding-123")
        adapter.create_finding.return_value = mock_finding
        mock_snwc.return_value = ({"Finding Title": "SQL Injection", "Severity": "High"}, "{}")

        result = generate_finding_task.run(
            generation_task_id="test-task-id",
            notes="SQL injection in login",
            template_markdown="",
            report_id="report-1",
            organization_id="org-1",
            user_id="user-1",
            llm_provider="openai",
            llm_api_key="sk-test",
        )

        assert result["ok"] is True
        assert result["finding_id"] == "finding-123"
        adapter.create_finding.assert_called_once()
        completed = [
            c for c in adapter.update_generation_task.call_args_list
            if c.kwargs.get("status") == "completed"
        ]
        assert len(completed) == 1

    @patch("app.tasks.llm_generation.get_adapter")
    def test_aborts_if_already_running(self, mock_get_adapter):
        """generate_finding_task: returns early if claim fails (task already running)."""
        from app.tasks.llm_generation import generate_finding_task

        adapter = _make_adapter()
        adapter.claim_generation_task.return_value = None  # Already claimed
        mock_get_adapter.return_value = adapter

        result = generate_finding_task.run(
            generation_task_id="test-task-id",
            notes="notes",
            template_markdown="",
            report_id="report-1",
            organization_id="org-1",
            user_id="user-1",
        )

        assert result["ok"] is False
        assert "claimed" in result["reason"]
        adapter.create_finding.assert_not_called()

    @patch("app.tasks.llm_generation.get_adapter")
    @patch("app.services.structurer.structure_notes_with_context")
    def test_marks_failed_on_exception(self, mock_snwc, mock_get_adapter):
        """generate_finding_task: marks task as failed when LLM call raises."""
        from app.tasks.llm_generation import generate_finding_task

        adapter = _make_adapter()
        mock_get_adapter.return_value = adapter
        mock_snwc.side_effect = RuntimeError("LLM connection refused")

        result = generate_finding_task.run(
            generation_task_id="test-task-id",
            notes="notes",
            template_markdown="",
            report_id="report-1",
            organization_id="org-1",
            user_id="user-1",
            llm_provider="openai",
        )

        assert result["ok"] is False
        failed = [
            c for c in adapter.update_generation_task.call_args_list
            if c.kwargs.get("status") == "failed"
        ]
        assert len(failed) >= 1

    @patch("app.tasks.llm_generation.get_adapter")
    @patch("app.services.structurer.structure_notes_with_context")
    @patch("app.services.severity_rubric.enforce_severity_label", side_effect=lambda s, *a, **kw: s)
    @patch("app.services.field_extraction.derive_table_values", return_value={})
    @patch("app.services.field_extraction.canonicalize_severity_value", side_effect=lambda v: v)
    def test_progress_log_appended(self, mock_canon, mock_derive, mock_enforce, mock_snwc, mock_get_adapter):
        """generate_finding_task: update_generation_task is called for each step."""
        from app.tasks.llm_generation import generate_finding_task

        adapter = _make_adapter()
        mock_get_adapter.return_value = adapter
        adapter.create_finding.return_value = MagicMock(id="f-1")
        mock_snwc.return_value = ({"Finding Title": "XSS"}, "{}")

        generate_finding_task.run(
            generation_task_id="test-task-id",
            notes="xss",
            template_markdown="",
            report_id="report-1",
            organization_id="org-1",
            user_id="user-1",
        )

        # At least 4 update calls: one per step (0-index advance) plus final completed
        assert adapter.update_generation_task.call_count >= 4


# ── regenerate_finding_task ───────────────────────────────────────────────────

class TestRegenerateFindingTask:
    @patch("app.tasks.llm_generation.get_adapter")
    @patch("app.services.structurer.structure_notes_with_context")
    @patch("app.services.severity_rubric.enforce_severity_label", side_effect=lambda s, *a, **kw: s)
    @patch("app.services.field_extraction.derive_table_values", return_value={})
    @patch("app.services.field_extraction.canonicalize_severity_value", side_effect=lambda v: v)
    def test_does_not_auto_save(self, mock_canon, mock_derive, mock_enforce, mock_snwc, mock_get_adapter):
        """regenerate_finding_task: result stored only — update_finding NOT called by worker."""
        from app.tasks.llm_generation import regenerate_finding_task

        adapter = _make_adapter(_make_task(task_type="regenerate_finding"))
        mock_get_adapter.return_value = adapter
        adapter.get_finding.return_value = MagicMock(id="finding-original", content_json='{}')
        mock_snwc.return_value = ({"Finding Title": "New Title"}, "{}")

        result = regenerate_finding_task.run(
            generation_task_id="test-task-id",
            finding_id="finding-original",
            notes="notes",
            template_markdown="",
            report_id="report-1",
            organization_id="org-1",
            user_id="user-1",
        )

        assert result["ok"] is True
        # Worker must NOT call update_finding — user must approve first
        adapter.update_finding.assert_not_called()
        # result_json must be stored in the task
        completed = [
            c for c in adapter.update_generation_task.call_args_list
            if c.kwargs.get("status") == "completed"
        ]
        assert len(completed) == 1
        assert "result_json" in completed[0].kwargs

    @patch("app.tasks.llm_generation.get_adapter")
    def test_fails_if_finding_not_found(self, mock_get_adapter):
        """regenerate_finding_task: marks failed if original finding missing."""
        from app.tasks.llm_generation import regenerate_finding_task

        adapter = _make_adapter(_make_task(task_type="regenerate_finding"))
        mock_get_adapter.return_value = adapter
        adapter.get_finding.return_value = None

        result = regenerate_finding_task.run(
            generation_task_id="test-task-id",
            finding_id="missing-finding",
            notes="notes",
            template_markdown="",
            report_id="report-1",
            organization_id="org-1",
            user_id="user-1",
        )

        assert result["ok"] is False
        failed = [c for c in adapter.update_generation_task.call_args_list if c.kwargs.get("status") == "failed"]
        assert len(failed) == 1


# ── generate_summaries_task ───────────────────────────────────────────────────

class TestGenerateSummariesTask:
    @patch("app.tasks.llm_generation.get_adapter")
    @patch("app.services.llm.chat_completion")
    def test_stores_result_only(self, mock_chat, mock_get_adapter):
        """generate_summaries_task: result stored only — report summaries NOT auto-updated."""
        from app.tasks.llm_generation import generate_summaries_task

        adapter = _make_adapter(_make_task(task_type="generate_summaries"))
        mock_get_adapter.return_value = adapter
        adapter.list_findings.return_value = [
            MagicMock(
                id="f1",
                title="SQL Injection",
                content_json='{"Severity": "High", "Vulnerability Summary": "Test"}'
            )
        ]
        mock_chat.return_value = "Summary text."

        result = generate_summaries_task.run(
            generation_task_id="test-task-id",
            report_id="report-1",
            user_id="user-1",
            llm_provider="openai",
            llm_api_key="sk-test",
        )

        assert result["ok"] is True
        # report summaries must NOT be saved by the worker
        adapter.update_report_summaries.assert_not_called()
        # result_json must be stored
        completed = [
            c for c in adapter.update_generation_task.call_args_list
            if c.kwargs.get("status") == "completed"
        ]
        assert len(completed) == 1
        stored = json.loads(completed[0].kwargs["result_json"])
        assert "summary_executive" in stored
        assert "summary_technical" in stored
        assert "summary_recommendations" in stored

    @patch("app.tasks.llm_generation.get_adapter")
    def test_fails_if_no_findings(self, mock_get_adapter):
        """generate_summaries_task: marks failed when report has no findings."""
        from app.tasks.llm_generation import generate_summaries_task

        adapter = _make_adapter(_make_task(task_type="generate_summaries"))
        mock_get_adapter.return_value = adapter
        adapter.list_findings.return_value = []

        result = generate_summaries_task.run(
            generation_task_id="test-task-id",
            report_id="report-1",
            user_id="user-1",
        )

        assert result["ok"] is False
        failed = [c for c in adapter.update_generation_task.call_args_list if c.kwargs.get("status") == "failed"]
        assert len(failed) == 1


# ── vision_extraction_task ────────────────────────────────────────────────────

_TINY_PNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="


# ── validate_guidance_task ─────────────────────────────────────────────────────

class TestValidateGuidanceTask:
    @patch("app.tasks.llm_generation.get_adapter")
    @patch("app.services.llm.chat_completion")
    def test_success_saves_guidance(self, mock_chat, mock_get_adapter):
        """validate_guidance_task: completes and auto-saves guidance to finding."""
        from app.tasks.llm_generation import validate_guidance_task

        adapter = _make_adapter(_make_task(task_type="validate_guidance"))
        mock_get_adapter.return_value = adapter
        mock_finding = MagicMock(
            id="finding-1",
            title="SQL Injection",
            content_json='{"Severity": "High", "Vulnerability Summary": "Test"}',
            validation_guidance=None,
            evidence_payload=None,
        )
        adapter.get_finding.return_value = mock_finding
        mock_chat.return_value = "## Validation Steps\n- Test the endpoint"

        result = validate_guidance_task.run(
            generation_task_id="test-task-id",
            finding_id="finding-1",
            user_id="user-1",
            organization_id="org-1",
            report_id="report-1",
            llm_provider="openai",
            llm_api_key="sk-test",
        )

        assert result["ok"] is True
        assert result["finding_id"] == "finding-1"
        adapter.update_finding.assert_called_once()
        call_kwargs = adapter.update_finding.call_args
        assert "validation_guidance" in call_kwargs.kwargs or "validation_guidance" in (call_kwargs[1] if len(call_kwargs) > 1 else {})
        completed = [
            c for c in adapter.update_generation_task.call_args_list
            if c.kwargs.get("status") == "completed"
        ]
        assert len(completed) == 1
        stored = json.loads(completed[0].kwargs["result_json"])
        assert "guidance" in stored
        assert stored["cached"] is False

    @patch("app.tasks.llm_generation.get_adapter")
    def test_cache_skip_when_guidance_exists(self, mock_get_adapter):
        """validate_guidance_task: completes immediately without LLM call when guidance exists and regenerate=False."""
        from app.tasks.llm_generation import validate_guidance_task

        adapter = _make_adapter(_make_task(task_type="validate_guidance"))
        mock_get_adapter.return_value = adapter
        mock_finding = MagicMock(
            id="finding-1",
            title="XSS",
            content_json='{}',
            validation_guidance="Existing guidance text",
            evidence_payload=None,
        )
        adapter.get_finding.return_value = mock_finding

        result = validate_guidance_task.run(
            generation_task_id="test-task-id",
            finding_id="finding-1",
            user_id="user-1",
            organization_id="org-1",
            report_id="report-1",
            regenerate=False,
        )

        assert result["ok"] is True
        assert result["cached"] is True
        # No LLM call should have been made
        adapter.update_finding.assert_not_called()
        completed = [
            c for c in adapter.update_generation_task.call_args_list
            if c.kwargs.get("status") == "completed"
        ]
        assert len(completed) == 1
        stored = json.loads(completed[0].kwargs["result_json"])
        assert stored["cached"] is True

    @patch("app.tasks.llm_generation.get_adapter")
    @patch("app.services.llm.chat_completion")
    def test_regenerate_calls_llm_even_with_existing_guidance(self, mock_chat, mock_get_adapter):
        """validate_guidance_task: regenerate=True calls LLM even if guidance already exists."""
        from app.tasks.llm_generation import validate_guidance_task

        adapter = _make_adapter(_make_task(task_type="validate_guidance"))
        mock_get_adapter.return_value = adapter
        mock_finding = MagicMock(
            id="finding-1",
            title="CSRF",
            content_json='{"Severity": "Medium"}',
            validation_guidance="Old guidance",
            evidence_payload=None,
        )
        adapter.get_finding.return_value = mock_finding
        mock_chat.return_value = "New guidance text"

        result = validate_guidance_task.run(
            generation_task_id="test-task-id",
            finding_id="finding-1",
            user_id="user-1",
            organization_id="org-1",
            report_id="report-1",
            regenerate=True,
            llm_provider="openai",
            llm_api_key="sk-test",
        )

        assert result["ok"] is True
        mock_chat.assert_called_once()
        adapter.update_finding.assert_called_once()

    @patch("app.tasks.llm_generation.get_adapter")
    @patch("app.services.llm.chat_completion")
    def test_marks_failed_on_llm_error(self, mock_chat, mock_get_adapter):
        """validate_guidance_task: marks failed when LLM call raises, finding unchanged."""
        from app.tasks.llm_generation import validate_guidance_task

        adapter = _make_adapter(_make_task(task_type="validate_guidance"))
        mock_get_adapter.return_value = adapter
        mock_finding = MagicMock(
            id="finding-1",
            title="RCE",
            content_json='{}',
            validation_guidance=None,
            evidence_payload=None,
        )
        adapter.get_finding.return_value = mock_finding
        mock_chat.side_effect = RuntimeError("LLM unavailable")

        result = validate_guidance_task.run(
            generation_task_id="test-task-id",
            finding_id="finding-1",
            user_id="user-1",
            organization_id="org-1",
            report_id="report-1",
        )

        assert result["ok"] is False
        adapter.update_finding.assert_not_called()
        failed = [c for c in adapter.update_generation_task.call_args_list if c.kwargs.get("status") == "failed"]
        assert len(failed) == 1

    @patch("app.tasks.llm_generation.get_adapter")
    def test_fails_if_finding_not_found(self, mock_get_adapter):
        """validate_guidance_task: marks failed if finding does not exist."""
        from app.tasks.llm_generation import validate_guidance_task

        adapter = _make_adapter(_make_task(task_type="validate_guidance"))
        mock_get_adapter.return_value = adapter
        adapter.get_finding.return_value = None

        result = validate_guidance_task.run(
            generation_task_id="test-task-id",
            finding_id="missing-finding",
            user_id="user-1",
            organization_id="org-1",
            report_id="report-1",
        )

        assert result["ok"] is False
        failed = [c for c in adapter.update_generation_task.call_args_list if c.kwargs.get("status") == "failed"]
        assert len(failed) == 1


# ── vision_extraction_task ────────────────────────────────────────────────────

class TestVisionExtractionTask:
    @patch("app.tasks.llm_generation.get_adapter")
    @patch("app.services.llm.vision_completion")
    def test_stores_extracted_text(self, mock_vc, mock_get_adapter):
        """vision_extraction_task: stores extracted text in result_json."""
        from app.tasks.llm_generation import vision_extraction_task

        adapter = _make_adapter(_make_task(task_type="vision_extraction"))
        mock_get_adapter.return_value = adapter
        mock_vc.return_value = "Extracted: http://example.com/login"

        result = vision_extraction_task.run(
            generation_task_id="test-task-id",
            image_base64=_TINY_PNG,
            image_mime_type="image/png",
            llm_provider="openai",
            llm_model="gpt-4o-mini",
            llm_api_key="sk-test",
        )

        assert result["ok"] is True
        completed = [
            c for c in adapter.update_generation_task.call_args_list
            if c.kwargs.get("status") == "completed"
        ]
        assert len(completed) == 1
        parsed = json.loads(completed[0].kwargs["result_json"])
        assert "text" in parsed
        assert "http://example.com/login" in parsed["text"]

    @patch("app.tasks.llm_generation.get_adapter")
    @patch("app.services.llm.vision_completion")
    def test_marks_failed_on_vision_error(self, mock_vc, mock_get_adapter):
        """vision_extraction_task: marks failed when vision_completion raises."""
        from app.tasks.llm_generation import vision_extraction_task

        adapter = _make_adapter(_make_task(task_type="vision_extraction"))
        mock_get_adapter.return_value = adapter
        mock_vc.side_effect = RuntimeError("Vision model error")

        result = vision_extraction_task.run(
            generation_task_id="test-task-id",
            image_base64=_TINY_PNG,
            image_mime_type="image/png",
        )

        assert result["ok"] is False
        failed = [c for c in adapter.update_generation_task.call_args_list if c.kwargs.get("status") == "failed"]
        assert len(failed) == 1
