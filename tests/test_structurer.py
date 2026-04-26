"""Tests for app.services.structurer."""
from unittest.mock import patch

import pytest

from app.services import structurer


class TestStructureNotesNoAi:
    def test_empty_notes_raises(self):
        with pytest.raises(ValueError, match="Notes cannot be empty"):
            structurer.structure_notes("", "# Summary", use_ai=False)

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError, match="Notes cannot be empty"):
            structurer.structure_notes("   \n  ", "# Summary", use_ai=False)

    def test_fallback_structure_single_section(self):
        result = structurer.structure_notes("my notes", "# Summary", use_ai=False)
        out = result[0]
        assert out["title"] == ""
        assert out["Summary"] == "my notes"

    def test_fallback_structure_multiple_sections(self):
        result = structurer.structure_notes(
            "raw findings",
            "# Summary\n# Details\n# Remediation",
            use_ai=False,
        )
        out = result[0]
        assert out["Summary"] == "raw findings"
        assert "Fill this section" in out["Details"]
        assert "Fill this section" in out["Remediation"]

    def test_fallback_title_in_structured(self):
        result = structurer.structure_notes("x", "# Summary", use_ai=False)
        out = result[0]
        assert "title" in out
        assert out["title"] == ""

    def test_fallback_returns_debug_source_fallback(self):
        result = structurer.structure_notes("x", "# Summary", use_ai=False)
        assert result[1].get("source") == "fallback"

    def test_normalize_title_from_first_section_when_missing(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        import importlib
        import app.config
        import app.services.llm
        importlib.reload(app.config)
        importlib.reload(app.services.llm)
        with patch("app.services.llm.is_llm_available", return_value=True), \
             patch("app.services.llm.chat_completion") as m:
            m.return_value = '{"Summary": "s", "Details": "d"}'  # no title key
            result = structurer.structure_notes("n", "# Summary\n# Details", use_ai=True)
            out = result[0]
        assert out["title"] == ""

    def test_apply_severity_override_updates_fields(self):
        structured = {
            "Severity": "Low",
            "Justification": "Low because ...",
            "Rationale": "Low rationale",
        }
        structurer.apply_severity_override(structured, "High", reason="because exploitable")
        assert structured["Severity"] == "High"
        assert "High" in structured["Justification"]
        assert "High" in structured["Rationale"]

    def test_enforce_severity_downgrades_library_cve_without_evidence(self):
        structured = {
            "Severity": "Critical",
            "Justification": "Critical because CVE-2022-0001",
        }
        notes = "Library CVE-2022-0001 in a dependency; no evidence of use."
        structurer._enforce_severity(structured, notes)
        assert structured["Severity"].startswith("Medium")
        assert "Medium" in structured["Justification"]


class TestStructureNotesWithAi:
    def test_empty_notes_raises(self):
        with pytest.raises(ValueError, match="Notes cannot be empty"):
            structurer.structure_notes("", "# Summary", use_ai=True)

    def test_llm_not_configured_raises(self, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "openai")
        monkeypatch.setenv("OPENAI_API_KEY", "")  # empty so load_dotenv won't override (override=False)
        import importlib
        import app.config
        import app.services.llm
        importlib.reload(app.config)
        importlib.reload(app.services.llm)
        with pytest.raises(ValueError, match="LLM is not configured"):
            structurer.structure_notes("some notes", "# Summary", use_ai=True)

    def test_llm_returns_json_used(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.setenv("LLM_PROVIDER", "openai")
        import importlib
        import app.config
        import app.services.llm
        importlib.reload(app.config)
        importlib.reload(app.services.llm)

        with patch("app.services.llm.is_llm_available", return_value=True), \
             patch("app.services.llm.chat_completion") as m:
            m.return_value = '{"title": "SQLi in Login", "Summary": "A summary."}'
            result = structurer.structure_notes("notes", "# Summary", use_ai=True)
            out = result[0]
            assert out["title"] == "SQLi in Login"
            assert out["Summary"] == "A summary."

    def test_ai_returns_debug_source_ai(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        import importlib
        import app.config
        import app.services.llm
        importlib.reload(app.config)
        importlib.reload(app.services.llm)
        with patch("app.services.llm.is_llm_available", return_value=True), \
             patch("app.services.llm.chat_completion") as m:
            m.return_value = '{"title": "T", "Summary": "S"}'
            result = structurer.structure_notes("notes", "# Summary", use_ai=True)
            assert result[1].get("source") == "ai"
            assert "provider" in result[1]

    def test_llm_returns_json_with_code_block_stripped(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        import importlib
        import app.config
        importlib.reload(app.config)

        with patch("app.services.llm.is_llm_available", return_value=True), \
             patch("app.services.llm.chat_completion") as m:
            m.return_value = '```json\n{"title": "X", "Summary": "Y"}\n```'
            result = structurer.structure_notes("notes", "# Summary", use_ai=True)
            out = result[0]
            assert out["title"] == "X"
            assert out["Summary"] == "Y"

    def test_llm_json_decode_error_fallback(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        import importlib
        import app.config
        importlib.reload(app.config)

        with patch("app.services.llm.is_llm_available", return_value=True), \
             patch("app.services.llm.chat_completion") as m:
            m.return_value = "not valid json at all"
            result = structurer.structure_notes("notes", "# Summary\n# Details", use_ai=True)
            out = result[0]
            assert "title" in out
            assert "Summary" in out
            assert "Details" in out

    def test_ai_exception_wrapped_in_value_error(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        import importlib
        import app.config
        importlib.reload(app.config)

        with patch("app.services.llm.chat_completion") as m:
            m.side_effect = RuntimeError("API down")
            with pytest.raises(ValueError, match="AI structuring failed"):
                structurer.structure_notes("notes", "# Summary", use_ai=True)

    def test_extra_instructions_passed_to_llm(self, monkeypatch):
        """extra_instructions is passed through to _call_llm (and thus to system message)."""
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        import importlib
        import app.config
        import app.services.llm
        importlib.reload(app.config)
        importlib.reload(app.services.llm)

        with patch("app.services.structurer._call_llm") as mock_call:
            mock_call.return_value = {"title": "T", "Summary": "S"}
            structurer.structure_notes(
                "notes",
                "# Summary",
                use_ai=True,
                self_check=False,
                extra_instructions="Use British English.",
            )
            mock_call.assert_called_once()
            call_kwargs = mock_call.call_args[1]
            assert call_kwargs.get("extra_instructions") == "Use British English."

    def test_deepseek_provider_passed_to_llm_not_ollama(self):
        """Regression: llm_provider=deepseek must reach chat_completion as provider_override=deepseek, never ollama."""
        with patch("app.services.llm.is_llm_available", return_value=True), \
             patch("app.services.llm.chat_completion") as mock_chat:
            mock_chat.return_value = '{"title": "T", "Summary": "S", "Details": "D"}'
            structurer.structure_notes(
                "some notes",
                "# Summary\n# Details",
                use_ai=True,
                llm_provider="deepseek",
                llm_model="deepseek-chat",
                llm_api_key_override="sk-deepseek-test",
            )
        mock_chat.assert_called()
        for call in mock_chat.call_args_list:
            kwargs = call[1] if call[1] else {}
            provider = kwargs.get("provider_override")
            assert provider == "deepseek", (
                "structurer must pass llm_provider to LLM as provider_override; got %s" % provider
            )
            assert provider != "ollama"

    def test_self_check_skipped_when_local_validation_passes(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        import importlib
        import app.config
        import app.services.llm
        importlib.reload(app.config)
        importlib.reload(app.services.llm)

        with patch("app.services.structurer._call_llm") as mock_call, patch("app.services.structurer._self_check_llm") as mock_self_check:
            mock_call.return_value = {"title": "T", "Summary": "S"}
            out, debug = structurer.structure_notes(
                "notes",
                "# Summary",
                use_ai=True,
                self_check=True,
            )
            assert out["Summary"] == "S"
            assert debug.get("source") == "ai"
            mock_self_check.assert_not_called()

    def test_self_check_runs_once_when_local_validation_fails(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        import importlib
        import app.config
        import app.services.llm
        importlib.reload(app.config)
        importlib.reload(app.services.llm)

        with patch("app.services.structurer._call_llm") as mock_call, patch("app.services.structurer._local_validate") as mock_local_validate, patch("app.services.structurer._self_check_llm") as mock_self_check:
            mock_call.return_value = {"title": "T", "Summary": "S"}
            mock_local_validate.return_value = ["Missing or empty section: Summary"]
            mock_self_check.return_value = {"verdict": "ok", "issues": ["Looks good"], "revised": None}

            _out, debug = structurer.structure_notes(
                "notes",
                "# Summary",
                use_ai=True,
                self_check=True,
                self_check_rounds=3,  # should still run exactly once
            )
            mock_self_check.assert_called_once()
            assert debug.get("verification_log") == ["Pass 1: Looks good"]

    def test_self_check_runs_when_notes_identifiers_missing_from_output(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        import importlib
        import app.config
        import app.services.llm
        importlib.reload(app.config)
        importlib.reload(app.services.llm)

        with patch("app.services.structurer._call_llm") as mock_call, patch("app.services.structurer._self_check_llm") as mock_self_check:
            mock_call.return_value = {"title": "T", "Summary": "Plain summary without references"}
            mock_self_check.return_value = {"verdict": "ok", "issues": ["No issues found"], "revised": None}
            _out, debug = structurer.structure_notes(
                "Exploit references CVE-2024-12345 at https://example.test/poc",
                "# Summary",
                use_ai=True,
                self_check=True,
            )
            mock_self_check.assert_called_once()
            assert debug.get("verification_log") == ["Pass 1: No issues found"]

    def test_severity_canonicalized_even_when_language_localized(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        import importlib
        import app.config
        import app.services.llm
        importlib.reload(app.config)
        importlib.reload(app.services.llm)

        with patch("app.services.structurer._call_llm") as mock_call:
            mock_call.return_value = {"title": "T", "Summary": "S", "Severity": "Hoch"}
            out, _debug = structurer.structure_notes(
                "notes",
                "# Summary\n# Severity",
                use_ai=True,
                self_check=False,
                preferred_language="de",
            )
            assert out["Severity"] == "High"


def test_structure_notes_default_self_check_rounds_is_1():
    import inspect
    sig = inspect.signature(structurer.structure_notes)
    assert sig.parameters["self_check_rounds"].default == 1


class TestRequiredSectionValidation:
    """Verify that missing required sections trigger retry (commit 7095ab7)."""

    def _setup_env(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "test-key")
        monkeypatch.setenv("LLM_PROVIDER", "openai")
        import importlib, app.config, app.services.llm
        importlib.reload(app.config)
        importlib.reload(app.services.llm)

    def test_missing_section_triggers_retry_and_succeeds(self, monkeypatch):
        """First call missing Severity should trigger one retry; retry returns full output."""
        self._setup_env(monkeypatch)
        first  = '{"title": "T", "Summary": "S"}'          # missing Severity
        second = '{"title": "T", "Summary": "S", "Severity": "High"}'  # complete

        with patch("app.services.llm.chat_completion", side_effect=[first, second]) as mock_llm, \
             patch("app.services.llm.is_llm_available", return_value=True):
            out, debug = structurer.structure_notes(
                "notes", "# Summary\n# Severity", use_ai=True, self_check=False
            )

        assert mock_llm.call_count == 2, "Expected exactly one retry"
        assert out["Severity"] == "High"

    def test_missing_section_retry_also_fails_raises_value_error(self, monkeypatch):
        """Both initial and retry output missing Severity should raise ValueError."""
        self._setup_env(monkeypatch)
        incomplete = '{"title": "T", "Summary": "S"}'  # missing Severity — both calls

        with patch("app.services.llm.chat_completion", return_value=incomplete), \
             patch("app.services.llm.is_llm_available", return_value=True):
            with pytest.raises(ValueError, match="LLM output validation failed after retry"):
                structurer.structure_notes(
                    "notes", "# Summary\n# Severity", use_ai=True, self_check=False
                )

    def test_complete_output_no_retry(self, monkeypatch):
        """When all required sections are present, no retry should happen."""
        self._setup_env(monkeypatch)
        complete = '{"title": "T", "Summary": "S", "Severity": "High"}'

        with patch("app.services.llm.chat_completion", return_value=complete) as mock_llm, \
             patch("app.services.llm.is_llm_available", return_value=True):
            out, _ = structurer.structure_notes(
                "notes", "# Summary\n# Severity", use_ai=True, self_check=False
            )

        assert mock_llm.call_count == 1, "No retry expected when output is complete"
        assert out["Severity"] == "High"
