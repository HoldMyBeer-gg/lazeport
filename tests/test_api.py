"""Tests for API routes."""
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.db import get_adapter
from app.main import app

client = TestClient(app)


class TestHealth:
    def test_health_returns_ok(self):
        """Public health endpoint should only return basic status."""
        r = client.get("/api/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        # Public endpoint should NOT expose sensitive info
        assert "llm_configured" not in data
        assert "providers" not in data

    def test_health_detailed_requires_admin(self):
        r = client.get("/api/health/detailed")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert "llm_note" in data


class TestSpec:
    def test_api_spec_available(self):
        r = client.get("/api/spec")
        assert r.status_code == 200
        data = r.json()
        assert data.get("openapi")
        assert data.get("info", {}).get("title")


class TestDocsAuth:
    """DocsAuthMiddleware: /docs, /redoc, /openapi.json, /api/spec require session when auth enabled."""

    def test_openapi_json_200_when_auth_disabled(self):
        """With AUTH_DISABLED=1 (conftest), openapi.json is public."""
        r = client.get("/openapi.json")
        assert r.status_code == 200
        assert r.json().get("openapi")

    def test_openapi_json_401_when_auth_enabled_no_session(self):
        """When auth is enabled, unauthenticated request to openapi.json returns 401."""
        with patch("app.services.auth.is_auth_enabled", return_value=True):
            r = client.get("/openapi.json")
        assert r.status_code == 401
        assert r.json().get("detail") == "Authentication required"

    def test_api_spec_401_when_auth_enabled_no_session(self):
        """When auth is enabled, unauthenticated request to /api/spec returns 401."""
        with patch("app.services.auth.is_auth_enabled", return_value=True):
            r = client.get("/api/spec")
        assert r.status_code == 401
        assert r.json().get("detail") == "Authentication required"

    def test_docs_redirects_to_login_when_auth_enabled_no_session(self):
        """When auth is enabled, unauthenticated /docs redirects to /login."""
        with patch("app.services.auth.is_auth_enabled", return_value=True):
            r = client.get("/docs", follow_redirects=False)
        assert r.status_code == 302
        assert r.headers.get("location") == "/login"


class TestTemplates:
    def test_list_templates_returns_list(self):
        r = client.get("/api/templates")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_list_templates_from_custom_dir(self, monkeypatch, tmp_path):
        from app.api import templates as templates_api

        (tmp_path / "alpha.md").write_text("# Alpha", encoding="utf-8")
        (tmp_path / "beta.txt").write_text("Beta", encoding="utf-8")
        (tmp_path / "ignore.bin").write_text("x", encoding="utf-8")

        monkeypatch.setattr(templates_api, "TEMPLATES_DIR", tmp_path)
        r = client.get("/api/templates")
        assert r.status_code == 200
        assert r.json() == ["alpha", "beta"]

    def test_get_template_default(self):
        r = client.get("/api/templates/default")
        assert r.status_code == 200
        assert "html" in r.text.lower() or "finding" in r.text.lower() or "template" in r.text.lower()

    def test_get_template_invalid_name_rejected(self):
        # Backslash in name (encoded as %5C) becomes single segment "foo\bar", rejected as invalid
        r = client.get("/api/templates/foo%5Cbar")
        assert r.status_code == 400
        assert "Invalid template name" in (r.json() or {}).get("detail", "")

    def test_get_template_not_found(self):
        r = client.get("/api/templates/nonexistent_template_xyz")
        assert r.status_code == 404

    def test_list_master_templates_sorted(self):
        adapter = get_adapter()
        org_id = adapter.ensure_system_org()
        adapter.create_master_template("zeta", b"dummy", organization_id=org_id)
        adapter.create_master_template("alpha", b"dummy", organization_id=org_id)
        r = client.get("/api/master-templates")
        assert r.status_code == 200
        assert r.json() == ["alpha", "zeta"]


class TestGenerateStructured:
    def test_empty_notes_returns_400(self):
        r = client.post(
            "/api/generate/structured",
            json={"notes": "", "template": "# Summary", "use_ai": False},
        )
        assert r.status_code == 400

    def test_no_ai_returns_structured(self):
        r = client.post(
            "/api/generate/structured",
            json={
                "notes": "some burp notes",
                "template": "# Summary\n# Details",
                "use_ai": False,
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert "structured" in data
        assert "debug" in data
        assert data["debug"].get("source") == "fallback"
        assert "Summary" in data["structured"]
        assert "Details" in data["structured"]
        assert data["structured"]["Summary"] == "some burp notes"
        # Found Date is set when missing (paste + AI flow)
        assert "Found Date" in data["structured"]
        assert data["structured"]["Found Date"]  # non-empty, YYYY-MM-DD format

    def test_use_ai_without_llm_returns_400(self):
        with patch("app.services.llm.is_llm_available", return_value=False):
            r = client.post(
                "/api/generate/structured",
                json={
                    "notes": "notes",
                    "template": "# Summary",
                    "use_ai": True,
                },
            )
            assert r.status_code == 400

    def test_structured_identifier_links_and_overrides(self):
        r = client.post(
            "/api/generate/structured",
            json={
                "notes": "CVE-2021-1234 CWE-79 A1:2021 XSS",
                "template": "# Summary\n# Details",
                "use_ai": False,
                "severity_override": "high",
                "cvss_score": "6.1",
                "cvss_vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "affected_roles": "All Employees",
            },
        )
        assert r.status_code == 200
        data = r.json()
        table_values = data.get("table_values", {})
        assert table_values.get("Severity") == "high"
        assert table_values.get("Affected Roles") == "All Employees"
        assert "CVSS v3.1" in table_values
        links = data.get("identifier_links", {})
        assert "CVE-2021-1234" in links
        assert "CWE-79" in links

    def test_generate_structured_passes_user_llm_extra_instructions(self):
        """Generate endpoint passes current user's llm_extra_instructions (from DB) into structure_notes."""
        r = client.put("/api/admin/me/llm-instructions", json={"instructions": "Use formal tone."})
        assert r.status_code == 200

        with patch("app.api.generate.structure_notes") as mock_structure:
            mock_structure.return_value = (
                {"title": "T", "Summary": "S", "Details": "D"},
                {"source": "ai"},
            )
            r = client.post(
                "/api/generate/structured",
                json={
                    "notes": "some notes",
                    "template": "# Summary\n# Details",
                    "use_ai": True,
                    "llm_provider": "ollama",
                },
            )
        assert r.status_code == 200
        mock_structure.assert_called_once()
        call_kwargs = mock_structure.call_args[1]
        assert call_kwargs.get("extra_instructions") == "Use formal tone."

    def test_generate_structured_uses_request_llm_provider_and_base_url_not_env(self):
        """Regression: UI sends provider=openai → LLM layer must be called with openai, never Ollama."""
        client.put("/api/admin/profile", json={"openai_api_key": "sk-test", "ai_key_provider": "openai"})
        valid_json = '{"title": "T", "Summary": "S", "Details": "D"}'
        with patch("app.services.llm.chat_completion") as mock_chat:
            mock_chat.return_value = valid_json
            r = client.post(
                "/api/generate/structured",
                json={
                    "notes": "some notes",
                    "template": "# Summary\n# Details",
                    "use_ai": True,
                    "llm_provider": "openai",
                    "llm_base_url": "https://api.openai.com/v1",
                    "llm_model": "gpt-4o-mini",
                },
            )
        assert r.status_code == 200
        mock_chat.assert_called()
        for call in mock_chat.call_args_list:
            kwargs = call[1] if call[1] else {}
            assert kwargs.get("provider_override") == "openai", (
                "LLM must be called with provider_override=openai when request sends openai; got %s" % kwargs.get("provider_override")
            )
            assert kwargs.get("provider_override") != "ollama"

    def test_generate_structured_deepseek_request_reaches_llm_as_deepseek_not_ollama(self):
        """Regression: When client sends llm_provider=deepseek, chat_completion must receive deepseek, never ollama."""
        client.put("/api/admin/profile", json={"openai_api_key": "sk-test", "ai_key_provider": "deepseek"})
        valid_json = '{"title": "T", "Summary": "S", "Details": "D"}'
        with patch("app.services.llm.chat_completion") as mock_chat:
            mock_chat.return_value = valid_json
            r = client.post(
                "/api/generate/structured",
                json={
                    "notes": "some notes",
                    "template": "# Summary\n# Details",
                    "use_ai": True,
                    "llm_provider": "deepseek",
                    "llm_model": "deepseek-chat",
                },
            )
        assert r.status_code == 200
        mock_chat.assert_called()
        for call in mock_chat.call_args_list:
            kwargs = call[1] if call[1] else {}
            provider = kwargs.get("provider_override")
            assert provider == "deepseek", (
                "LLM must be called with provider_override=deepseek when request sends deepseek; got %s" % provider
            )
            assert provider != "ollama", "Must never use ollama when user requested deepseek"

    def test_generate_structured_returns_localized_severity_label_but_keeps_canonical_storage(self):
        with patch("app.api.generate.structure_notes") as mock_structure:
            mock_structure.return_value = (
                {"title": "T", "Summary": "S", "Severity": "High"},
                {"source": "ai"},
            )
            r = client.post(
                "/api/generate/structured",
                json={
                    "notes": "notes",
                    "template": "# Summary\n# Severity",
                    "use_ai": True,
                    "llm_provider": "ollama",
                    "locale": "de",
                },
            )
        assert r.status_code == 200
        data = r.json()
        assert data["structured"]["Severity"] == "High"
        assert data["display"]["severity_label"] == "Hoch"


class TestGenerateDocx:
    def test_empty_notes_returns_400(self):
        r = client.post(
            "/api/generate/docx",
            json={"notes": "", "template": "# Summary", "use_ai": False},
        )
        assert r.status_code == 400

    def test_no_ai_returns_docx(self):
        r = client.post(
            "/api/generate/docx",
            json={
                "notes": "findings here",
                "template": "# Summary\n# Remediation",
                "use_ai": False,
                "vulnerability_title": "Test Report",
            },
        )
        assert r.status_code == 200
        assert "application/vnd.openxmlformats" in r.headers.get("content-type", "")
        assert "attachment" in r.headers.get("content-disposition", "")
        assert len(r.content) > 100
        assert r.content[:2] == b"PK"  # ZIP/DOCX magic


class TestGenerateSummaries:
    def test_missing_provider_returns_400(self):
        adapter = get_adapter()
        org_client = adapter.create_client("Provider Test Team")
        app_row = adapter.create_application("Provider Test App")
        report = adapter.create_report("Provider Test Report", client_id=org_client.id, application_id=app_row.id)
        adapter.create_finding(
            report_id=report.id,
            title="XSS",
            content_json="{\"Severity\": \"High\"}",
            notes="notes",
            template="# Summary",
        )
        r = client.post(
            "/api/generate/summaries",
            json={"report_id": report.id},
        )
        assert r.status_code == 400
        detail = r.json().get("detail")
        assert isinstance(detail, dict) and detail.get("code") == "llm_provider_required"

    def test_report_not_found(self):
        r = client.post(
            "/api/generate/summaries",
            json={"report_id": "00000000-0000-0000-0000-000000000099"},
        )
        assert r.status_code == 404

    def test_report_with_no_findings(self):
        adapter = get_adapter()
        org_client = adapter.create_client("No Findings Team")
        app_row = adapter.create_application("Test App")
        report = adapter.create_report("Empty Report", client_id=org_client.id, application_id=app_row.id)
        r = client.post(
            "/api/generate/summaries",
            json={"report_id": report.id, "llm_provider": "ollama"},
        )
        assert r.status_code == 400
        assert "no findings" in r.json().get("detail", "").lower()

    def test_generate_summaries_success(self):
        adapter = get_adapter()
        org_client = adapter.create_client("Summary Team")
        app_row = adapter.create_application("Summary App")
        report = adapter.create_report("Summary Report", client_id=org_client.id, application_id=app_row.id)
        adapter.create_finding(
            report_id=report.id,
            title="SQLi",
            content_json="{\"Severity\": \"High\", \"Remediation\": \"Fix\"}",
            notes="notes",
            template="# Summary",
        )
        with patch("app.services.llm.chat_completion") as mock_chat:
            mock_chat.side_effect = ["exec", "tech", "reco"]
            r = client.post(
                "/api/generate/summaries",
                json={"report_id": report.id, "llm_provider": "ollama"},
            )
        assert r.status_code == 200
        data = r.json()
        assert data["summary_executive"] == "exec"
        assert data["summary_technical"] == "tech"
        assert data["summary_recommendations"] == "reco"

    def test_generate_summaries_does_not_use_mismatched_provider_key(self):
        adapter = get_adapter()
        org_client = adapter.create_client("Summary Provider Mismatch Team")
        app_row = adapter.create_application("Summary Provider Mismatch App")
        report = adapter.create_report("Summary Provider Mismatch Report", client_id=org_client.id, application_id=app_row.id)
        adapter.create_finding(
            report_id=report.id,
            title="XSS",
            content_json="{\"Severity\": \"High\"}",
            notes="notes",
            template="# Summary",
        )

        # Save OpenAI key first, then DeepSeek key (user has both)
        r = client.put(
            "/api/admin/profile",
            json={"openai_api_key": "sk-openai-test", "ai_key_provider": "openai"},
        )
        assert r.status_code == 200
        r = client.put(
            "/api/admin/profile",
            json={"openai_api_key": "sk-deepseek-test", "ai_key_provider": "deepseek"},
        )
        assert r.status_code == 200

        with patch("app.services.llm.chat_completion") as mock_chat:
            mock_chat.side_effect = ["exec", "tech", "reco"]
            r = client.post(
                "/api/generate/summaries",
                json={"report_id": report.id, "llm_provider": "openai"},
            )
        assert r.status_code == 200
        first_call_kwargs = mock_chat.call_args_list[0].kwargs
        assert first_call_kwargs.get("provider_override") == "openai"
        # Uses OpenAI key, not DeepSeek key
        assert first_call_kwargs.get("api_key_override") == "sk-openai-test"

    def test_generate_summaries_uses_key_when_provider_matches(self):
        adapter = get_adapter()
        org_client = adapter.create_client("Summary Provider Match Team")
        app_row = adapter.create_application("Summary Provider Match App")
        report = adapter.create_report("Summary Provider Match Report", client_id=org_client.id, application_id=app_row.id)
        adapter.create_finding(
            report_id=report.id,
            title="SQLi",
            content_json="{\"Severity\": \"High\"}",
            notes="notes",
            template="# Summary",
        )

        # Save a DeepSeek-scoped key and use DeepSeek provider
        r = client.put(
            "/api/admin/profile",
            json={"openai_api_key": "sk-deepseek-test", "ai_key_provider": "deepseek"},
        )
        assert r.status_code == 200

        with patch("app.services.llm.chat_completion") as mock_chat:
            mock_chat.side_effect = ["exec", "tech", "reco"]
            r = client.post(
                "/api/generate/summaries",
                json={"report_id": report.id, "llm_provider": "deepseek"},
            )
        assert r.status_code == 200
        first_call_kwargs = mock_chat.call_args_list[0].kwargs
        assert first_call_kwargs.get("provider_override") == "deepseek"
        assert first_call_kwargs.get("api_key_override") == "sk-deepseek-test"

    def test_generate_summaries_keeps_openai_key_when_deepseek_saved_later(self):
        adapter = get_adapter()
        org_client = adapter.create_client("Summary Multi Key Team")
        app_row = adapter.create_application("Summary Multi Key App")
        report = adapter.create_report("Summary Multi Key Report", client_id=org_client.id, application_id=app_row.id)
        adapter.create_finding(
            report_id=report.id,
            title="Auth",
            content_json="{\"Severity\": \"High\"}",
            notes="notes",
            template="# Summary",
        )

        # Save OpenAI key first, then DeepSeek key
        r = client.put(
            "/api/admin/profile",
            json={"openai_api_key": "sk-openai-test", "ai_key_provider": "openai"},
        )
        assert r.status_code == 200
        r = client.put(
            "/api/admin/profile",
            json={"openai_api_key": "sk-deepseek-test", "ai_key_provider": "deepseek"},
        )
        assert r.status_code == 200

        with patch("app.services.llm.chat_completion") as mock_chat:
            mock_chat.side_effect = ["exec", "tech", "reco"]
            r = client.post(
                "/api/generate/summaries",
                json={"report_id": report.id, "llm_provider": "openai"},
            )
        assert r.status_code == 200
        first_call_kwargs = mock_chat.call_args_list[0].kwargs
        assert first_call_kwargs.get("provider_override") == "openai"
        assert first_call_kwargs.get("api_key_override") == "sk-openai-test"
    
    def test_generate_summaries_injects_severity_constraints(self):
        # Uses ollama (no key required) so we can test without profile setup
        """Verify severity distribution facts are injected into prompts to prevent hallucinations."""
        adapter = get_adapter()
        org_client = adapter.create_client("Summary Constraint Team")
        app_row = adapter.create_application("Summary Constraint App")
        report = adapter.create_report("Summary Constraint Report", client_id=org_client.id, application_id=app_row.id)
        
        # Create findings with NO Critical severity (highest is High)
        adapter.create_finding(
            report_id=report.id,
            title="SQL Injection",
            content_json='{"Severity": "High", "Vulnerability Summary": "Database vulnerability"}',
            notes="notes",
            template="# Summary",
        )
        adapter.create_finding(
            report_id=report.id,
            title="XSS",
            content_json='{"Severity": "Medium", "Vulnerability Summary": "Script injection"}',
            notes="notes",
            template="# Summary",
        )
        adapter.create_finding(
            report_id=report.id,
            title="Config",
            content_json='{"Severity": "Low", "Vulnerability Summary": "Weak config"}',
            notes="notes",
            template="# Summary",
        )
        
        with patch("app.services.llm.chat_completion") as mock_chat:
            mock_chat.side_effect = ["exec", "tech", "reco"]
            r = client.post(
                "/api/generate/summaries",
                json={"report_id": report.id, "llm_provider": "ollama"},
            )
        assert r.status_code == 200

        # Verify severity constraint was injected into all three prompts
        assert mock_chat.call_count == 3
        
        for call in mock_chat.call_args_list:
            prompt = call.kwargs["messages"][-1]["content"]
            
            # Should contain severity distribution
            assert "SEVERITY DISTRIBUTION" in prompt
            assert "Critical: 0 finding(s)" in prompt
            assert "High: 1 finding(s)" in prompt
            assert "Medium: 1 finding(s)" in prompt
            assert "Low: 1 finding(s)" in prompt
            assert "Highest severity present: High" in prompt
            
            # Should contain constraint
            assert "CRITICAL CONSTRAINT" in prompt
            assert 'Do not claim "critical vulnerabilities"' in prompt or "Do not exaggerate" in prompt


class TestListReportsFindingStats:
    def test_list_reports_includes_finding_count_and_severity_breakdown(self):
        """list_reports should return finding_count and severity_breakdown per report."""
        adapter = get_adapter()
        report = adapter.create_report("Stats Report")
        adapter.create_finding(
            report_id=report.id,
            title="Critical Finding",
            content_json='{"Severity": "Critical"}',
            notes="",
            template="",
        )
        adapter.create_finding(
            report_id=report.id,
            title="High Finding 1",
            content_json='{"Severity": "High"}',
            notes="",
            template="",
        )
        adapter.create_finding(
            report_id=report.id,
            title="High Finding 2",
            content_json='{"Severity": "High"}',
            notes="",
            template="",
        )

        r = client.get("/api/admin/reports")
        assert r.status_code == 200
        reports = r.json()
        our_report = next((rp for rp in reports if rp["id"] == report.id), None)
        assert our_report is not None, "Created report not found in list"
        assert our_report["finding_count"] == 3
        assert our_report["severity_breakdown"]["Critical"] == 1
        assert our_report["severity_breakdown"]["High"] == 2

    def test_list_reports_finding_count_zero_for_empty_report(self):
        """Reports with no findings should have finding_count=0 and empty severity_breakdown."""
        adapter = get_adapter()
        report = adapter.create_report("Empty Stats Report")

        r = client.get("/api/admin/reports")
        assert r.status_code == 200
        reports = r.json()
        our_report = next((rp for rp in reports if rp["id"] == report.id), None)
        assert our_report is not None
        assert our_report["finding_count"] == 0
        assert our_report["severity_breakdown"] == {}
