"""Tests for app.services.docx_builder."""
import io
import zipfile


from app.services.docx_builder import build_docx


def _docx_paragraph_texts(docx_bytes: bytes) -> list[str]:
    """Extract paragraph/heading text from a DOCX (simplified: we just check it's valid zip with word/document.xml)."""
    z = zipfile.ZipFile(io.BytesIO(docx_bytes), "r")
    assert "word/document.xml" in z.namelist()
    content = z.read("word/document.xml").decode("utf-8")
    z.close()
    return content


def _docx_relationships(docx_bytes: bytes) -> str:
    z = zipfile.ZipFile(io.BytesIO(docx_bytes), "r")
    rels = z.read("word/_rels/document.xml.rels").decode("utf-8")
    z.close()
    return rels


class TestBuildDocx:
    def test_returns_bytes(self):
        out = build_docx(
            structured={"title": "Test", "Summary": "Hello", "Details": "World"},
            template="# Summary\n# Details",
            title="Report Title",
        )
        assert isinstance(out, bytes)
        assert len(out) > 100

    def test_does_not_render_doc_title(self):
        out = build_docx(
            structured={"title": "Vuln", "Summary": "S"},
            template="# Summary",
            title="My Report",
        )
        xml = _docx_paragraph_texts(out)
        assert "My Report" not in xml and "MyReport" not in xml.replace(" ", "")

    def test_section_order_follows_template(self):
        out = build_docx(
            structured={
                "title": "T",
                "Remediation": "R",
                "Summary": "S",
                "Details": "D",
            },
            template="# Summary\n# Details\n# Remediation",
            title="T",
        )
        xml = _docx_paragraph_texts(out)
        # Order in XML should reflect template order
        idx_summary = xml.find("Summary")
        idx_details = xml.find("Details")
        idx_remediation = xml.find("Remediation")
        assert idx_summary < idx_details < idx_remediation

    def test_filters_title_from_sections(self):
        out = build_docx(
            structured={"title": "Finding Title", "Summary": "S"},
            template="# title\n# Summary",
            title="Report",
        )
        xml = _docx_paragraph_texts(out)
        assert "Summary" in xml

    def test_extra_keys_appended(self):
        out = build_docx(
            structured={
                "title": "T",
                "Summary": "S",
                "CustomSection": "Custom content",
            },
            template="# Summary",
            title="T",
        )
        xml = _docx_paragraph_texts(out)
        assert "CustomSection" in xml or "Custom Section" in xml
        assert "Custom content" in xml

    def test_empty_content_skipped(self):
        out = build_docx(
            structured={"title": "T", "Summary": "S", "Details": ""},
            template="# Summary\n# Details",
            title="T",
        )
        xml = _docx_paragraph_texts(out)
        assert "Summary" in xml

    def test_template_table_inserted_after_justification(self):
        template = "<b>Justification</b><table><tr><td>Severity</td><td>High</td></tr>"
        template += "<tr><td>CVSS v3.1</td><td>link</td></tr></table><b>Rationale</b>"
        out = build_docx(
            structured={
                "title": "T",
                "Justification": "Because.",
                "Severity": "High",
                "CVSS v3.1": "7.5",
                "Rationale": "Reason.",
            },
            template=template,
            title="T",
        )
        xml = _docx_paragraph_texts(out)
        assert "Severity" in xml and "High" in xml
        assert "CVSS v3.1" in xml and "7.5" in xml
        # Table grid / tbl present
        assert "w:tbl" in xml or "tbl" in xml

    def test_links_added_for_identifiers_when_allowed(self, monkeypatch):
        def fake_valid_urls(urls):
            return set(urls)

        monkeypatch.setattr("app.services.docx_builder.get_valid_urls", fake_valid_urls)
        out = build_docx(
            structured={
                "Summary": "References CVE-2021-1234 and CWE-79",
                "Details": "See https://example.com/advisory",
            },
            template="# Summary\n# Details",
            title="T",
        )
        rels = _docx_relationships(out)
        assert "nvd.nist.gov" in rels
        assert "cwe.mitre.org" in rels
        assert "example.com" in rels

    def test_missing_cvss_renders_placeholder_not_invented_vector(self):
        template = "<b>Justification</b><table><tr><td>Severity</td><td>High</td></tr>"
        template += "<tr><td>CVSS v3.1</td><td>link</td></tr></table><b>Rationale</b>"
        out = build_docx(
            structured={
                "title": "T",
                "Justification": "SQL injection in the login form.",
                "Severity": "High",
                "Rationale": "Reason.",
            },
            template=template,
            title="T",
        )
        xml = _docx_paragraph_texts(out)
        assert "Not provided in evidence" in xml
        assert "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" not in xml
        assert "7.5" not in xml

    def test_cvss_vector_creates_calculator_link(self, monkeypatch):
        def fake_valid_urls(urls):
            return set(urls)

        monkeypatch.setattr("app.services.docx_builder.get_valid_urls", fake_valid_urls)
        template = "<b>Justification</b><table><tr><td>CVSS v3.1</td><td>link</td></tr></table>"
        out = build_docx(
            structured={
                "Justification": "Vector CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "CVSS v3.1": "6.1 (AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)",
            },
            template=template,
            title="T",
        )
        rels = _docx_relationships(out)
        assert "first.org/cvss/calculator/3.1" in rels

    def test_localizes_severity_in_docx_table_only(self):
        template = "<b>Justification</b><table><tr><td>Severity</td><td>High</td></tr></table>"
        structured = {
            "Justification": "Because.",
            "Severity": "High",
        }
        out = build_docx(
            structured=structured,
            template=template,
            title="T",
            locale="de",
        )
        xml = _docx_paragraph_texts(out)
        assert "Hoch" in xml
        assert structured["Severity"] == "High"

    def test_internal_flags_excluded_from_output(self):
        """Test that internal metadata flags (starting with _) are not rendered in DOCX."""
        template = "# Summary\n# Details"
        structured = {
            "Summary": "Test vulnerability",
            "Details": "More information",
            "_severity_flags": ["clamped", "rubric_source=template"],
            "_clamp_flags": ["affected_files_set_from_evidence"],
            "_validation_flags": ["retry_successful"],
            "_model_retry": True,
        }
        out = build_docx(
            structured=structured,
            template=template,
            title="Test Finding",
        )
        xml = _docx_paragraph_texts(out)
        
        # Verify internal flags do not appear in output
        assert "_severity_flags" not in xml
        assert "_clamp_flags" not in xml
        assert "_validation_flags" not in xml
        assert "_model_retry" not in xml
        assert "rubric_source" not in xml
        assert "affected_files_set_from_evidence" not in xml
        
        # Verify actual content is present
        assert "Test vulnerability" in xml
        assert "More information" in xml


class TestDeriveTableValuesAffected:
    """Affected Roles/Users default to the evidence placeholder, not an invented 'All Users'."""

    def test_missing_affected_uses_placeholder(self):
        from app.services.docx_builder import _derive_table_values
        values = _derive_table_values({"Severity": "High"})
        assert values["Affected Roles"] == "Not provided in evidence"
        assert values["Affected Users"] == "Not provided in evidence"

    def test_stated_affected_kept(self):
        from app.services.docx_builder import _derive_table_values
        values = _derive_table_values({"Severity": "High", "Affected Roles": "Authenticated users"})
        assert values["Affected Roles"] == "Authenticated users"
