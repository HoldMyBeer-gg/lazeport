"""Tests for app.services.template_parse."""

from app.services.template_parse import (
    _headings_from_html,
    _headings_from_markdown,
    template_all_table_row_labels,
    template_table_rows,
    template_to_section_keys,
)


class TestHeadingsFromMarkdown:
    def test_single_hash(self):
        assert _headings_from_markdown("# Summary") == ["Summary"]

    def test_double_hash(self):
        assert _headings_from_markdown("## Details") == ["Details"]

    def test_multiple_in_order(self):
        text = "# Summary\n\n# Details\n\n# Remediation"
        assert _headings_from_markdown(text) == ["Summary", "Details", "Remediation"]

    def test_ignores_non_headings(self):
        text = "Some text\n# Title\nmore text"
        assert _headings_from_markdown(text) == ["Title"]

    def test_empty(self):
        assert _headings_from_markdown("") == []
        assert _headings_from_markdown("no hashes here") == []


class TestHeadingsFromHtml:
    def test_h2(self):
        assert _headings_from_html("<h2>Finding Title</h2>") == ["Finding Title"]

    def test_h1_h4_case_insensitive(self):
        text = "<H1>One</H1><h4>Four</h4>"
        assert _headings_from_html(text) == ["One", "Four"]

    def test_bold(self):
        assert _headings_from_html("<b>Vulnerability Summary</b>") == ["Vulnerability Summary"]

    def test_strong(self):
        assert _headings_from_html("<strong>Remediation</strong>") == ["Remediation"]

    def test_mixed_order(self):
        text = "<h2>Title</h2><b>Summary</b><strong>Details</strong>"
        assert _headings_from_html(text) == ["Title", "Summary", "Details"]

    def test_dedupe(self):
        text = "<b>Summary</b> text <b>Summary</b>"
        assert _headings_from_html(text) == ["Summary"]

    def test_empty(self):
        assert _headings_from_html("") == []
        assert _headings_from_html("<p>no headings</p>") == []


class TestTemplateToSectionKeys:
    def test_empty_returns_default(self):
        assert template_to_section_keys("") == ["Summary", "Details", "Remediation", "References"]
        assert template_to_section_keys("   ") == ["Summary", "Details", "Remediation", "References"]
        assert template_to_section_keys(None) == ["Summary", "Details", "Remediation", "References"]

    def test_markdown_detection(self):
        text = "# Summary\n# Details"
        assert template_to_section_keys(text) == ["Summary", "Details"]

    def test_html_detection(self):
        text = "<h2>Finding Title</h2><b>Summary</b>"
        assert template_to_section_keys(text) == ["Finding Title", "Summary"]

    def test_looks_like_html_with_b(self):
        text = "<b>Only Bold</b>"
        assert template_to_section_keys(text) == ["Only Bold"]

    def test_no_headings_returns_default(self):
        assert template_to_section_keys("just plain text") == ["Summary", "Details", "Remediation", "References"]

    def test_strip_whitespace(self):
        assert template_to_section_keys("  # Foo  ") == ["Foo"]


class TestTemplateTableRows:
    def test_no_table_returns_none_empty(self):
        assert template_table_rows("") == (None, [])
        assert template_table_rows("<p>No table</p>") == (None, [])

    def test_table_extracts_row_labels(self):
        html = "<b>Justification</b><table><tr><td>Severity</td><td>High</td></tr>"
        html += "<tr><td>CVSS v3.1</td><td>https://example.com</td></tr></table>"
        insert_after, labels = template_table_rows(html)
        assert insert_after == "Justification"
        assert labels == ["Severity", "CVSS v3.1"]

    def test_insert_after_last_heading_before_table(self):
        html = "<h2>A</h2><b>B</b><b>Justification</b><table><tr><td>CWE</td><td>x</td></tr></table>"
        insert_after, labels = template_table_rows(html)
        assert insert_after == "Justification"
        assert labels == ["CWE"]


class TestTemplateAllTableRowLabels:
    def test_no_table_returns_empty(self):
        assert template_all_table_row_labels("") == []
        assert template_all_table_row_labels("<p>No table</p>") == []

    def test_single_table(self):
        html = "<table><tr><td>Severity</td><td>High</td></tr><tr><td>CVSS v3.1</td><td>url</td></tr></table>"
        assert template_all_table_row_labels(html) == ["Severity", "CVSS v3.1"]

    def test_multiple_tables_in_order(self):
        html = "<table><tr><td>Affected Files</td><td>list</td></tr></table>"
        html += "<p>text</p><table class='raw_code'><tr><td>Raw HTTP Request</td><td><pre><code></code></pre></td></tr>"
        html += "<tr><td>Raw HTTP Response</td><td><pre><code></code></pre></td></tr></table>"
        assert template_all_table_row_labels(html) == [
            "Affected Files",
            "Raw HTTP Request",
            "Raw HTTP Response",
        ]
