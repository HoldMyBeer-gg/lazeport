"""
Build a DOCX from structured content (dict of section heading -> content) and optional template.
Uses python-docx; template (Markdown or HTML) determines section order and headings.
Applies Tahoma font and severity colors per template UX.
Includes template table (e.g. Severity, CVSS, CWE, OWASP) with hyperlinks only for validated URLs.
"""
import io
import re
from typing import Any, Dict, Set, List

from docx import Document
from docx.shared import RGBColor
from docx.enum.style import WD_STYLE_TYPE
from docx.oxml.ns import qn
from docx.oxml.parser import OxmlElement
from docx.opc.constants import RELATIONSHIP_TYPE as RT

from app.services.template_parse import template_to_section_keys, template_table_rows
from app.services.severity_localization import localize_severity_label
from app.services.link_validator import (
    extract_urls,
    extract_identifier_urls,
    get_valid_urls,
    identifier_to_url,
    is_canonical_url,
)

# Severity colors from template CSS (Tahoma, severity colors)
FONT_NAME = "Tahoma"
SEVERITY_COLORS = {
    "critical": RGBColor(102, 42, 128),
    "high": RGBColor(218, 47, 32),
    "medium": RGBColor(193, 79, 33),
    "low": RGBColor(53, 121, 180),
    "informational": RGBColor(0, 98, 0),
}
SEVERITY_WORDS = re.compile(
    r"\b(Critical|High|Medium|Low|Informational)\b",
    re.IGNORECASE,
)
LINK_TOKEN_RE = re.compile(
    r"(https?://[^\s<>\"')\]]+|\bCVE-\d{4}-\d{4,7}\b|\bCWE-\d{1,5}\b|\bA\d{1,2}(?::20\d{2})?\b|CVSS:3\.1/[A-Za-z0-9:/]+|(?<![A-Za-z])AV:[A-Z]/AC:[A-Z]/PR:[A-Z]/UI:[A-Z]/S:[A-Z]/C:[A-Z]/I:[A-Z]/A:[A-Z])",
    re.IGNORECASE,
)
CVSS_CALC_URL = "https://www.first.org/cvss/calculator/3.1"
CVSS_VECTOR_RE = re.compile(
    r"(CVSS:3\.1/[A-Za-z0-9:/]+|AV:[A-Z]/AC:[A-Z]/PR:[A-Z]/UI:[A-Z]/S:[A-Z]/C:[A-Z]/I:[A-Z]/A:[A-Z])"
)
CWE_TOKEN_RE = re.compile(r"\bCWE-\d{1,5}\b", re.IGNORECASE)
OWASP_TOKEN_RE = re.compile(r"\bA\d{1,2}(?::20\d{2})?\b", re.IGNORECASE)

HTTP_TABLE_BG = "F2F2F2"
HTTP_TABLE_BORDER = "4D4D4D"
HTTP_FONT = "Courier New"


def _set_document_font_tahoma(doc: Document) -> None:
    """Set Tahoma as default font for Normal and Heading styles."""
    for style in doc.styles:
        if style.type in (WD_STYLE_TYPE.PARAGRAPH, WD_STYLE_TYPE.CHARACTER):
            if style.font:
                style.font.name = FONT_NAME
        if style.name.startswith("Heading") and style.font:
            style.font.name = FONT_NAME


def _add_text_with_severity_runs(p, text: str) -> None:
    """Add text to paragraph with markdown formatting and severity word coloring.
    
    Handles: **bold**, *italic*, `code`, single \\n as line breaks,
    and severity-word coloring (Critical, High, Medium, Low, Informational).
    """
    from app.services.docx_markdown import add_markdown_runs

    if not text:
        return

    def _severity_handler(run, token):
        """Post-process each run to color severity words."""
        if token.get("type") in ("break", "code"):
            return
        run_text = run.text or ""
        # Check if the entire run is a severity word
        sev_match = SEVERITY_WORDS.fullmatch(run_text.strip())
        if sev_match:
            run.font.bold = True
            color = SEVERITY_COLORS.get(sev_match.group(0).lower())
            if color:
                run.font.color.rgb = color
            return
        # For runs containing severity words mixed with other text,
        # we can't split mid-run, but the markdown parser has already
        # split on formatting boundaries, so severity words in plain
        # text segments will typically be whole runs.

    add_markdown_runs(p, text, font_name=FONT_NAME, extra_run_handler=_severity_handler)


def _add_hyperlink(p, doc: Document, url: str, text: str) -> bool:
    """Add a hyperlink run to the paragraph. Returns True if added."""
    try:
        rId = doc.part.relate_to(url, RT.HYPERLINK, is_external=True)
        hyperlink_el = OxmlElement("w:hyperlink", attrs={qn("r:id"): rId})
        run_el = OxmlElement("w:r")
        rPr = run_el.get_or_add_rPr()
        rFonts = rPr.get_or_add_rFonts()
        rFonts.set(qn("w:ascii"), FONT_NAME)
        rFonts.set(qn("w:hAnsi"), FONT_NAME)
        rFonts.set(qn("w:cs"), FONT_NAME)
        rStyle = OxmlElement("w:rStyle")
        rStyle.set(qn("w:val"), "Hyperlink")
        rPr.append(rStyle)
        run_el.add_t(text)
        hyperlink_el.append(run_el)
        p._p.append(hyperlink_el)
        return True
    except Exception:
        return False


def _set_cell_shading(cell, fill: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    tc_pr.append(shd)


def _set_cell_border(cell, color: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    borders = OxmlElement("w:tcBorders")
    for edge in ("top", "left", "bottom", "right"):
        edge_el = OxmlElement(f"w:{edge}")
        edge_el.set(qn("w:val"), "single")
        edge_el.set(qn("w:sz"), "4")
        edge_el.set(qn("w:space"), "0")
        edge_el.set(qn("w:color"), color)
        borders.append(edge_el)
    tc_pr.append(borders)


def _add_http_snippets(doc: Document, snippets: list[dict[str, str]]) -> None:
    if not snippets:
        return
    for snippet in snippets:
        label = "HTTP Request" if snippet.get("type") == "request" else "HTTP Response"
        h_para = doc.add_paragraph()
        run = h_para.add_run(label)
        run.font.name = FONT_NAME
        run.font.bold = True
        tbl = doc.add_table(rows=1, cols=1)
        cell = tbl.rows[0].cells[0]
        _set_cell_shading(cell, HTTP_TABLE_BG)
        _set_cell_border(cell, HTTP_TABLE_BORDER)
        p = cell.paragraphs[0]
        p._p.clear_content()
        for line in (snippet.get("text") or "").splitlines():
            run = p.add_run(line + "\n")
            run.font.name = HTTP_FONT
        doc.add_paragraph()


def _allowed_link(url: str, valid_urls: Set[str]) -> bool:
    """Allow link if validated or from canonical reference (CVE/CWE/OWASP/CVSS). Always link identifiers."""
    return url in valid_urls or is_canonical_url(url)


def _cvss_link_from_value(value: str) -> str | None:
    m = CVSS_VECTOR_RE.search(value)
    if not m:
        return None
    vector = m.group(1)
    if not vector.startswith("CVSS:3.1/"):
        vector = f"CVSS:3.1/{vector}"
    return f"{CVSS_CALC_URL}#{vector}"


def _token_to_url(token: str, row_label: str | None = None) -> str | None:
    """Resolve a matched token to its canonical URL."""
    token = token.strip().rstrip(".,;:)")
    # Plain URL
    if token.startswith(("http://", "https://")):
        return token
    # CVE / CWE / OWASP
    url = identifier_to_url(token)
    if url:
        return url
    # CVSS vector
    m = CVSS_VECTOR_RE.search(token)
    if m:
        vector = m.group(1)
        if not vector.startswith("CVSS:3.1/"):
            vector = f"CVSS:3.1/{vector}"
        return f"{CVSS_CALC_URL}#{vector}"
    return None


def _add_paragraph_with_links(doc: Document, text: str, valid_urls: Set[str]) -> None:
    """Add a paragraph; hyperlink validated URLs/CVE/CWE/OWASP/CVSS tokens; keep severity styling."""
    if not text.strip():
        return
    p = doc.add_paragraph()
    p.style.font.name = FONT_NAME
    last_end = 0
    for m in LINK_TOKEN_RE.finditer(text):
        if m.start() > last_end:
            _add_text_with_severity_runs(p, text[last_end : m.start()])
        token = m.group(0)
        token_clean = token.rstrip(".,;:)")
        url = _token_to_url(token_clean)
        if url and _allowed_link(url, valid_urls):
            if _add_hyperlink(p, doc, url, token_clean):
                # Add back trailing punctuation
                trail = token[len(token_clean):]
                if trail:
                    _add_text_with_severity_runs(p, trail)
            else:
                _add_text_with_severity_runs(p, token)
        else:
            _add_text_with_severity_runs(p, token)
        last_end = m.end()
    if last_end < len(text):
        _add_text_with_severity_runs(p, text[last_end:])


def _template_headings_order(template: str) -> list[str]:
    """Return section headings in order as they appear in the template (Markdown or HTML)."""
    keys = template_to_section_keys(template)
    # Dedupe preserving order
    seen = set()
    ordered = []
    for k in keys:
        if k not in seen:
            seen.add(k)
            ordered.append(k)
    return ordered if ordered else ["Summary", "Details", "Remediation", "References"]


def _collect_urls_from_structured(structured: Dict[str, Any], row_labels: list[str]) -> list[str]:
    """Collect all URLs from structured content and from table row values."""
    urls: list[str] = []
    for k, v in structured.items():
        # Skip internal metadata keys
        if k.startswith("_"):
            continue
        if isinstance(v, str):
            urls.extend(extract_urls(v))
            urls.extend(extract_identifier_urls(v))
            # Also collect CVSS calculator URLs with their vectors from any value
            cvss_url = _cvss_link_from_value(v)
            if cvss_url:
                urls.append(cvss_url)
    for label in row_labels:
        val = structured.get(label)
        if isinstance(val, str):
            urls.extend(extract_urls(val))
            urls.extend(extract_identifier_urls(val))
        if "cvss" in label.lower():
            urls.append(CVSS_CALC_URL)
            # Also collect the specific vector URL
            cvss_val = structured.get(label, "")
            if isinstance(cvss_val, str):
                cvss_url = _cvss_link_from_value(cvss_val)
                if cvss_url:
                    urls.append(cvss_url)
    return urls


_SEVERITY_TO_CVSS = {"Critical": "9.8", "High": "7.5", "Medium": "5.3", "Low": "3.1", "Informational": "0.0"}


def _derive_table_values(structured: Dict[str, Any]) -> dict[str, str]:
    """Derive table values (Severity/CVSS/CWE/OWASP) from structured content when missing."""
    values: dict[str, str] = {}
    text = "\n".join(str(v) for k, v in structured.items() if isinstance(v, str) and not k.startswith("_"))
    severity = str(structured.get("Severity", "")).strip()
    values["Severity"] = severity or ""
    # CWE
    m = CWE_TOKEN_RE.search(text)
    if m:
        values["CWE"] = m.group(0).upper()
    # OWASP
    m = OWASP_TOKEN_RE.search(text)
    if m:
        values["OWASP"] = m.group(0).upper()
    # CVSS score + vector: use severity-based default when no parseable CVSS
    cvss_text = str(structured.get("CVSS v3.1", "")) + "\n" + text
    score_match = re.search(r"\b([0-9]\.[0-9])\b", cvss_text)
    vector_match = CVSS_VECTOR_RE.search(cvss_text)
    if score_match and vector_match:
        vector = vector_match.group(1)
        if not vector.startswith("CVSS:3.1/"):
            vector = f"CVSS:3.1/{vector}"
        values["CVSS v3.1"] = f"{score_match.group(1)} ({vector})"
    else:
        default_score = (_SEVERITY_TO_CVSS.get(severity) if severity else None) or "6.1"
        values["CVSS v3.1"] = f"{default_score} (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)"
    affected = str(structured.get("Affected Roles") or structured.get("Affected Users") or "").strip()
    values["Affected Roles"] = affected or "Not provided in evidence"
    values["Affected Users"] = affected or "Not provided in evidence"
    return values


def _set_cell_value(
    cell,
    value: str,
    valid_urls: Set[str],
    doc: Document,
    is_severity_row: bool = False,
    row_label: str | None = None,
) -> None:
    """Set cell content with inline hyperlinks for identifiers (CVE, CWE, OWASP, CVSS, URLs)."""
    value = (value or "").strip()
    p = cell.paragraphs[0]
    p._p.clear_content()
    if not value:
        return

    # For CVSS rows: try linking the whole value to the CVSS calculator first
    if row_label and "cvss" in row_label.lower():
        cvss_url = _cvss_link_from_value(value)
        if cvss_url and _allowed_link(cvss_url, valid_urls):
            if _add_hyperlink(p, doc, cvss_url, value):
                return

    # Scan the cell text for identifiers and hyperlink them inline
    last_end = 0
    linked_any = False
    for m in LINK_TOKEN_RE.finditer(value):
        # Add any text before this match as plain text
        if m.start() > last_end:
            preceding = value[last_end:m.start()]
            if is_severity_row:
                _add_text_with_severity_runs(p, preceding)
            else:
                run = p.add_run(preceding)
                run.font.name = FONT_NAME

        token = m.group(0)
        token_clean = token.rstrip(".,;:)")
        url = _token_to_url(token_clean, row_label)

        if url and _allowed_link(url, valid_urls):
            if _add_hyperlink(p, doc, url, token_clean):
                # Add back any trailing punctuation that was stripped
                trail = token[len(token_clean):]
                if trail:
                    run = p.add_run(trail)
                    run.font.name = FONT_NAME
                linked_any = True
            else:
                if is_severity_row:
                    _add_text_with_severity_runs(p, token)
                else:
                    run = p.add_run(token)
                    run.font.name = FONT_NAME
        else:
            if is_severity_row:
                _add_text_with_severity_runs(p, token)
            else:
                run = p.add_run(token)
                run.font.name = FONT_NAME

        last_end = m.end()

    # Add any remaining text after the last match
    if last_end < len(value):
        remaining = value[last_end:]
        if is_severity_row:
            _add_text_with_severity_runs(p, remaining)
        else:
            run = p.add_run(remaining)
            run.font.name = FONT_NAME


def build_docx(
    structured: Dict[str, Any],
    template: str,
    title: str = "Vulnerability Report",
    raw_http_snippets: List[Dict[str, str]] | None = None,
    locale: str | None = None,
) -> bytes:
    """
    Produce a DOCX file. structured is a dict: section_heading -> content (str).
    Section order follows template (Markdown or HTML); title is the document title.
    If template has a table, it is inserted after the designated heading with validated hyperlinks only.
    """
    doc = Document()
    _set_document_font_tahoma(doc)

    insert_after_heading, table_row_labels = template_table_rows(template)
    all_urls = _collect_urls_from_structured(structured, table_row_labels or [])
    valid_urls: Set[str] = get_valid_urls(all_urls) if all_urls else set()

    # No document-level title for single-finding copy/paste use

    _add_http_snippets(doc, raw_http_snippets or [])

    order = _template_headings_order(template)
    order = [h for h in order if h.lower() != "title"]
    # Do not render table fields as standalone sections
    table_field_set = {k.lower() for k in (table_row_labels or [])}
    order = [h for h in order if h.lower() not in table_field_set]

    derived_table_values = _derive_table_values(structured)
    for heading in order:
        content = structured.get(heading, "")
        if isinstance(content, list):
            content = "\n\n".join(str(x) for x in content if x is not None)
        if not content and heading not in structured:
            continue
        # Use the actual finding title as heading text when the template section is "Finding Title"
        display_heading = heading
        if heading == "Finding Title":
            display_heading = (structured.get("title") or "").strip() or (
                (structured.get("Finding Title") or "").strip().split("\n")[0]
            ) or "Finding Title"
        if heading == "Finding Title":
            h_para = doc.add_heading(display_heading, level=2)
            for run in h_para.runs:
                run.font.name = FONT_NAME
        else:
            h_para = doc.add_paragraph()
            run = h_para.add_run(display_heading)
            run.font.name = FONT_NAME
            run.font.bold = True
        for block in (content or "").split("\n\n"):
            block = block.strip()
            if not block:
                continue
            # Avoid repeating the finding title as first paragraph when heading is already the title
            if heading == "Finding Title" and block == display_heading:
                continue
            _add_paragraph_with_links(doc, block, valid_urls)
        doc.add_paragraph()

        # Insert template table after this section if configured
        if table_row_labels and heading == insert_after_heading:
            tbl = doc.add_table(rows=len(table_row_labels), cols=2)
            tbl.style = "Table Grid"
            for i, label in enumerate(table_row_labels):
                tbl.rows[i].cells[0].text = label
                for run in tbl.rows[i].cells[0].paragraphs[0].runs:
                    run.font.name = FONT_NAME
                val = structured.get(label, "") or derived_table_values.get(label, "")
                display_val = val
                if label.lower() == "severity":
                    display_val = localize_severity_label(
                        val if isinstance(val, str) else str(val or ""),
                        locale,
                    )
                _set_cell_value(
                    tbl.rows[i].cells[1],
                    display_val if isinstance(display_val, str) else str(display_val or ""),
                    valid_urls,
                    doc,
                    is_severity_row=(label.lower() == "severity"),
                    row_label=label,
                )
            doc.add_paragraph()

    for key, value in structured.items():
        # Skip internal metadata keys (traceability flags, system metadata)
        if key.startswith("_"):
            continue
        if key in ("title",) or key in order:
            continue
        if key.lower() in table_field_set:
            continue
        if isinstance(value, list):
            value = "\n\n".join(str(x) for x in value if x is not None)
        if isinstance(value, str) and value.strip():
            h_para = doc.add_heading(key, level=1)
            for run in h_para.runs:
                run.font.name = FONT_NAME
            for block in value.split("\n\n"):
                if block.strip():
                    _add_paragraph_with_links(doc, block.strip(), valid_urls)
            doc.add_paragraph()

    buffer = io.BytesIO()
    doc.save(buffer)
    buffer.seek(0)
    return buffer.read()
