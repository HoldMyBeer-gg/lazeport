from __future__ import annotations

import io
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List
from zipfile import BadZipFile

from docx import Document
from docx.shared import Pt, RGBColor
from docxtpl import DocxTemplate

from app.services.severity_localization import canonicalize_severity, localize_severity_label

log = logging.getLogger(__name__)

# Severity keywords for extraction
SEVERITY_KEYWORDS = ["critical", "high", "medium", "low", "informational"]


def _iter_all_paragraphs(doc: Document):
    """
    Iterate over ALL paragraphs in document including body, tables, headers, and footers.

    Covers: body, table cells, default headers/footers, first-page headers/footers,
    and even-page headers/footers — docxtpl misses the latter two during rendering.
    """
    # Body paragraphs
    for p in doc.paragraphs:
        yield p

    # Table cell paragraphs
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                for p in cell.paragraphs:
                    yield p

    # All header/footer variants per section
    for section in doc.sections:
        for hf in (
            section.header,
            section.footer,
            section.first_page_header,
            section.first_page_footer,
            section.even_page_header,
            section.even_page_footer,
        ):
            if hf is not None:
                for p in hf.paragraphs:
                    yield p
                for table in hf.tables:
                    for row in table.rows:
                        for cell in row.cells:
                            for p in cell.paragraphs:
                                yield p

# In-memory cache for extracted severity criteria
# Key: (name, content_hash), Value: Dict[str, str]
_severity_cache: Dict[tuple[str, str], Dict[str, str]] = {}


# ── Severity criteria extraction ──────────────────────────────────────────

def extract_severity_criteria_from_bytes(name: str, docx_bytes: bytes) -> Dict[str, str]:
    """
    Extract severity definitions from DOCX bytes (cached).
    Returns dict: {"Critical": "...", "High": "...", etc.}
    Returns empty dict if no definitions found.
    
    Looks for patterns like:
    - "Critical:" or "Critical Severity:" followed by definition text
    - Tables with severity levels in first column
    - Dedicated severity definition sections
    
    Results are cached in memory, keyed by (name, hash(content)).
    """
    try:
        # Check cache first using content hash
        import hashlib
        content_hash = hashlib.sha256(docx_bytes).hexdigest()[:16]
        cache_key = (name, content_hash)
        
        if cache_key in _severity_cache:
            return _severity_cache[cache_key]
        
        # Not cached - extract from bytes
        doc = Document(io.BytesIO(docx_bytes))
    except Exception:
        return {}
    
    criteria: Dict[str, str] = {}
    
    # Pattern 1: Prose definitions (e.g., "Critical: ..." or "Critical Severity:")
    severity_pattern = re.compile(
        r"^(Critical|High|Medium|Low|Informational)\s*(?:Severity)?[:\-–—]\s*(.+)",
        re.IGNORECASE | re.MULTILINE
    )
    
    # Search all paragraphs
    for para in doc.paragraphs:
        text = para.text.strip()
        if not text:
            continue
        match = severity_pattern.search(text)
        if match:
            sev_level = match.group(1).capitalize()
            definition = match.group(2).strip()
            # Capture following paragraphs that seem to be part of the definition
            if definition and sev_level not in criteria:
                criteria[sev_level] = definition
    
    # Pattern 2: Tables with severity levels in first column
    for table in doc.tables:
        if len(table.rows) < 2:
            continue
        # Check if first column contains severity keywords
        first_col_text = "\n".join(row.cells[0].text.strip().lower() for row in table.rows)
        if not any(kw in first_col_text for kw in SEVERITY_KEYWORDS):
            continue
        
        for row in table.rows:
            if len(row.cells) < 2:
                continue
            cell_text = row.cells[0].text.strip()
            # Check if this cell contains a severity keyword
            match = re.match(r"^(Critical|High|Medium|Low|Informational)", cell_text, re.IGNORECASE)
            if match:
                sev_level = match.group(1).capitalize()
                definition = row.cells[1].text.strip()
                if definition and sev_level not in criteria:
                    criteria[sev_level] = definition
    
    # Cache the result
    _severity_cache[cache_key] = criteria
    
    # Clean up old cache entries (keep only last 10)
    if len(_severity_cache) > 10:
        oldest_key = next(iter(_severity_cache))
        del _severity_cache[oldest_key]
    
    return criteria


def extract_severity_criteria(docx_path: Path) -> Dict[str, str]:
    """
    Extract severity definitions from a DOCX file path.
    This is a compatibility wrapper for file-based extraction.
    """
    try:
        docx_bytes = docx_path.read_bytes()
        return extract_severity_criteria_from_bytes(docx_path.stem, docx_bytes)
    except Exception:
        return {}


# ── Finding helpers ─────────────────────────────────────────────────────────

def _extract_severity(content: Dict[str, str]) -> str:
    sev = _to_str(content.get("Severity") or content.get("severity")).strip().lower()
    # Normalize Burp's "information" to "informational"
    if sev == "information":
        sev = "informational"
    if sev in ("critical", "high", "medium", "low", "informational"):
        return sev
    return "informational"


SEVERITY_COLORS = {
    "critical": RGBColor(0x66, 0x2A, 0x80),
    "high": RGBColor(0xDA, 0x2F, 0x20),
    "medium": RGBColor(0xC1, 0x4F, 0x21),
    "low": RGBColor(0x35, 0x79, 0xB4),
    "informational": RGBColor(0x00, 0x62, 0x00),
}


def _normalize_finding(content) -> Dict[str, str]:
    if isinstance(content, dict):
        return content
    if isinstance(content, str):
        try:
            return json.loads(content)
        except Exception:
            return {}
    return {}


# Ordered list of section keys we look for in each finding
_SECTION_ORDER = [
    "Vulnerability Summary",
    "Justification",
    "Rationale",
    "Root Cause",
    "Details",
    "Remediation",
    "Additional Notes",
    "References",
    "Validation Guidance",
]

# Keys that go into the metadata table row
_TABLE_KEYS = ["Severity", "CVSS v3.1", "CWE", "OWASP", "Affected Roles", "Affected Files"]


def _to_str(val) -> str:
    """Convert value to string safely; content_json can have lists/numbers."""
    if val is None:
        return ""
    if isinstance(val, list):
        return "\n".join(str(x) for x in val) if val else ""
    return str(val)


def _add_text_with_hyperlinks(paragraph, text: str, font_size=None) -> None:
    """Add text to a paragraph, converting URLs/references to hyperlinks and
    rendering markdown inline formatting (**bold**, *italic*, `code`).
    
    Single newlines within the text become Word line breaks (soft returns).
    
    Detects and creates hyperlinks for:
    - Full URLs (http://, https://)
    - CWE-XXX patterns → https://cwe.mitre.org/data/definitions/XXX.html
    - CVE-XXXX-XXXX patterns → https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXX
    - OWASP AXX patterns → https://owasp.org/Top10/A0X_2021-.../ or 2017 version
    - CVSS vector strings → https://www.first.org/cvss/calculator/3.1#...
    """
    from app.services.docx_markdown import add_markdown_runs
    
    # OWASP Top 10 URL mappings
    OWASP_2021 = {
        '1': 'A01_2021-Broken_Access_Control',
        '2': 'A02_2021-Cryptographic_Failures',
        '3': 'A03_2021-Injection',
        '4': 'A04_2021-Insecure_Design',
        '5': 'A05_2021-Security_Misconfiguration',
        '6': 'A06_2021-Vulnerable_and_Outdated_Components',
        '7': 'A07_2021-Identification_and_Authentication_Failures',
        '8': 'A08_2021-Software_and_Data_Integrity_Failures',
        '9': 'A09_2021-Security_Logging_and_Monitoring_Failures',
        '10': 'A10_2021-Server-Side_Request_Forgery_%28SSRF%29',
    }
    OWASP_2017 = {
        '1': 'A1_2017-Injection',
        '2': 'A2_2017-Broken_Authentication',
        '3': 'A3_2017-Sensitive_Data_Exposure',
        '4': 'A4_2017-XML_External_Entities_%28XXE%29',
        '5': 'A5_2017-Broken_Access_Control',
        '6': 'A6_2017-Security_Misconfiguration',
        '7': 'A7_2017-Cross-Site_Scripting_%28XSS%29',
        '8': 'A8_2017-Insecure_Deserialization',
        '9': 'A9_2017-Using_Components_with_Known_Vulnerabilities',
        '10': 'A10_2017-Insufficient_Logging%26Monitoring',
    }
    
    # Pattern to match URLs, CWE, CVE, OWASP, and CVSS vectors (full and shorthand)
    url_pattern = re.compile(
        r'(https?://[^\s<>"{}|\\^`\[\]]+|'  # Full URLs
        r'CWE-\d+|'  # CWE references
        r'CVE-\d{4}-\d{4,}|'  # CVE references
        r'A\d{1,2}(?::20\d{2})?|'  # OWASP references (A01:2021, A9, etc.)
        r'CVSS:3\.[01]/[A-Za-z0-9:/]+|'  # CVSS v3.x full vector strings
        r'(?<![A-Za-z])AV:[A-Z]/AC:[A-Z]/PR:[A-Z]/UI:[A-Z]/S:[A-Z]/C:[A-Z]/I:[A-Z]/A:[A-Z])',  # CVSS shorthand vector
        re.IGNORECASE
    )
    
    last_end = 0
    for match in url_pattern.finditer(text):
        # Add text before the match with markdown formatting
        if match.start() > last_end:
            segment = text[last_end:match.start()]
            add_markdown_runs(paragraph, segment, font_size=font_size)
        
        matched_text = match.group(0)
        url = matched_text
        
        # Convert patterns to full URLs
        if matched_text.upper().startswith('CWE-'):
            cwe_num = matched_text.split('-', 1)[1]
            url = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
        elif matched_text.upper().startswith('CVE-'):
            url = f"https://nvd.nist.gov/vuln/detail/{matched_text.upper()}"
        elif matched_text.upper().startswith('CVSS:'):
            # CVSS full vector string → FIRST calculator
            url = f"https://www.first.org/cvss/calculator/3.1#{matched_text}"
        elif re.match(r'AV:[A-Z]/AC:', matched_text, re.IGNORECASE):
            # CVSS shorthand vector → FIRST calculator with full prefix
            url = f"https://www.first.org/cvss/calculator/3.1#CVSS:3.1/{matched_text}"
        elif re.match(r'A\d{1,2}(?::20\d{2})?$', matched_text, re.IGNORECASE):
            # OWASP Top 10 reference (A01:2021, A9, etc.)
            owasp_match = re.match(r'A(\d{1,2})(?::(20\d{2}))?$', matched_text, re.IGNORECASE)
            if owasp_match:
                a_num = str(int(owasp_match.group(1)))  # "01" -> "1", "9" -> "9"
                year = owasp_match.group(2)
                
                if year == '2017' and a_num in OWASP_2017:
                    url = f"https://owasp.org/www-project-top-ten/2017/{OWASP_2017[a_num]}"
                elif (year is None or year == '2021') and a_num in OWASP_2021:
                    url = f"https://owasp.org/Top10/{OWASP_2021[a_num]}/"
                else:
                    # Unknown OWASP reference, don't hyperlink
                    add_markdown_runs(paragraph, matched_text, font_size=font_size)
                    last_end = match.end()
                    continue
        
        # Add hyperlink
        _add_hyperlink_run(paragraph, matched_text, url)
        last_end = match.end()
    
    # Add remaining text after last match with markdown formatting
    if last_end < len(text):
        add_markdown_runs(paragraph, text[last_end:], font_size=font_size)


def _tight(p) -> None:
    """Apply compact spacing to a programmatically-added content paragraph.

    Report prose should be tight — section heading styles control section
    spacing, but inline content (steps, bullets, code) should not inherit
    large gaps from the Normal paragraph defaults.
    """
    fmt = p.paragraph_format
    fmt.space_before = Pt(1)
    fmt.space_after = Pt(2)


def _render_markdown_content(doc, text: str) -> None:
    """Render markdown text into the document with block-level element support.

    Handles: ATX headings (# ## ###), bullet lists (- * +), numbered lists,
    fenced code blocks (```), and regular paragraphs. Inline formatting
    (**bold**, *italic*, `code`) and hyperlinks are handled by
    _add_text_with_hyperlinks for regular paragraphs and list items.

    Used for sections whose content is known to contain block-level markdown
    from LLM output (e.g. "Validation Guidance").
    """
    lines = text.split('\n')
    i = 0
    in_code_block = False
    code_lines: list[str] = []

    _HEADING_RE = re.compile(r'^(#{1,6})\s+(.*)')
    _BULLET_RE = re.compile(r'^[ \t]*[-*+]\s+(.*)')
    _NUMBERED_RE = re.compile(r'^[ \t]*\d+\.\s+(.*)')
    _CODE_FENCE_RE = re.compile(r'^[ \t]*```')

    while i < len(lines):
        line = lines[i]

        # ── Fenced code block ────────────────────────────────────────────────
        if _CODE_FENCE_RE.match(line):
            if not in_code_block:
                in_code_block = True
                code_lines = []
            else:
                in_code_block = False
                if code_lines:
                    try:
                        p = doc.add_paragraph(style='Code')
                        p.add_run('\n'.join(code_lines))
                    except Exception:
                        p = doc.add_paragraph()
                        run = p.add_run('\n'.join(code_lines))
                        run.font.name = 'Courier New'
                        run.font.size = Pt(9)
                    _tight(p)
                code_lines = []
            i += 1
            continue

        if in_code_block:
            code_lines.append(line)
            i += 1
            continue

        # ── ATX Heading ──────────────────────────────────────────────────────
        heading_match = _HEADING_RE.match(line)
        if heading_match:
            level = len(heading_match.group(1))
            heading_text = heading_match.group(2).strip()
            # Findings are H2/H3 so map # → H4, ## → H5, ### → H6
            word_level = min(level + 3, 6)
            try:
                p = doc.add_paragraph(style=f'Heading {word_level}')
                _add_text_with_hyperlinks(p, heading_text, font_size=Pt(13 - level))
            except Exception:
                p = doc.add_paragraph()
                run = p.add_run(heading_text)
                run.bold = True
                run.font.size = Pt(13 - level)
                _tight(p)
            i += 1
            continue

        # ── Bullet list item ─────────────────────────────────────────────────
        bullet_match = _BULLET_RE.match(line)
        if bullet_match:
            item_text = bullet_match.group(1)
            try:
                p = doc.add_paragraph(style='List Bullet')
            except Exception:
                try:
                    p = doc.add_paragraph(style='List Paragraph')
                except Exception:
                    p = doc.add_paragraph()
                item_text = f'\u2022  {item_text}'
            _tight(p)
            _add_text_with_hyperlinks(p, item_text, font_size=Pt(11))
            i += 1
            continue

        # ── Numbered list item ───────────────────────────────────────────────
        numbered_match = _NUMBERED_RE.match(line)
        if numbered_match:
            item_text = numbered_match.group(1)
            try:
                p = doc.add_paragraph(style='List Number')
            except Exception:
                try:
                    p = doc.add_paragraph(style='List Paragraph')
                except Exception:
                    p = doc.add_paragraph()
            _tight(p)
            _add_text_with_hyperlinks(p, item_text, font_size=Pt(11))
            i += 1
            continue

        # ── Empty line ───────────────────────────────────────────────────────
        if not line.strip():
            i += 1
            continue

        # ── Regular paragraph: collect contiguous non-block lines ────────────
        para_lines: list[str] = []
        while i < len(lines):
            l = lines[i]
            if (not l.strip()
                    or _CODE_FENCE_RE.match(l)
                    or _HEADING_RE.match(l)
                    or _BULLET_RE.match(l)
                    or _NUMBERED_RE.match(l)):
                break
            para_lines.append(l)
            i += 1
        if para_lines:
            p = doc.add_paragraph()
            _tight(p)
            _add_text_with_hyperlinks(p, '\n'.join(para_lines), font_size=Pt(11))

    # Flush an unclosed code block
    if in_code_block and code_lines:
        try:
            p = doc.add_paragraph(style='Code')
            p.add_run('\n'.join(code_lines))
        except Exception:
            p = doc.add_paragraph()
            run = p.add_run('\n'.join(code_lines))
            run.font.name = 'Courier New'
            run.font.size = Pt(9)
        _tight(p)


def _add_hyperlink_run(paragraph, text: str, url: str):
    """Add a hyperlink to a paragraph using low-level XML manipulation."""
    from docx.oxml.shared import OxmlElement
    from docx.oxml.ns import qn
    
    # Get the paragraph's parent document part to create relationship
    part = paragraph.part
    r_id = part.relate_to(url, 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink', is_external=True)
    
    # Create the hyperlink element
    hyperlink = OxmlElement('w:hyperlink')
    hyperlink.set(qn('r:id'), r_id)
    
    # Create a new run with the text
    new_run = OxmlElement('w:r')
    rPr = OxmlElement('w:rPr')
    
    # Style the hyperlink (blue, underlined)
    rStyle = OxmlElement('w:rStyle')
    rStyle.set(qn('w:val'), 'Hyperlink')
    rPr.append(rStyle)
    
    new_run.append(rPr)

    # Properly create a w:t text element (not .text on the run element)
    t_elem = OxmlElement('w:t')
    t_elem.set(qn('xml:space'), 'preserve')
    t_elem.text = text
    new_run.append(t_elem)

    hyperlink.append(new_run)
    
    # Add to paragraph
    paragraph._p.append(hyperlink)


def _add_finding_to_doc(doc: Document, title: str, data: Dict[str, str], locale: str | None = None) -> None:
    """Append a fully-formatted finding to the document body."""

    # Title as Heading 2 - use add_paragraph to ensure it's added at the end
    h = doc.add_paragraph(title, style='Heading 2')
    for run in h.runs:
        run.font.size = Pt(16)

    sev_canonical = canonicalize_severity(data.get("Severity") or data.get("severity"))
    if sev_canonical not in {"Critical", "High", "Medium", "Low", "Informational"}:
        sev_canonical = "Informational"
    sev_color = SEVERITY_COLORS.get(sev_canonical.lower(), RGBColor(0, 0, 0))
    sev_display = localize_severity_label(sev_canonical, locale)

    # Severity line
    p = doc.add_paragraph()
    run = p.add_run("Severity: ")
    run.bold = True
    run.font.size = Pt(11)
    run = p.add_run(sev_display)
    run.bold = True
    run.font.size = Pt(11)
    run.font.color.rgb = sev_color

    # Metadata table
    table_rows = []
    for key in _TABLE_KEYS:
        val = _to_str(data.get(key)).strip()
        if val:
            table_rows.append((key, val))
    if table_rows:
        table = doc.add_table(rows=len(table_rows), cols=2)
        table.style = "Table Grid"
        for i, (key, val) in enumerate(table_rows):
            display_val = val
            if key.lower() == "severity":
                display_val = localize_severity_label(sev_canonical, locale)
            row = table.rows[i]
            cell_key = row.cells[0]
            cell_val = row.cells[1]
            cell_key.text = key
            
            # For CVSS rows, try to link the entire value to the CVSS calculator
            if "cvss" in key.lower():
                cvss_vector_match = re.search(
                    r'(CVSS:3\.[01]/[A-Za-z0-9:/]+|AV:[A-Z]/AC:[A-Z]/PR:[A-Z]/UI:[A-Z]/S:[A-Z]/C:[A-Z]/I:[A-Z]/A:[A-Z])',
                    val, re.IGNORECASE
                )
                if cvss_vector_match:
                    vector = cvss_vector_match.group(1)
                    if not vector.upper().startswith('CVSS:'):
                        vector = f"CVSS:3.1/{vector}"
                    cvss_url = f"https://www.first.org/cvss/calculator/3.1#{vector}"
                    # Clear default paragraph and add entire value as hyperlink
                    cell_val.paragraphs[0].clear()
                    _add_hyperlink_run(cell_val.paragraphs[0], display_val, cvss_url)
                else:
                    _add_text_with_hyperlinks(cell_val.paragraphs[0], display_val)
            else:
                # Add value with hyperlink support for CWE, CVE, OWASP, URLs
                _add_text_with_hyperlinks(cell_val.paragraphs[0], display_val)
            
            for run in cell_key.paragraphs[0].runs:
                run.bold = True

    # Prose sections
    for section_key in _SECTION_ORDER:
        text = _to_str(data.get(section_key)).strip()
        if not text:
            continue
        sh = doc.add_paragraph(section_key, style='Heading 3')
        for run in sh.runs:
            run.font.size = Pt(14)
        if section_key == "Validation Guidance":
            _render_markdown_content(doc, text)
        else:
            for para_text in text.split("\n\n"):
                para_text = para_text.strip()
                if para_text:
                    p = doc.add_paragraph()
                    # Add text with hyperlink detection + markdown formatting
                    _add_text_with_hyperlinks(p, para_text, font_size=Pt(11))

    # Any remaining keys not covered above
    covered = set(_SECTION_ORDER) | set(_TABLE_KEYS) | {"Finding Title", "title", "Title", "severity", "Summary"}
    for key, val in data.items():
        if key in covered or not val or not _to_str(val).strip():
            continue
        sh = doc.add_paragraph(key, style='Heading 4')
        for run in sh.runs:
            run.font.size = Pt(12)
        val_text = _to_str(val).strip()
        for para_text in val_text.split("\n\n"):
            para_text = para_text.strip()
            if para_text:
                p = doc.add_paragraph()
                _add_text_with_hyperlinks(p, para_text, font_size=Pt(11))

    # Blank separator between findings
    doc.add_paragraph("")


def _group_findings(findings: list) -> Dict[str, list]:
    """Group findings by severity. Each item is (title, data_dict)."""
    grouped: Dict[str, list] = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "informational": [],
    }
    for f in findings:
        if isinstance(f, dict) and "_title" in f:
            title = f.get("_title", "")
            data = _normalize_finding(f.get("_content", f))
        elif isinstance(f, dict):
            data = f
            title = _to_str(data.get("Finding Title") or data.get("title") or data.get("Title")).strip() or "Untitled Finding"
        else:
            data = _normalize_finding(f)
            title = _to_str(data.get("Finding Title") or data.get("title") or data.get("Title")).strip() or "Untitled Finding"
        sev = _extract_severity(data)
        grouped.setdefault(sev, []).append((title, data))
    return grouped


# ── Main builder ────────────────────────────────────────────────────────────

def build_master_docx(
    template_bytes: bytes,
    *,
    report_name: str,
    client_name: str = "",
    team_name: str = "",
    company_name: str = "",
    department_name: str = "",
    author_name: str,
    author_email: str,
    author_phone: str = "",
    author_title: str = "",
    findings: List[Dict[str, str]],
    summaries: Dict[str, str] | None = None,
    locale: str | None = None,
) -> bytes:
    """Build master DOCX report using docxtpl templating engine.
    
    Template uses Jinja2 syntax: {{ TOKEN }} with spaces.
    Findings are inserted after their placeholder markers using custom formatting.
    """
    grouped = _group_findings(findings)
    now = datetime.now(timezone.utc)
    
    log.info(f"Building master DOCX with docxtpl: year={now.year}, company={company_name}, author={author_name}")

    # Step 1: Render template with docxtpl
    try:
        tpl = DocxTemplate(io.BytesIO(template_bytes))
    except BadZipFile:
        raise ValueError("Template file is corrupted or not a valid DOCX file")
    except Exception as e:
        raise ValueError(f"Failed to load template: {str(e)}")
    
    # Extract summary text separately so we can post-process markdown after rendering
    _summary_data = {
        "EXECUTIVE": (summaries or {}).get("SUMMARY_EXECUTIVE", "").strip(),
        "TECHNICAL": (summaries or {}).get("SUMMARY_TECHNICAL", "").strip(),
        "RECOMMENDATIONS": (summaries or {}).get("SUMMARY_RECOMMENDATIONS", "").strip(),
    }
    # Markers must be unique strings unlikely to appear in template prose
    _SUMMARY_MARKER = "LZPT_SUM_{key}_MARKER"

    context = {
        # App / client (client_name is now the application name for template compat)
        "APP_NAME": client_name or report_name,
        "CLIENT_NAME": client_name or "",
        "TEAM_NAME": team_name or "",
        "REPORT_NAME": report_name or "",
        # Company / org
        "MY_COMPANY_NAME": company_name or "",
        "COMPANY_NAME": company_name or "",
        "MY_COMPANY_DEPARTMENT": department_name or "",
        "MY_COMPANY_DAPRTMETN": department_name or "",  # handle typo in template
        "DEPARTMENT_NAME": department_name or "",
        # Author
        "AUTHOR": author_name or "",
        "AUTHOR_NAME": author_name or "",
        "AUTHOR_EMAIL": author_email or "",
        "AUTH_EMAIL": author_email or "",  # handle typo in template
        "MY_EMAIL": author_email or "",
        "AUTHOR_PHONE": author_phone or "",
        "MY_PHONE": author_phone or "",
        "AUTHOR_TITLE": author_title or "",
        "MY_TITLE": author_title or "",
        # Dates
        "DATE": now.strftime("%Y-%m-%d"),
        "YEAR": str(now.year),
        "MONTH": now.strftime("%B"),  # "February"
        "MONTH_YEAR": now.strftime("%B %Y"),  # "February 2026"
        # Summaries: use markers; markdown content inserted in Step 2.5
        "SUMMARY_EXECUTIVE": _SUMMARY_MARKER.format(key="EXECUTIVE") if _summary_data["EXECUTIVE"] else "",
        "SUMMARY_TECHNICAL": _SUMMARY_MARKER.format(key="TECHNICAL") if _summary_data["TECHNICAL"] else "",
        "SUMMMARY_TECHNICAL": _SUMMARY_MARKER.format(key="TECHNICAL") if _summary_data["TECHNICAL"] else "",  # handle typo in template
        "SUMMARY_RECOMMENDATIONS": _SUMMARY_MARKER.format(key="RECOMMENDATIONS") if _summary_data["RECOMMENDATIONS"] else "",
        # Findings placeholders (text markers; formatted findings inserted after these)
        "FINDINGS_CRITICAL": f"[{len(grouped['critical'])} critical finding(s)]" if grouped["critical"] else "No critical findings.",
        "FINDINGS_HIGH": f"[{len(grouped['high'])} high finding(s)]" if grouped["high"] else "No high findings.",
        "FINDINGS_MEDIUM": f"[{len(grouped['medium'])} medium finding(s)]" if grouped["medium"] else "No medium findings.",
        "FINDINGS_LOW": f"[{len(grouped['low'])} low finding(s)]" if grouped["low"] else "No low findings.",
        "FINDINGS_INFORMATIONAL": f"[{len(grouped['informational'])} informational finding(s)]" if grouped["informational"] else "No informational findings.",
        "FINDINGS_INFORMATION": f"[{len(grouped['informational'])} informational finding(s)]" if grouped["informational"] else "No informational findings.",  # handle typo in template
        # Misc
        "TABLE_OF_CONTENTS": "",
        "MY_COMPANY_LOGO": "",
    }
    
    try:
        tpl.render(context)
    except Exception as e:
        raise ValueError(f"Failed to render template: {str(e)}")
    
    # Step 2: Access the underlying python-docx Document (no save/reload needed)
    doc = tpl.docx

    # Step 2.1: docxtpl does not substitute tokens in first-page or even-page
    # headers/footers. Do a manual pass over those variants now.
    _TOKEN_RE = re.compile(r'\{\{\s*(\w+)\s*\}\}')

    def _substitute_missed_hf(hf):
        if hf is None:
            return
        for p in hf.paragraphs:
            for run in p.runs:
                def _replace(m):
                    return str(context.get(m.group(1), m.group(0)))
                run.text = _TOKEN_RE.sub(_replace, run.text)

    for section in doc.sections:
        for hf in (section.first_page_header, section.first_page_footer,
                   section.even_page_header, section.even_page_footer):
            _substitute_missed_hf(hf)

    # Step 2.5: Replace summary markers with markdown-formatted content
    for key, text in _summary_data.items():
        if not text:
            continue
        marker = _SUMMARY_MARKER.format(key=key)
        found = False
        for p in _iter_all_paragraphs(doc):
            if marker in p.text:
                for run in p.runs:
                    if marker in run.text:
                        run.text = run.text.replace(marker, "", 1)
                if not p.runs:
                    p.text = p.text.replace(marker, "", 1)
                _insert_markdown_after_paragraph(doc, p, text)
                found = True
                break
        if not found:
            log.warning("Summary marker %s not found in template", marker)

    # Step 3: Insert formatted findings after their placeholder paragraphs
    for sev_key in ("critical", "high", "medium", "low", "informational"):
        marker = context[f"FINDINGS_{sev_key.upper()}"]
        items = grouped[sev_key]
        if not items:
            continue
        # HIGH-13/14 fix: Iterate over all paragraphs including tables, headers, footers
        found = False
        for p in _iter_all_paragraphs(doc):
            if marker in p.text:
                # Replace only the marker text (preserve other placeholders in same paragraph)
                for run in p.runs:
                    if marker in run.text:
                        run.text = run.text.replace(marker, "", 1)
                if not p.runs:
                    p.text = p.text.replace(marker, "", 1)
                _insert_findings_after_paragraph(doc, p, items, locale=locale)
                found = True
                break
        
        if not found:
            log.warning(f"Placeholder {marker} not found in document (checked body, tables, headers, footers)")

    # Step 4: Save final document to bytes
    # Use the docx object's save to preserve media after modifications
    final_buf = io.BytesIO()
    doc.save(final_buf)
    return final_buf.getvalue()


def _insert_markdown_after_paragraph(doc: Document, target_para, text: str) -> None:
    """Insert markdown-formatted content immediately after target_para.

    Uses the same record-append-move pattern as _insert_findings_after_paragraph
    to ensure content lands in the right position rather than at the end of the doc.
    """
    body = doc.element.body
    existing_elements = set(body)

    _render_markdown_content(doc, text)

    new_elements = [
        elem for elem in body
        if elem not in existing_elements
        and not (elem.tag.endswith('}sectPr') or 'sectPr' in elem.tag)
    ]
    if not new_elements:
        return

    for elem in new_elements:
        body.remove(elem)

    insert_after = target_para._element
    for elem in new_elements:
        insert_after.addnext(elem)
        insert_after = elem


def _insert_findings_after_paragraph(doc: Document, target_para, items: list, locale: str | None = None) -> None:
    """Insert formatted finding paragraphs immediately after target_para.

    Adds findings to the SAME document (to preserve relationships), then
    moves the generated elements from the end of the body to just after
    the target paragraph.
    """
    if not items:
        return
    
    # Record existing elements
    body = doc.element.body
    existing_elements = set(body)

    # Add findings to the end of THIS document
    for title, data in items:
        _add_finding_to_doc(doc, title, data, locale=locale)

    # Collect NEW elements (ones that weren't in existing_elements)
    # Skip sectPr which is always present
    new_elements = []
    for elem in body:
        if elem not in existing_elements:
            # Skip sectPr (section properties)
            if elem.tag.endswith('}sectPr') or 'sectPr' in elem.tag:
                continue
            new_elements.append(elem)
    
    if not new_elements:
        return  # Nothing to move
    
    # Remove all new elements from their current positions
    for elem in new_elements:
        body.remove(elem)
    
    # Insert them after the target paragraph, maintaining order
    target_elem = target_para._element
    insert_after = target_elem
    
    for elem in new_elements:
        insert_after.addnext(elem)
        insert_after = elem  # Update for next insertion


def parse_severity_criteria_markdown() -> Dict[str, str]:
    """
    Parse severity criteria from templates/severity_criteria.md.
    Returns dict: {"Critical": "definition", "High": "definition", ...}
    """
    try:
        criteria_path = Path(__file__).resolve().parent.parent.parent / "templates" / "severity_criteria.md"
        content = criteria_path.read_text(encoding='utf-8')

        criteria = {}
        lines = content.split('\n')
        current_level = None
        current_definition = []

        for line in lines:
            # Look for level headers like "## Critical"
            if line.startswith('## '):
                # Save previous level if any
                if current_level and current_definition:
                    criteria[current_level] = '\n'.join(current_definition).strip()
                    current_definition = []

                # Extract new level
                level = line.replace('## ', '').strip()
                if level in ('Critical', 'High', 'Medium', 'Low', 'Informational'):
                    current_level = level
            elif current_level and line.strip():
                # Accumulate definition lines
                current_definition.append(line)

        # Save last level
        if current_level and current_definition:
            criteria[current_level] = '\n'.join(current_definition).strip()

        # Validate we got all 5 levels
        required = {'Critical', 'High', 'Medium', 'Low', 'Informational'}
        if set(criteria.keys()) != required:
            missing = required - set(criteria.keys())
            log.warning(f"Severity criteria missing levels: {missing}")
            return {}

        return criteria
    except Exception as e:
        log.exception(f"Failed to parse severity_criteria.md: {e}")
        return {}
