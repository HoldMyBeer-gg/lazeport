"""
Extract section headings from a template string (Markdown or HTML).
Used by structurer and docx_builder to get section order and names.
"""
import re


_OPEN_TAG_RE = {
    tag: re.compile(rf"<{tag}[^<>]*>", re.IGNORECASE) for tag in ("table", "tr")
}


def _iter_elements(html: str, tag: str):
    """
    Yield the inner HTML of each <tag ...>...</tag> in document order, in linear time.

    Replaces `<tag[^<>]*>(.*?)</tag>` regexes, which rescan to end-of-input for
    every unclosed opening tag (CodeQL py/polynomial-redos on admin templates).
    """
    open_re = _OPEN_TAG_RE[tag]
    close_tag = f"</{tag}>"
    lower = html.lower()
    pos = 0
    while True:
        m = open_re.search(html, pos)
        if not m:
            return
        close = lower.find(close_tag, m.end())
        if close < 0:
            return
        yield html[m.end():close]
        pos = close + len(close_tag)


def _headings_from_markdown(text: str) -> list[str]:
    """Extract headings from Markdown (# or ## etc.)."""
    keys = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("#"):
            heading = re.sub(r"^#+\s*", "", line).strip()
            if heading:
                keys.append(heading)
    return keys


def _headings_from_html(text: str) -> list[str]:
    """Extract section headings from HTML: h1–h4, then <b>...</b> / <strong>...</strong>, in document order."""
    keys = []
    seen = set()
    # h1–h4 in order (case-insensitive)
    for m in re.finditer(r"<h([1-4])[^<>]*>([^<]+)</h\1>", text, re.IGNORECASE):
        title = m.group(2).strip()
        if title and title not in seen:
            keys.append(title)
            seen.add(title)
    # <b> and <strong> in order
    for m in re.finditer(r"<(?:b|strong)[^<>]*>([^<]+)</(?:b|strong)>", text, re.IGNORECASE):
        title = m.group(1).strip()
        if title and title not in seen:
            keys.append(title)
            seen.add(title)
    return keys


def template_to_section_keys(template: str) -> list[str]:
    """
    Extract section headings in order. Detects HTML vs Markdown:
    - If template contains angle brackets and looks like HTML, parse as HTML.
    - Otherwise parse as Markdown.
    """
    template = (template or "").strip()
    if not template:
        return ["Summary", "Details", "Remediation", "References"]
    looks_like_html = "<" in template and ("</" in template or "<h" in template.lower() or "<b>" in template.lower() or "<strong>" in template.lower())
    if looks_like_html:
        keys = _headings_from_html(template)
    else:
        keys = _headings_from_markdown(template)
    return keys if keys else ["Summary", "Details", "Remediation", "References"]


def template_table_rows(template: str) -> tuple[str | None, list[str]]:
    """
    If template has a <table>, return (heading_after_which_to_insert, row_labels).
    Row labels are the first <td> of each <tr>. Insert-after is the last heading
    that appears before <table> in the template. Else return (None, []).
    """
    template = (template or "").strip()
    if "<table" not in template.lower():
        return (None, [])
    # Find first table
    table_body = next(_iter_elements(template, "table"), None)
    if table_body is None:
        return (None, [])
    row_labels = []
    for row_html in _iter_elements(table_body, "tr"):
        td_match = re.search(r"<td[^<>]*>([^<]*(?:<[^/<>][^<>]*>[^<]*)*)</td>", row_html, re.IGNORECASE)
        if td_match:
            label = re.sub(r"<[^<>]+>", "", td_match.group(1)).strip()
            if label:
                row_labels.append(label)
    if not row_labels:
        return (None, [])
    # Insert after the last heading that appears before <table> in template
    head_pos = template.lower().find("<table")
    before = template[:head_pos]
    last_heading = None
    for m in re.finditer(r"<(?:b|strong|h[1-4])[^<>]*>([^<]+)</(?:b|strong|h[1-4])>", before, re.IGNORECASE):
        last_heading = m.group(1).strip()
    return (last_heading, row_labels)


def template_all_table_row_labels(template: str) -> list[str]:
    """
    Extract row labels from every <table> in the template, in document order.
    Each row label is the first <td> of each <tr>. Used so section_keys
    include all table rows (e.g. first table: Severity, CVSS...; second table: Raw HTTP Request, Raw HTTP Response).
    """
    template = (template or "").strip()
    if "<table" not in template.lower():
        return []
    out = []
    for table_body in _iter_elements(template, "table"):
        for row_html in _iter_elements(table_body, "tr"):
            td_match = re.search(r"<td[^<>]*>([^<]*(?:<[^/<>][^<>]*>[^<]*)*)</td>", row_html, re.IGNORECASE)
            if td_match:
                label = re.sub(r"<[^<>]+>", "", td_match.group(1)).strip()
                if label:
                    out.append(label)
    return out
