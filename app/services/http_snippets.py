from __future__ import annotations

import re
from typing import Dict, List

REQUEST_LINE_RE = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+\S+\s+HTTP/\d\.\d", re.I)
RESPONSE_LINE_RE = re.compile(r"^HTTP/\d\.\d\s+\d{3}\b", re.I)


def extract_http_snippets(notes: str, max_snippets: int = 6, max_chars: int = 4000) -> List[Dict[str, str]]:
    """Extract raw HTTP request/response blocks from notes."""
    if not notes:
        return []
    lines = notes.splitlines()
    snippets: List[Dict[str, str]] = []
    i = 0
    while i < len(lines) and len(snippets) < max_snippets:
        line = lines[i].strip()
        kind = None
        if REQUEST_LINE_RE.match(line):
            kind = "request"
        elif RESPONSE_LINE_RE.match(line):
            kind = "response"
        if not kind:
            i += 1
            continue
        start = i
        i += 1
        while i < len(lines):
            next_line = lines[i].strip()
            if REQUEST_LINE_RE.match(next_line) or RESPONSE_LINE_RE.match(next_line):
                break
            i += 1
        block = "\n".join(lines[start:i]).strip()
        if block:
            if len(block) > max_chars:
                block = block[: max_chars - 3].rstrip() + "..."
            snippets.append({"type": kind, "text": block})
    return snippets
