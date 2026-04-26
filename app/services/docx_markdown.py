"""Markdown-to-DOCX run rendering. Parses lightweight markdown inline formatting into python-docx runs: **bold**, *italic*, ***bold italic***, `code`, single newlines become Word line breaks. Used by docx_builder and master_docx so all DOCX export paths render markdown consistently."""
from __future__ import annotations

import re
from typing import Callable

from docx.shared import Pt

# Regex that splits text into markdown tokens.
# Order matters: longest patterns first (*** before ** before *).
# Groups: (1) bold-italic, (2) bold, (3) italic, (4) code, (5) newline, (6) plain text
_MD_TOKEN_RE = re.compile(
    r"(\*{3}(?=\S)(.+?)(?<=\S)\*{3})"   # ***bold italic***
    r"|(\*{2}(?=\S)(.+?)(?<=\S)\*{2})"  # **bold**
    r"|(__(?=\S)(.+?)(?<=\S)__)"          # __bold__
    r"|(\*(?=\S)(.+?)(?<=\S)\*)"          # *italic*
    r"|(_(?=\S)(.+?)(?<=\S)_)"            # _italic_ (but not __bold__)
    r"|(`([^`]+?)`)"                       # `code`
    r"|(\n)"                               # newline
)


def _parse_md_tokens(text: str) -> list[dict]:
    """Parse text into a list of token dicts with type and content."""
    tokens: list[dict] = []
    pos = 0
    for m in _MD_TOKEN_RE.finditer(text):
        # Plain text before this match
        if m.start() > pos:
            tokens.append({"type": "text", "text": text[pos:m.start()]})

        full = m.group(0)
        if full.startswith("***"):
            inner = m.group(2)
            tokens.append({"type": "bold_italic", "text": inner})
        elif full.startswith("**"):
            inner = m.group(4)
            tokens.append({"type": "bold", "text": inner})
        elif full.startswith("__"):
            inner = m.group(6)
            tokens.append({"type": "bold", "text": inner})
        elif full.startswith("*"):
            inner = m.group(8)
            tokens.append({"type": "italic", "text": inner})
        elif full.startswith("_") and not full.startswith("__"):
            inner = m.group(10)
            tokens.append({"type": "italic", "text": inner})
        elif full.startswith("`"):
            inner = m.group(12)
            tokens.append({"type": "code", "text": inner})
        elif full == "\n":
            tokens.append({"type": "break"})

        pos = m.end()

    # Remaining text after last match
    if pos < len(text):
        tokens.append({"type": "text", "text": text[pos:]})

    return tokens


def add_markdown_runs(
    paragraph,
    text: str,
    font_name: str = "Tahoma",
    font_size: Pt | None = None,
    extra_run_handler: Callable | None = None,
) -> None:
    """
    Add runs to a python-docx paragraph, interpreting markdown inline formatting.

    Args:
        paragraph: A python-docx Paragraph object.
        text: The source text, possibly containing markdown.
        font_name: Font to apply to all runs.
        font_size: Optional font size for all runs.
        extra_run_handler: Optional callback(run, token_dict) for additional
                          run styling (e.g. severity coloring).  Called for
                          every run *after* markdown formatting is applied.
    """
    if not text:
        return

    tokens = _parse_md_tokens(text)
    for token in tokens:
        ttype = token["type"]

        if ttype == "break":
            # Add a line break (soft return) in the current paragraph
            run = paragraph.add_run()
            run.add_break()
            if font_name:
                run.font.name = font_name
            continue

        content = token.get("text", "")
        if not content:
            continue

        run = paragraph.add_run(content)
        if font_name:
            run.font.name = font_name
        if font_size:
            run.font.size = font_size

        if ttype == "bold":
            run.font.bold = True
        elif ttype == "italic":
            run.font.italic = True
        elif ttype == "bold_italic":
            run.font.bold = True
            run.font.italic = True
        elif ttype == "code":
            run.font.name = "Courier New"
            run.font.size = font_size or Pt(9)

        if extra_run_handler:
            extra_run_handler(run, token)


def strip_markdown(text: str) -> str:
    """Strip markdown formatting from text, returning plain text.
    
    Useful for contexts where you need the raw text without formatting
    (e.g. text extraction, comparisons).
    """
    if not text:
        return text
    # Remove bold/italic markers
    text = re.sub(r'\*{3}(.+?)\*{3}', r'\1', text)
    text = re.sub(r'\*{2}(.+?)\*{2}', r'\1', text)
    text = re.sub(r'__(.+?)__', r'\1', text)
    text = re.sub(r'\*(.+?)\*', r'\1', text)
    text = re.sub(r'_(.+?)_', r'\1', text)
    text = re.sub(r'`(.+?)`', r'\1', text)
    return text
