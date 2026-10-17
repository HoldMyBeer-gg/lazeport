"""Regex inputs under attacker control must stay linear-time (CodeQL py/polynomial-redos)."""
import time

import pytest

from app.services.evidence_schema import _extract_locations_from_text, MAX_LOCATION_SCAN_CHARS
from app.services.template_parse import (
    template_all_table_row_labels,
    template_table_rows,
    template_to_section_keys,
)

BUDGET_SECONDS = 1.0


def _timed(fn, *args):
    t0 = time.perf_counter()
    out = fn(*args)
    return out, time.perf_counter() - t0


class TestEvidenceLocationExtraction:
    def test_still_extracts_the_supported_shapes(self):
        text = (
            "see app/api/auth.py:848 and /etc/nginx/nginx.conf:12, "
            "also ../lib/util.js line 7, src/Main.java (line 99), "
            "and README.md ln 3 plus weird.tar.gz:5"
        )
        locs = {(l.file, l.line) for l in _extract_locations_from_text(text)}
        assert ("app/api/auth.py", 848) in locs
        assert ("/etc/nginx/nginx.conf", 12) in locs
        assert ("../lib/util.js", 7) in locs
        assert ("src/Main.java", 99) in locs
        assert ("README.md", 3) in locs
        assert ("weird.tar.gz", 5) in locs

    def test_no_false_positive_on_plain_prose(self):
        assert _extract_locations_from_text("The server responded in 200 ms. No issue.") == []

    @pytest.mark.parametrize("payload", [
        "a." * 50_000,                 # long dotted token, no terminator
        "a/" * 50_000 + "x",           # long slashed token
        "-" * 100_000,                 # all separators
        ("a.b" * 20_000) + " line ",   # pattern 2 prefix without digits
        ("a.b" * 20_000) + " (line ",  # pattern 3 prefix without digits
    ])
    def test_adversarial_input_is_fast(self, payload):
        _, elapsed = _timed(_extract_locations_from_text, payload)
        assert elapsed < BUDGET_SECONDS, f"took {elapsed:.2f}s"

    def test_oversized_notes_are_truncated_not_scanned(self):
        text = "x" * (MAX_LOCATION_SCAN_CHARS + 10) + " tail.py:1"
        assert _extract_locations_from_text(text) == []

    def test_empty_and_none_safe(self):
        assert _extract_locations_from_text("") == []
        assert _extract_locations_from_text(None) == []


class TestTemplateParse:
    def test_behaviour_unchanged_on_normal_template(self):
        tpl = (
            "<h2>Description</h2><p>x</p><b>Impact</b>"
            "<table><tr><td><b>Severity</b></td><td>High</td></tr><tr><td>CVSS</td><td>9</td></tr></table>"
            "<h3>Remediation</h3>"
        )
        # Expected values were captured from the pre-change implementation so
        # the regex rewrite is verified to be behaviour-preserving.
        assert template_to_section_keys(tpl) == ["Description", "Remediation", "Impact", "Severity"]
        assert template_table_rows(tpl) == ("Impact", ["High", "CVSS"])
        assert template_all_table_row_labels(tpl) == ["High", "CVSS"]

    @pytest.mark.parametrize("payload", [
        "<h1 " * 30_000,                               # unterminated heading tags
        "<b " * 30_000,                                # unterminated bold tags
        "<table><tr><td>" + "<a " * 30_000,            # unterminated inner tags in a cell
        "<table>" * 5_000,                             # many table opens, no close
    ])
    def test_adversarial_input_is_fast(self, payload):
        for fn in (template_to_section_keys, template_table_rows, template_all_table_row_labels):
            _, elapsed = _timed(fn, payload)
            assert elapsed < BUDGET_SECONDS, f"{fn.__name__} took {elapsed:.2f}s"
