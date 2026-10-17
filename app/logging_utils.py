"""
Log hygiene: keep user-controlled values from forging log entries.

Anything a user types (emails, finding titles, model names, task ids) can end
up interpolated into a log line. A value containing a newline would let them
inject a fake log record. ``ScrubFilter`` neutralizes CR/LF and other control
characters in the message and its arguments before any formatter sees them,
while leaving exception tracebacks untouched.
"""
import logging
import re
from typing import Optional

# Everything in C0 except tab, plus DEL. Newlines are handled separately so
# they render as a readable literal "\n" rather than "\x0a".
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def scrub_log_text(text: str) -> str:
    """Return ``text`` with CR/LF and control characters replaced by visible escapes."""
    if not text:
        return text
    text = text.replace("\r\n", "\\r\\n").replace("\r", "\\r").replace("\n", "\\n")
    return _CONTROL_CHARS.sub(lambda m: f"\\x{ord(m.group()):02x}", text)


class ScrubFilter(logging.Filter):
    """Logging filter that scrubs ``record.msg`` and string ``record.args`` in place."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = scrub_log_text(record.msg)
        args = record.args
        if isinstance(args, dict):
            record.args = {k: scrub_log_text(v) if isinstance(v, str) else v for k, v in args.items()}
        elif isinstance(args, tuple):
            record.args = tuple(scrub_log_text(a) if isinstance(a, str) else a for a in args)
        return True


_FILTER = ScrubFilter()


def install_log_scrubbing(logger: Optional[logging.Logger] = None) -> None:
    """
    Attach the scrub filter to every handler on ``logger`` (default: root).

    Idempotent. Handler-level filters run for every record the handler emits,
    including records propagated from child loggers, so attaching to the root
    handlers covers the whole application.
    """
    logger = logger or logging.getLogger()
    for handler in logger.handlers:
        if _FILTER not in handler.filters:
            handler.addFilter(_FILTER)
