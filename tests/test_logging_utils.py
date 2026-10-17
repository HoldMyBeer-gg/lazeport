"""Log injection guard: newlines/control chars in user-controlled values never forge log lines."""
import io
import logging

from app.logging_utils import ScrubFilter, install_log_scrubbing, scrub_log_text


def _capture_logger(name):
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    logger = logging.getLogger(name)
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    install_log_scrubbing(logger)
    return logger, stream


def test_scrub_log_text_escapes_newlines_and_controls():
    assert scrub_log_text("a\nb") == "a\\nb"
    assert scrub_log_text("a\r\nb") == "a\\r\\nb"
    assert scrub_log_text("a\rb") == "a\\rb"
    assert scrub_log_text("a\x1b[31mb\x00") == "a\\x1b[31mb\\x00"
    assert scrub_log_text("tab\tkept") == "tab\tkept"
    assert scrub_log_text("") == ""
    assert scrub_log_text(None) is None


def test_injected_newline_in_args_stays_on_one_line():
    logger, stream = _capture_logger("test.scrub.args")
    logger.warning("login failed for %s", "bob@example.com\nINFO login ok for admin")
    out = stream.getvalue()
    assert out.count("\n") == 1
    assert "bob@example.com\\nINFO login ok for admin" in out


def test_injected_newline_in_preformatted_message_is_scrubbed():
    logger, stream = _capture_logger("test.scrub.msg")
    evil = "x\nFORGED"
    logger.info(f"value: {evil}")
    assert stream.getvalue() == "INFO value: x\\nFORGED\n"


def test_dict_args_are_scrubbed():
    logger, stream = _capture_logger("test.scrub.dict")
    logger.info("user=%(user)s n=%(n)d", {"user": "a\nb", "n": 3})
    assert stream.getvalue() == "INFO user=a\\nb n=3\n"


def test_tracebacks_keep_their_newlines():
    logger, stream = _capture_logger("test.scrub.exc")
    try:
        raise ValueError("boom\nline2")
    except ValueError:
        logger.exception("failed for %s", "u\nv")
    out = stream.getvalue()
    assert out.startswith("ERROR failed for u\\nv\n")
    assert "Traceback (most recent call last)" in out
    assert out.count("\n") > 2


def test_install_is_idempotent():
    logger, _ = _capture_logger("test.scrub.idem")
    install_log_scrubbing(logger)
    install_log_scrubbing(logger)
    handler = logger.handlers[0]
    assert sum(isinstance(f, ScrubFilter) for f in handler.filters) == 1


def test_install_defaults_to_root_logger():
    # Under pytest the root handlers are pytest's own, so we can't rely on the
    # basicConfig handler from app.main being present; verify the no-arg call
    # (what app.main uses) covers whatever handlers root currently has.
    root = logging.getLogger()
    extra = logging.StreamHandler(io.StringIO())
    root.addHandler(extra)
    try:
        install_log_scrubbing()
        assert all(any(isinstance(f, ScrubFilter) for f in h.filters) for h in root.handlers)
    finally:
        root.removeHandler(extra)
