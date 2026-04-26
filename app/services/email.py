"""
Email utilities for notifications.
"""
from __future__ import annotations

import json
import logging
import smtplib
from email.message import EmailMessage

from app.config import settings
from app.db.adapter import StorageAdapter
from app.services.crypto import decrypt_text

log = logging.getLogger("lazeport.email")


def _get_smtp_config(overrides: dict | None = None) -> dict:
    base = {
        "host": settings.smtp_host,
        "port": settings.smtp_port,
        "username": settings.smtp_username,
        "password": settings.smtp_password,
        "from": settings.smtp_from,
        "use_tls": settings.smtp_use_tls,
    }
    if overrides:
        base.update({k: v for k, v in overrides.items() if v is not None})
    return base


def send_email(to_email: str, subject: str, body: str, smtp_overrides: dict | None = None) -> bool:
    """Send a plain-text email. Returns True on success."""
    smtp = _get_smtp_config(smtp_overrides)
    if not smtp.get("host") or not smtp.get("from"):
        log.warning("SMTP not configured; skipping email to %s", to_email)
        return False

    msg = EmailMessage()
    msg["From"] = smtp["from"]
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        with smtplib.SMTP(smtp["host"], smtp.get("port", 587), timeout=10) as server:
            if smtp.get("use_tls"):
                server.starttls()
            if smtp.get("username"):
                server.login(smtp.get("username"), smtp.get("password", ""))
            server.send_message(msg)
        return True
    except Exception as exc:
        log.warning("Failed to send email to %s: %s", to_email, exc)
        return False


def send_org_email(
    adapter: StorageAdapter,
    org_id: str,
    to_email: str,
    subject: str,
    body: str,
) -> bool:
    org = adapter.get_organization(org_id)
    settings_json = org.settings if org and org.settings else "{}"
    try:
        org_settings = json.loads(settings_json)
    except Exception:
        org_settings = {}

    smtp_password = org_settings.get("smtp_password")
    if smtp_password:
        try:
            smtp_password = decrypt_text(smtp_password)
        except Exception:
            smtp_password = None

    overrides = {
        "host": org_settings.get("smtp_host"),
        "port": org_settings.get("smtp_port"),
        "username": org_settings.get("smtp_username"),
        "password": smtp_password,
        "from": org_settings.get("smtp_from"),
        "use_tls": org_settings.get("smtp_use_tls"),
    }
    return send_email(to_email, subject, body, overrides)
