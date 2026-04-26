from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Dict

# Canonical backend severities (storage/logic contract)
_CANONICAL = ("Critical", "High", "Medium", "Low", "Informational")


def canonicalize_severity(severity: str | None) -> str:
    raw = str(severity or "").strip()
    if not raw:
        return ""
    lowered = raw.lower()
    if lowered == "information":
        return "Informational"
    for c in _CANONICAL:
        if lowered == c.lower():
            return c
    return raw


def _frontend_locales_dir() -> Path:
    # repo_root/app/services/severity_localization.py -> repo_root
    return Path(__file__).resolve().parents[2] / "frontend" / "src" / "i18n" / "locales"


@lru_cache(maxsize=16)
def _load_from_frontend_locale(locale: str) -> Dict[str, str]:
    """
    Source-of-truth mapping from frontend i18n JSON:
    trends.severityOptions.{critical,high,medium,low,informational}
    """
    path = _frontend_locales_dir() / f"{locale}.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        so = (
            data.get("trends", {})
            .get("severityOptions", {})
        )
        if not isinstance(so, dict):
            return {}
        return {
            "Critical": str(so.get("critical", "")).strip(),
            "High": str(so.get("high", "")).strip(),
            "Medium": str(so.get("medium", "")).strip(),
            "Low": str(so.get("low", "")).strip(),
            "Informational": str(so.get("informational", "")).strip(),
        }
    except Exception:
        return {}


def _is_safe_locale(locale: str) -> bool:
    return "/" not in locale and "\\" not in locale and ".." not in locale


def _locale_candidates(locale: str | None) -> list[str]:
    raw = (locale or "").strip()
    if not raw or not _is_safe_locale(raw):
        return ["en"]
    candidates = [raw]
    base = raw.split("-", 1)[0].split("_", 1)[0].strip()
    if base and base != raw:
        candidates.append(base)
    if "en" not in candidates:
        candidates.append("en")
    return candidates


def localize_severity_label(severity: str | None, locale: str | None) -> str:
    """
    Presentation-only severity localization.
    Falls back to English canonical labels for unknown/missing locale.
    """
    canonical = canonicalize_severity(severity)
    if not canonical:
        return ""

    for loc in _locale_candidates(locale):
        labels = _load_from_frontend_locale(loc)
        if labels:
            return labels.get(canonical) or canonical
    return canonical
