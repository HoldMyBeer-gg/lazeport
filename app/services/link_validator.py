"""Validate URLs before using them as hyperlinks: must return 200 and not be a not-found page. Cached with TTL - longer for canonical CVE/CWE/OWASP domains, shorter for others."""
import re
import threading
import time
from urllib.parse import urlparse

import httpx

URL_RE = re.compile(
    r"https?://[^\s<>\"')\]]+",
    re.IGNORECASE,
)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
CWE_RE = re.compile(r"\bCWE-\d{1,5}\b", re.IGNORECASE)
OWASP_RE = re.compile(r"\bA([0-9]{1,2})(?::(20\d{2}))?\b", re.IGNORECASE)
NOT_FOUND_RE = re.compile(
    r"not\s+found|404|page\s+not\s+found|document\s+not\s+found",
    re.IGNORECASE,
)
TIMEOUT = 4.0
MAX_BODY_SAMPLE = 4000
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
CANONICAL_DOMAINS = {"nvd.nist.gov", "cwe.mitre.org", "owasp.org", "www.first.org"}

# TTL in seconds. Canonical reference URLs (CVE/CWE/OWASP/CVSS) rarely change.
TTL_CANONICAL = 7 * 24 * 60 * 60  # 7 days
TTL_OTHER = 60 * 60  # 1 hour

MAX_CACHE_SIZE = 10_000

# Cache: url -> (status, expires_at). Pruned and evicted FIFO when full.
_validation_cache: dict[str, tuple[str, float]] = {}
_cache_lock = threading.Lock()

# OWASP Top 10 slugs for stable linking
OWASP_2021 = {
    "1": "A01_2021-Broken_Access_Control",
    "2": "A02_2021-Cryptographic_Failures",
    "3": "A03_2021-Injection",
    "4": "A04_2021-Insecure_Design",
    "5": "A05_2021-Security_Misconfiguration",
    "6": "A06_2021-Vulnerable_and_Outdated_Components",
    "7": "A07_2021-Identification_and_Authentication_Failures",
    "8": "A08_2021-Software_and_Data_Integrity_Failures",
    "9": "A09_2021-Security_Logging_and_Monitoring_Failures",
    "10": "A10_2021-Server-Side_Request_Forgery_%28SSRF%29",
}
OWASP_2017 = {
    "1": "A1_2017-Injection",
    "2": "A2_2017-Broken_Authentication",
    "3": "A3_2017-Sensitive_Data_Exposure",
    "4": "A4_2017-XML_External_Entities_%28XXE%29",
    "5": "A5_2017-Broken_Access_Control",
    "6": "A6_2017-Security_Misconfiguration",
    "7": "A7_2017-Cross-Site_Scripting_%28XSS%29",
    "8": "A8_2017-Insecure_Deserialization",
    "9": "A9_2017-Using_Components_with_Known_Vulnerabilities",
    "10": "A10_2017-Insufficient_Logging%26Monitoring",
}


def extract_urls(text: str) -> list[str]:
    """Extract HTTP(S) URLs from text. Deduplicated, order preserved."""
    if not text or not isinstance(text, str):
        return []
    seen = set()
    out = []
    for m in URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;:)")
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out


def _cve_to_nvd_url(cve: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cve.upper()}"


def _cwe_to_url(cwe: str) -> str:
    num = re.sub(r"\D", "", cwe)
    return f"https://cwe.mitre.org/data/definitions/{num}.html"


def _owasp_to_url(a_num: str, year: str | None) -> str | None:
    if year == "2017" and a_num in OWASP_2017:
        return f"https://owasp.org/www-project-top-ten/2017/{OWASP_2017[a_num]}"
    if (year is None or year == "2021") and a_num in OWASP_2021:
        return f"https://owasp.org/Top10/{OWASP_2021[a_num]}/"
    return None


def extract_identifier_urls(text: str) -> list[str]:
    """Generate canonical URLs for CVE/CWE/OWASP identifiers found in text."""
    if not text or not isinstance(text, str):
        return []
    urls: list[str] = []
    seen = set()
    for m in CVE_RE.finditer(text):
        url = _cve_to_nvd_url(m.group(0))
        if url not in seen:
            seen.add(url)
            urls.append(url)
    for m in CWE_RE.finditer(text):
        url = _cwe_to_url(m.group(0))
        if url not in seen:
            seen.add(url)
            urls.append(url)
    for m in OWASP_RE.finditer(text):
        a_num = str(int(m.group(1)))
        year = m.group(2)
        url = _owasp_to_url(a_num, year)
        if url and url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def identifier_to_url(token: str) -> str | None:
    """Return canonical URL for a single CVE/CWE/OWASP token, if recognized."""
    if not token:
        return None
    token = token.strip()
    if CVE_RE.fullmatch(token):
        return _cve_to_nvd_url(token)
    if CWE_RE.fullmatch(token):
        return _cwe_to_url(token)
    # Try matching OWASP with word boundaries
    m = OWASP_RE.fullmatch(token)
    if not m:
        # Try without word boundaries for exact table cell values
        m = re.fullmatch(r"A([0-9]{1,2})(?::(20\d{2}))?", token, re.IGNORECASE)
    if m:
        a_num = str(int(m.group(1)))
        year = m.group(2)
        return _owasp_to_url(a_num, year)
    return None


def _is_canonical_domain(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        return host.lower() in CANONICAL_DOMAINS
    except Exception:
        return False


def is_canonical_url(url: str) -> bool:
    """Public helper for canonical reference domains."""
    return _is_canonical_domain(url)


def _get_cache_ttl(url: str) -> float:
    """Return cache TTL in seconds (longer for canonical reference domains)."""
    return TTL_CANONICAL if _is_canonical_domain(url) else TTL_OTHER


def validate_url(url: str) -> str:
    """
    Return 'valid', 'invalid', or 'error' (e.g., network failure).
    Results are cached by TTL: 7 days for CVE/CWE/OWASP/CVSS domains, 1 hour for others.
    """
    if not url or not url.startswith(("http://", "https://")):
        return "invalid"

    now = time.monotonic()
    with _cache_lock:
        entry = _validation_cache.get(url)
        if entry is not None:
            status, expires_at = entry
            if now < expires_at:
                return status

    try:
        with httpx.Client(
            follow_redirects=True,
            timeout=TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            r = client.get(url)
            if r.status_code != 200:
                status = "invalid"
            else:
                sample = (r.text or "")[:MAX_BODY_SAMPLE]
                status = "invalid" if NOT_FOUND_RE.search(sample) else "valid"
    except Exception:
        status = "error"

    expires_at = now + _get_cache_ttl(url)
    with _cache_lock:
        # Prune expired entries
        expired = [k for k, (_, exp) in _validation_cache.items() if exp <= now]
        for k in expired:
            del _validation_cache[k]
        # Evict oldest (FIFO) if at capacity
        while len(_validation_cache) >= MAX_CACHE_SIZE:
            first_key = next(iter(_validation_cache))
            del _validation_cache[first_key]
        _validation_cache[url] = (status, expires_at)

    return status


def get_valid_urls(urls: list[str]) -> set[str]:
    """Return the subset of URLs that pass validation. Deduplicated."""
    valid = set()
    for url in urls:
        if url in valid:
            continue
        status = validate_url(url)
        if status == "valid":
            valid.add(url)
        elif status == "error" and _is_canonical_domain(url):
            # If validation couldn't run (offline), allow canonical references only
            valid.add(url)
    return valid
