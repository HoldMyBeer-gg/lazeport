"""
Input validation utilities and custom Pydantic validators.

Provides reusable validators for common patterns to prevent injection attacks,
data corruption, and ensure data integrity.
"""
from typing import Any
import re

# Security constraints
MAX_NAME_LENGTH = 255
MAX_TITLE_LENGTH = 500
MAX_NOTES_LENGTH = 50000
MAX_CONTENT_LENGTH = 100000
MAX_EMAIL_LENGTH = 320  # RFC 5321
MAX_URL_LENGTH = 2048
MAX_FILENAME_LENGTH = 255

# Pattern validation
SAFE_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9._\- ]+$')
UUID_PATTERN = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)

# Dangerous patterns to reject
HTML_TAG_PATTERN = re.compile(r'<[^>]+>', re.IGNORECASE)
SCRIPT_PATTERN = re.compile(r'<script[\s\S]*?</script>', re.IGNORECASE)
SQL_INJECTION_PATTERNS = [
    re.compile(r"('|(\\')|(--)|(/\*)|(%27)|(%23)|(%2D%2D))", re.IGNORECASE),
    re.compile(r"(union|select|insert|update|delete|drop|create|alter|exec|execute|script|javascript|alert|onerror|onload)", re.IGNORECASE)
]


def sanitize_string(v: str | None, max_length: int = MAX_NAME_LENGTH) -> str:
    """Sanitize and validate string input."""
    if v is None:
        return ""
    v = str(v)
    # Remove control characters but keep newlines and tabs for templates/notes
    v = "".join(ch for ch in v if ch.isprintable() or ch in ("\n", "\t"))
    v = v.strip()
    if len(v) > max_length:
        raise ValueError(f"Must be {max_length} characters or less")
    return v


def sanitize_html_input(v: str | None) -> str:
    """
    Sanitize HTML input - strips all HTML tags.
    For user content that should never contain HTML.
    """
    if v is None:
        return ""
    v = str(v).strip()
    # Remove script tags first (security)
    v = SCRIPT_PATTERN.sub('', v)
    # Remove all HTML tags
    v = HTML_TAG_PATTERN.sub('', v)
    return v


def validate_filename(v: str | None) -> str:
    """Validate filename is safe (no path traversal)."""
    if v is None:
        raise ValueError("Filename is required")
    v = str(v).strip()
    if not v:
        raise ValueError("Filename cannot be empty")
    if len(v) > MAX_FILENAME_LENGTH:
        raise ValueError(f"Filename must be {MAX_FILENAME_LENGTH} characters or less")
    # Check for path traversal
    if '..' in v or '/' in v or '\\' in v:
        raise ValueError("Filename cannot contain path separators or parent directory references")
    # Check for safe characters only
    if not SAFE_FILENAME_PATTERN.match(v):
        raise ValueError("Filename contains invalid characters")
    return v


def validate_email(v: str | None) -> str | None:
    """Validate email format."""
    if v is None or v == "":
        return None
    v = str(v).strip().lower()
    if any(ch.isspace() for ch in v):
        raise ValueError("Invalid email format")
    if len(v) > MAX_EMAIL_LENGTH:
        raise ValueError(f"Email must be {MAX_EMAIL_LENGTH} characters or less")
    # Basic email validation (Pydantic EmailStr is stricter)
    if '@' not in v:
        raise ValueError("Invalid email format")
    local, domain = v.split('@', 1)
    if not local or not domain:
        raise ValueError("Invalid email format")
    if domain.startswith('.') or domain.endswith('.'):
        raise ValueError("Invalid email format")
    if '.' not in domain:
        raise ValueError("Invalid email format")
    return v


def validate_uuid(v: str | None) -> str:
    """Validate UUID format."""
    if v is None:
        raise ValueError("UUID is required")
    v = str(v).strip().lower()
    if not UUID_PATTERN.match(v):
        raise ValueError("Invalid UUID format")
    return v


def validate_url(v: str | None) -> str | None:
    """Validate URL format and length."""
    if v is None or v == "":
        return None
    v = str(v).strip()
    if len(v) > MAX_URL_LENGTH:
        raise ValueError(f"URL must be {MAX_URL_LENGTH} characters or less")
    if not v.startswith(('http://', 'https://')):
        raise ValueError("URL must start with http:// or https://")
    return v


def check_sql_injection_patterns(v: str) -> None:
    """Check for common SQL injection patterns."""
    if not v:
        return
    for pattern in SQL_INJECTION_PATTERNS:
        if pattern.search(v):
            raise ValueError("Input contains potentially dangerous characters")


def check_html_tags(v: str) -> None:
    """Check for HTML tags (XSS prevention for name fields)."""
    if not v:
        return
    if HTML_TAG_PATTERN.search(v):
        raise ValueError("HTML tags are not allowed")


class ValidatedString:
    """Reusable validators for common string fields."""
    
    @classmethod
    def name_validator(cls, v: Any) -> str:
        """Validator for name fields (client name, application name, report name, etc.)."""
        result = sanitize_string(v, MAX_NAME_LENGTH)
        check_html_tags(result)
        return result
    
    @classmethod
    def title_validator(cls, v: Any) -> str:
        """Validator for title fields (finding title, etc.)."""
        result = sanitize_string(v, MAX_TITLE_LENGTH)
        return result
    
    @classmethod
    def notes_validator(cls, v: Any) -> str:
        """Validator for notes/description fields."""
        result = sanitize_string(v, MAX_NOTES_LENGTH)
        return result
    
    @classmethod
    def content_validator(cls, v: Any) -> str:
        """Validator for large content fields."""
        result = sanitize_string(v, MAX_CONTENT_LENGTH)
        return result
    
    @classmethod
    def email_validator(cls, v: Any) -> str | None:
        """Validator for email fields."""
        return validate_email(v)
    
    @classmethod
    def url_validator(cls, v: Any) -> str | None:
        """Validator for URL fields."""
        return validate_url(v)
    
    @classmethod
    def filename_validator(cls, v: Any) -> str:
        """Validator for filename fields."""
        return validate_filename(v)
    
    @classmethod
    def uuid_validator(cls, v: Any) -> str:
        """Validator for UUID fields."""
        return validate_uuid(v)
