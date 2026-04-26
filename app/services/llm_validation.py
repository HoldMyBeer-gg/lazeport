"""
LLM output validation to prevent JSON blob hallucinations.

Detects and prevents cases where the LLM outputs JSON objects/arrays
inside what should be plain string fields, which poisons reports and
can leak into SARIF parsing.
"""

import json
import logging
import re
from typing import Dict, Any, Tuple

log = logging.getLogger(__name__)


def validate_structured_output(
    structured: Dict[str, Any],
    required_keys: list[str] = None,
    system_owned_keys: list[str] = None
) -> Tuple[bool, list[str]]:
    """
    Validate that LLM output contains only string values, not embedded JSON.
    
    Args:
        structured: LLM output to validate
        required_keys: Keys that must be present (excludes system-owned fields)
        system_owned_keys: Fields set by system (e.g., Affected Files), not validated
    
    Returns:
        Tuple of (is_valid, list_of_issues)
        
    Validation fails if:
    - Required fields are missing (excluding system-owned)
    - Any field value is not a string (dict, list, etc.)
    - Any string field looks like embedded JSON (starts with { or [ and parses)
    - Any string contains code fences (```)
    - Any string looks like a full schema dump (many structured keys in one field)
    """
    issues = []
    required_keys = required_keys or []
    system_owned_keys = system_owned_keys or []
    
    # Check 0: All required keys must be present (excluding system-owned)
    for key in required_keys:
        if key in system_owned_keys:
            continue  # Skip system-owned fields like Affected Files
        if key not in structured:
            issues.append(f"Missing required field: '{key}'")
    
    for key, value in structured.items():
        # Skip internal/metadata keys and system-owned fields
        if key.startswith("_") or key in system_owned_keys:
            continue
        
        # Check 1: Value must be a string
        if not isinstance(value, str):
            issues.append(f"Field '{key}' is not a string (type: {type(value).__name__})")
            continue
        
        value_stripped = value.strip()
        if not value_stripped:
            continue
        
        # Check 2: Detect JSON object/array at start
        if value_stripped.startswith("{") or value_stripped.startswith("["):
            try:
                parsed = json.loads(value_stripped)
                if isinstance(parsed, (dict, list)):
                    issues.append(f"Field '{key}' contains embedded JSON (starts with {{/[)")
                    continue
            except json.JSONDecodeError:
                # Not valid JSON, but still suspicious if it looks like JSON
                if value_stripped.startswith("{") and ":" in value_stripped:
                    issues.append(f"Field '{key}' looks like malformed JSON (starts with {{ and contains :)")
        
        # Check 3: Detect code fences
        if "```" in value:
            issues.append(f"Field '{key}' contains code fences (```)")
        
        # Check 4: Detect schema dumps (many structured keys in one field)
        # Look for patterns like: "Title: ..., Severity: ..., Remediation: ..."
        schema_keywords = ["Title:", "Severity:", "Remediation:", "Root Cause:", 
                          "Vulnerability Summary:", "Attack Vector:", "Impact:",
                          "Justification:", "Rationale:"]
        keyword_count = sum(1 for kw in schema_keywords if kw in value)
        if keyword_count >= 4:  # If 4+ schema keywords appear in one field
            issues.append(f"Field '{key}' looks like a schema dump ({keyword_count} structured keywords)")
        
        # Check 5: Detect stringified JSON (entire JSON as quoted string in a string)
        # Pattern: field contains many "key": "value" pairs
        json_pattern_count = len(re.findall(r'"[^"]+"\s*:\s*"[^"]*"', value))
        if json_pattern_count >= 3:
            issues.append(f"Field '{key}' contains stringified JSON ({json_pattern_count} key-value pairs)")
    
    is_valid = len(issues) == 0
    return is_valid, issues


def get_strict_retry_instructions() -> str:
    """
    Return stricter instructions for LLM retry when validation fails.
    
    These instructions are appended to the system prompt on retry.
    """
    return """
CRITICAL - Your previous response was malformed. Follow these rules STRICTLY:

1. Return ONLY a JSON object with string values
2. Each field value must be plain text - NO nested JSON objects or arrays
3. Do NOT use code fences (```) anywhere
4. Do NOT embed the entire schema into a single field
5. Do NOT stringify JSON and put it in a field value
6. Each section should contain narrative text, not structured data dumps

Example of CORRECT format:
{
  "Vulnerability Summary": "The application uses weak cryptography...",
  "Severity": "High",
  "Remediation": "Replace MD5 with SHA-256 or better."
}

Example of INCORRECT format (DO NOT DO THIS):
{
  "Vulnerability Summary": "{\\"title\\": \\"Weak Crypto\\", \\"severity\\": \\"High\\"}"
}
"""
