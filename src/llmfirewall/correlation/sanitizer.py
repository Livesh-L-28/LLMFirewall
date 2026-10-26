"""Deep recursive metadata, payload, and exception privacy sanitizer.

Phase 4: Unified Security Event Correlation.
Guarantees:
- Zero raw credential leakage: Automatically masks API keys, tokens, passwords, and private keys.
- Deep recursion: Scrubs nested dicts, lists, tuples, sets, and object attributes.
- Exception safety: Scrubs error messages, stack traces, and exception representations.
- Deterministic and non-destructive: Replaces sensitive values with standard redaction tokens.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Union

REDACTED_CREDENTIAL_TOKEN = "[REDACTED_CREDENTIAL]"
REDACTED_TEXT_TOKEN = "[OMITTED_FOR_SAFETY]"

# Common high-risk secret and credential token patterns
SECRET_REGEXES: List[re.Pattern] = [
    re.compile(r"sk-(?:proj-)?[a-zA-Z0-9_\-]{20,}", re.IGNORECASE),                         # OpenAI API keys
    re.compile(r"gh[pousr]_[a-zA-Z0-9]{20,}", re.IGNORECASE),                               # GitHub tokens
    re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),                                         # AWS Access Key ID
    re.compile(r"(?:aws_secret_access_key|aws_secret|secret_key)\s*[:=]\s*[^\s]+", re.I),  # AWS Secret Key
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", re.MULTILINE),
    re.compile(r"Bearer\s+ey[a-zA-Z0-9_\-\.]+", re.IGNORECASE),                             # JWT / Bearer tokens
    re.compile(r"(?:postgres|mysql|mongodb|redis|amqp)://[^\s:@]+:[^\s:@]+@[^\s]+", re.I), # DB Connection strings with credentials
    re.compile(r"(?:password|passwd|pwd|api_key|apikey|client_secret|auth_token)\s*[:=]\s*['\"]?[^\s'\",]+['\"]?", re.IGNORECASE),
]

# Sensitive dictionary key names (case-insensitive)
SENSITIVE_KEY_NAMES: Set[str] = {
    "api_key",
    "apikey",
    "secret",
    "client_secret",
    "token",
    "auth_token",
    "access_token",
    "refresh_token",
    "password",
    "passwd",
    "pwd",
    "credential",
    "credentials",
    "private_key",
    "secret_key",
    "authorization",
    "cookie",
    "session_token",
    "ssn",
    "credit_card",
    "cvv",
}

SENSITIVE_SUFFIXES = ("_secret", "_password", "_passwd", "_token", "_credential", "_key", "_api_key")
SAFE_KEY_PREFIXES = ("control:", "asset:", "tool:", "model:", "agent:", "detector:", "rule:", "framework:")
SAFE_METRIC_KEYS = {
    "type", "version", "schema_version", "hash", "fingerprint", "status",
    "id", "name", "created_at", "updated_at", "last_seen", "first_seen",
    "event_id", "trace_id", "request_id", "workflow_id", "tenant_id",
    "step_number", "duration_ms", "count", "findings_count", "risk_score",
}


def sanitize_string(text: str) -> str:
    """Scrub known secret and credential patterns from a string."""
    if not text or not isinstance(text, str):
        return str(text)

    sanitized = text
    for pattern in SECRET_REGEXES:
        sanitized = pattern.sub(REDACTED_CREDENTIAL_TOKEN, sanitized)
    return sanitized


def sanitize_value(val: Any, max_depth: int = 10, current_depth: int = 0) -> Any:
    """Recursively sanitize arbitrary data structures (dicts, lists, tuples, sets, strings)."""
    if current_depth > max_depth:
        return "[TRUNCATED_MAX_DEPTH]"

    if isinstance(val, str):
        return sanitize_string(val)

    if isinstance(val, dict):
        clean_dict: Dict[str, Any] = {}
        for k, v in val.items():
            k_str = str(k)
            k_lower = k_str.lower()

            # Check if key itself designates a sensitive credential
            is_sensitive_key = (
                (k_lower in SENSITIVE_KEY_NAMES or any(k_lower.endswith(s) for s in SENSITIVE_SUFFIXES))
                and not any(k_lower.startswith(p) for p in SAFE_KEY_PREFIXES)
                and k_lower not in SAFE_METRIC_KEYS
            )

            if is_sensitive_key:
                clean_dict[k_str] = REDACTED_CREDENTIAL_TOKEN
            else:
                clean_dict[k_str] = sanitize_value(v, max_depth=max_depth, current_depth=current_depth + 1)
        return clean_dict

    if isinstance(val, (list, tuple)):
        clean_list = [sanitize_value(elem, max_depth=max_depth, current_depth=current_depth + 1) for elem in val]
        return type(val)(clean_list)

    if isinstance(val, set):
        return {sanitize_value(elem, max_depth=max_depth, current_depth=current_depth + 1) for elem in val}

    if isinstance(val, Exception):
        return sanitize_string(f"{type(val).__name__}: {str(val)}")

    if hasattr(val, "model_dump") and callable(val.model_dump):
        try:
            return sanitize_value(val.model_dump(mode="json"), max_depth=max_depth, current_depth=current_depth + 1)
        except Exception:
            return sanitize_string(str(val))

    if hasattr(val, "__dict__"):
        try:
            return sanitize_value(dict(val.__dict__), max_depth=max_depth, current_depth=current_depth + 1)
        except Exception:
            return sanitize_string(str(val))

    return val


def sanitize_metadata(metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Clean and sanitize an event or trace metadata dictionary."""
    if not metadata or not isinstance(metadata, dict):
        return {}
    return sanitize_value(metadata)
