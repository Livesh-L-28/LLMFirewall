"""Standard secure HTTP response builders for LLMFirewall FastAPI integration."""

from typing import Any, Dict, Optional
from fastapi.responses import JSONResponse


def create_blocked_response(
    request_id: str,
    status_code: int = 403,
    message: str = "Request rejected by security policy.",
    custom_headers: Optional[Dict[str, str]] = None,
) -> JSONResponse:
    """Create a safe, sanitized HTTP JSON error response for blocked requests.
    
    Security Guarantee:
    - Never leaks detector names, confidence scores, threat rules, raw PII, or raw secrets.
    - Emits request_id for operational triage and SIEM correlation.
    """
    headers = {
        "X-LLMFirewall-Request-ID": request_id,
        "X-LLMFirewall-Status": "blocked",
    }
    if custom_headers:
        headers.update(custom_headers)

    content: Dict[str, Any] = {
        "error": "request_blocked",
        "message": message,
        "request_id": request_id,
    }
    return JSONResponse(status_code=status_code, content=content, headers=headers)


def create_payload_too_large_response(
    request_id: str,
    status_code: int = 413,
    message: str = "Payload exceeds maximum allowed inspection limit.",
) -> JSONResponse:
    """Create a safe HTTP JSON error response when request payload exceeds size limits."""
    headers = {
        "X-LLMFirewall-Request-ID": request_id,
        "X-LLMFirewall-Status": "payload_too_large",
    }
    content: Dict[str, Any] = {
        "error": "payload_too_large",
        "message": message,
        "request_id": request_id,
    }
    return JSONResponse(status_code=status_code, content=content, headers=headers)


def create_firewall_error_response(
    request_id: str,
    status_code: int = 500,
    message: str = "Internal security inspection failed.",
) -> JSONResponse:
    """Create a safe HTTP JSON error response when firewall execution fails (fail-closed mode)."""
    headers = {
        "X-LLMFirewall-Request-ID": request_id,
        "X-LLMFirewall-Status": "error",
    }
    content: Dict[str, Any] = {
        "error": "firewall_error",
        "message": message,
        "request_id": request_id,
    }
    return JSONResponse(status_code=status_code, content=content, headers=headers)
