"""FastAPI integration exceptions for LLMFirewall."""

from typing import Any, Optional
from llmfirewall.core.exceptions import LLMFirewallError


class FastAPIIntegrationError(LLMFirewallError):
    """Base exception for FastAPI integration errors."""
    pass


class PayloadTooLargeError(FastAPIIntegrationError):
    """Raised when an incoming request exceeds the configured inspection byte limit."""
    def __init__(self, size: int, max_bytes: int):
        super().__init__(f"Request body size {size} exceeds maximum inspection size {max_bytes} bytes")
        self.size = size
        self.max_bytes = max_bytes


class RequestBlockedException(FastAPIIntegrationError):
    """Internal exception raised when a request is blocked by policy."""
    def __init__(self, message: str, request_id: str, decision: Optional[Any] = None):
        super().__init__(message)
        self.request_id = request_id
        self.decision = decision
