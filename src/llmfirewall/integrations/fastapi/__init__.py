"""FastAPI integration exports for LLMFirewall.

Optional dependency: requires fastapi and starlette.
"""

try:
    import fastapi
    import starlette
except ImportError as err:
    raise ImportError(
        "The 'fastapi' integration requires the optional 'fastapi' extra. "
        "Install it via: pip install 'llmfirewall[fastapi]'"
    ) from err

from llmfirewall.integrations.fastapi.exceptions import (
    FastAPIIntegrationError,
    PayloadTooLargeError,
    RequestBlockedException,
)
from llmfirewall.integrations.fastapi.extraction import ExtractorCallable, FieldExtractor
from llmfirewall.integrations.fastapi.helpers import (
    add_security_routes,
    firewall_dependency,
    get_firewall_request_id,
    get_scan_result,
    scan_response,
)
from llmfirewall.integrations.fastapi.middleware import FirewallMiddleware
from llmfirewall.integrations.fastapi.responses import (
    create_blocked_response,
    create_firewall_error_response,
    create_payload_too_large_response,
)

__all__ = [
    "FirewallMiddleware",
    "FieldExtractor",
    "ExtractorCallable",
    "get_scan_result",
    "get_firewall_request_id",
    "scan_response",
    "firewall_dependency",
    "add_security_routes",
    "create_blocked_response",
    "create_payload_too_large_response",
    "create_firewall_error_response",
    "FastAPIIntegrationError",
    "PayloadTooLargeError",
    "RequestBlockedException",
]
