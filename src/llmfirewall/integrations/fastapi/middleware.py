"""ASGI HTTP Middleware integrating LLMFirewall into FastAPI and Starlette applications."""

import json
import logging
import uuid
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from llmfirewall.core.models import Action, ScanResult
from llmfirewall.firewall import Firewall
from llmfirewall.integrations.fastapi.extraction import ExtractorCallable, FieldExtractor
from llmfirewall.integrations.fastapi.responses import (
    create_blocked_response,
    create_firewall_error_response,
    create_payload_too_large_response,
)

logger = logging.getLogger("llmfirewall.fastapi")


class FirewallMiddleware(BaseHTTPMiddleware):
    """Production-ready ASGI Middleware for FastAPI / Starlette.
    
    Responsibilities:
    1. Extract relevant payload text from incoming HTTP requests without consuming stream.
    2. Enforce byte size limits to prevent parser and memory exhaustion attacks.
    3. Execute LLMFirewall orchestrator (Detectors -> Risk Engine -> Policy Engine).
    4. Enforce policy decision:
       - BLOCK: Return HTTP 403 (or custom code) with sanitized JSON error response.
       - WARN: Allow request through; attach scan telemetry to request.state.
       - REDACT: Safely substitute redacted text into JSON payload; forward to endpoint.
       - ALLOW: Pass through unmodified.
    5. Maintain request correlation IDs and telemetry headers.
    6. Fail-closed or fail-open deterministically on unexpected exceptions.
    """

    def __init__(
        self,
        app: Any,
        firewall: Optional[Firewall] = None,
        paths: Optional[List[str]] = None,
        exclude_paths: Optional[List[str]] = None,
        methods: Optional[Set[str]] = None,
        extractor: Optional[Union[List[str], ExtractorCallable]] = None,
        max_inspection_bytes: int = 1_048_576,  # 1MB default
        on_payload_too_large: str = "block",  # 'block', 'skip', 'warn'
        blocked_status_code: int = 403,
        request_id_header: str = "X-Request-ID",
        fail_closed: bool = True,
        scan_output: bool = False,
    ) -> None:
        """
        Args:
            app: The ASGI application instance.
            firewall: Configured Firewall instance (defaults to Firewall()).
            paths: Specific path prefixes to protect (e.g. ['/api/v1/chat']). If None, all paths inspected.
            exclude_paths: Path prefixes to skip (e.g. ['/health', '/docs', '/metrics']).
            methods: HTTP methods to inspect (defaults to {'POST', 'PUT', 'PATCH'}).
            extractor: Either list of JSON field names or custom ExtractorCallable.
            max_inspection_bytes: Maximum request body bytes to inspect. Default 1MB.
            on_payload_too_large: Action when payload exceeds limit ('block', 'skip', 'warn').
            blocked_status_code: HTTP status code on policy block (default 403).
            request_id_header: Header name to check for inbound request IDs.
            fail_closed: If True (default), return HTTP 500 on firewall failure; if False, continue.
            scan_output: If True, inspect JSON responses from endpoints (default False).
        """
        super().__init__(app)
        self.firewall = firewall or Firewall()
        self.paths = paths
        self.exclude_paths = exclude_paths or ["/docs", "/redoc", "/openapi.json", "/health", "/metrics"]
        self.methods = methods or {"POST", "PUT", "PATCH"}
        self.max_inspection_bytes = max_inspection_bytes
        self.on_payload_too_large = on_payload_too_large.lower()
        self.blocked_status_code = blocked_status_code
        self.request_id_header = request_id_header
        self.fail_closed = fail_closed
        self.scan_output = scan_output

        if callable(extractor):
            self.extractor = extractor
        elif isinstance(extractor, list):
            self.extractor = FieldExtractor(field_names=extractor)
        else:
            self.extractor = FieldExtractor()

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # 1. Path & Method Filter Check
        path = request.url.path
        if not self._should_inspect(path, request.method):
            return await call_next(request)

        # 2. Extract or Generate Request ID
        req_id = request.headers.get(self.request_id_header) or str(uuid.uuid4())
        request.state.firewall_request_id = req_id

        # 3. Read Request Body Safely
        try:
            body_bytes = await request.body()
        except Exception as exc:
            logger.warning("Failed to read request body: %s", exc)
            if self.fail_closed:
                return create_firewall_error_response(request_id=req_id, status_code=500)
            return await call_next(request)

        # 4. Payload Size Limit Evaluation
        if len(body_bytes) > self.max_inspection_bytes:
            if self.on_payload_too_large == "block":
                logger.warning(
                    "Request %s exceeded payload limit (%d > %d bytes): BLOCKED",
                    req_id,
                    len(body_bytes),
                    self.max_inspection_bytes,
                )
                return create_payload_too_large_response(request_id=req_id)
            elif self.on_payload_too_large == "skip":
                logger.info("Request %s exceeded payload limit: Skipping firewall inspection", req_id)
                return await self._call_with_reset_body(request, body_bytes, call_next)
            # if 'warn', proceed with inspection on truncated bytes or pass through

        # 5. Extract Text Content
        extracted_text, parsed_json = self.extractor(request, body_bytes)
        if not extracted_text:
            # Nothing matched extraction criteria; pass through cleanly
            return await self._call_with_reset_body(request, body_bytes, call_next)

        # 6. Execute Firewall Inspection
        try:
            scan_context = {
                "path": path,
                "method": request.method,
                "client_ip": request.client.host if request.client else None,
            }
            scan_result: ScanResult = self.firewall.check(
                text_or_request=extracted_text,
                direction="input",
                user_id=request.headers.get("X-User-ID"),
                session_id=request.headers.get("X-Session-ID"),
                context=scan_context,
            )
        except Exception as exc:
            logger.exception("Firewall inspection raised exception for request %s: %s", req_id, exc)
            if self.fail_closed:
                return create_firewall_error_response(request_id=req_id)
            return await self._call_with_reset_body(request, body_bytes, call_next)

        # Attach ScanResult to request.state for endpoint access
        request.state.firewall_scan_result = scan_result

        # 7. Policy Enforcement
        action = scan_result.decision.action

        if action == Action.BLOCK:
            logger.warning(
                "Request %s blocked by policy. Reason: %s",
                req_id,
                scan_result.decision.reason,
            )
            return create_blocked_response(
                request_id=req_id,
                status_code=self.blocked_status_code,
            )

        new_body_bytes = body_bytes
        if action == Action.REDACT or (action == Action.WARN and scan_result.decision.redacted_text is not None):
            # Apply safe redaction to request body if it was parsed as JSON
            if parsed_json is not None and isinstance(parsed_json, dict):
                # Replace extracted field with processed_text
                updated_json = self._substitute_redacted_text(parsed_json, scan_result.processed_text)
                new_body_bytes = json.dumps(updated_json).encode("utf-8")
            elif not parsed_json and scan_result.processed_text:
                new_body_bytes = scan_result.processed_text.encode("utf-8")

        # 8. Forward to Downstream Endpoint
        response = await self._call_with_reset_body(request, new_body_bytes, call_next)

        # Attach telemetry headers
        response.headers["X-LLMFirewall-Request-ID"] = req_id
        response.headers["X-LLMFirewall-Action"] = action.value
        response.headers["X-LLMFirewall-Risk-Score"] = str(scan_result.risk_score.score)

        return response

    def _should_inspect(self, path: str, method: str) -> bool:
        """Determine whether the request matches route inspection rules."""
        if method.upper() not in self.methods:
            return False

        # Exclude paths take precedence
        for prefix in self.exclude_paths:
            if path.startswith(prefix):
                return False

        # If paths are specified, must match one prefix
        if self.paths is not None:
            return any(path.startswith(p) for p in self.paths)

        return True

    def _substitute_redacted_text(self, data: Dict[str, Any], redacted_text: str) -> Dict[str, Any]:
        """Substitute the redacted string into the first matching field key in data."""
        data_copy = dict(data)
        field_names = getattr(self.extractor, "field_names", ["prompt", "text", "message", "question", "content", "input"])
        for field in field_names:
            if field in data_copy and isinstance(data_copy[field], str):
                data_copy[field] = redacted_text
                break
        return data_copy

    async def _call_with_reset_body(
        self,
        request: Request,
        body_bytes: bytes,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """Reset the request stream and caches so downstream handlers can read request.body() or JSON."""
        request._body = body_bytes
        request._stream_consumed = False
        if hasattr(request, "_json"):
            del request._json

        async def receive() -> Dict[str, Any]:
            return {"type": "http.request", "body": body_bytes, "more_body": False}

        request._receive = receive  # type: ignore
        return await call_next(request)
