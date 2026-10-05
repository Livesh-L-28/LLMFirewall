"""Pure ASGI 3.0 Security Middleware for LLMFirewall v1.1.0 (Phase 51).

Zero mandatory third-party framework dependencies. Compatible with FastAPI,
Starlette, Quart, and any ASGI 3.0 compliant web application or gateway.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import uuid

from llmfirewall.core.models import Action, ScanResult
from llmfirewall.firewall import Firewall
from llmfirewall.integrations.stream import StreamingTextGuard


class LLMFirewallASGIMiddleware:
    """Pure ASGI 3.0 middleware providing input inspection, streaming output protection, and context propagation."""

    def __init__(
        self,
        app: Any,
        firewall: Optional[Firewall] = None,
        exclude_paths: Optional[Set[str]] = None,
        inspect_request: bool = True,
        inspect_response: bool = True,
        fail_closed: bool = True,
    ) -> None:
        self.app = app
        self.firewall = firewall or Firewall()
        self.exclude_paths: Set[str] = exclude_paths or {"/health", "/healthz", "/metrics", "/docs", "/openapi.json"}
        self.inspect_request = inspect_request
        self.inspect_response = inspect_response
        self.fail_closed = fail_closed
        self.stream_guard = StreamingTextGuard(firewall=self.firewall, fail_closed=self.fail_closed)

    async def __call__(self, scope: Dict[str, Any], receive: Callable, send: Callable) -> None:
        scope_type = scope.get("type")
        if scope_type == "http":
            await self._handle_http(scope, receive, send)
        elif scope_type == "websocket":
            await self._handle_websocket(scope, receive, send)
        else:
            await self.app(scope, receive, send)

    async def _handle_http(self, scope: Dict[str, Any], receive: Callable, send: Callable) -> None:
        path = scope.get("path", "")
        if path in self.exclude_paths:
            await self.app(scope, receive, send)
            return

        headers_dict = self._parse_headers(scope.get("headers", []))
        request_id = headers_dict.get("x-request-id", str(uuid.uuid4()))
        trace_id = headers_dict.get("x-trace-id", request_id)
        user_id = headers_dict.get("x-user-id")
        session_id = headers_dict.get("x-session-id")

        context = {
            "request_id": request_id,
            "trace_id": trace_id,
            "user_id": user_id,
            "session_id": session_id,
            "path": path,
            "method": scope.get("method", "POST"),
        }

        # 1. Inspect HTTP Request
        cached_messages: List[Dict[str, Any]] = []
        req_body = b""
        if self.inspect_request and scope.get("method") in {"POST", "PUT", "PATCH"}:
            more_body = True
            while more_body:
                msg = await receive()
                cached_messages.append(msg)
                req_body += msg.get("body", b"")
                more_body = msg.get("more_body", False)

            # Extract scan text from request body
            scan_text = self._extract_text_from_body(req_body, headers_dict.get("content-type", ""))
            if scan_text:
                scan_res = self.firewall.scan_prompt(scan_text, context=context)
                
                # Context propagation into scope
                if "state" not in scope or not isinstance(scope["state"], dict):
                    scope["state"] = {}
                scope["state"]["firewall_prompt_scan"] = scan_res
                scope["state"]["request_id"] = request_id

                if scan_res.action == Action.BLOCK:
                    await self._send_block_response(
                        send,
                        request_id=request_id,
                        reason=scan_res.reason,
                        status_code=403,
                    )
                    return

        # Prepare receive replayer
        msg_idx = 0

        async def replaying_receive() -> Dict[str, Any]:
            nonlocal msg_idx
            if msg_idx < len(cached_messages):
                msg = cached_messages[msg_idx]
                msg_idx += 1
                return msg
            return await receive()

        # 2. Inspect HTTP Response
        response_started = False
        captured_status = 200
        captured_headers: List[Tuple[bytes, bytes]] = []
        response_body_buffer = b""

        async def wrapping_send(msg: Dict[str, Any]) -> None:
            nonlocal response_started, captured_status, captured_headers, response_body_buffer

            if msg["type"] == "http.response.start":
                captured_status = msg.get("status", 200)
                captured_headers = list(msg.get("headers", []))
                # Do not send start immediately if inspecting full response body
                return

            if msg["type"] == "http.response.body":
                body_chunk = msg.get("body", b"")
                more_body = msg.get("more_body", False)

                if self.inspect_response and captured_status < 400:
                    response_body_buffer += body_chunk
                    if not more_body:
                        # Full body ready for inspection
                        res_text = response_body_buffer.decode("utf-8", errors="ignore")
                        if res_text:
                            scan_res = self.firewall.scan_output(res_text, context=context)
                            if scan_res.action == Action.BLOCK:
                                await self._send_block_response(
                                    send,
                                    request_id=request_id,
                                    reason=scan_res.reason,
                                    status_code=403,
                                )
                                return
                            elif scan_res.action == Action.REDACT and scan_res.sanitized_text:
                                response_body_buffer = scan_res.sanitized_text.encode("utf-8")

                        # Inject firewall headers
                        captured_headers.append((b"x-llmfirewall-action", b"allow"))
                        captured_headers.append((b"x-request-id", request_id.encode()))

                        # Send delayed start and body
                        await send({
                            "type": "http.response.start",
                            "status": captured_status,
                            "headers": captured_headers,
                        })
                        await send({
                            "type": "http.response.body",
                            "body": response_body_buffer,
                            "more_body": False,
                        })
                        return

                # Default pass-through if not inspecting or streaming chunk
                if not response_started:
                    response_started = True
                    captured_headers.append((b"x-request-id", request_id.encode()))
                    await send({
                        "type": "http.response.start",
                        "status": captured_status,
                        "headers": captured_headers,
                    })
                await send(msg)

        await self.app(scope, replaying_receive if cached_messages else receive, wrapping_send)

    async def _handle_websocket(self, scope: Dict[str, Any], receive: Callable, send: Callable) -> None:
        """Protect WebSocket text frames inbound and outbound."""
        async def secure_receive() -> Dict[str, Any]:
            msg = await receive()
            if msg.get("type") == "websocket.receive" and "text" in msg:
                scan_res = self.firewall.scan_prompt(msg["text"])
                if scan_res.action == Action.BLOCK:
                    # Close websocket with Policy Violation code 1008
                    await send({"type": "websocket.close", "code": 1008, "reason": "Security Policy Violation"})
                    return {"type": "websocket.disconnect", "code": 1008}
            return msg

        async def secure_send(msg: Dict[str, Any]) -> None:
            if msg.get("type") == "websocket.send" and "text" in msg:
                scan_res = self.firewall.scan_output(msg["text"])
                if scan_res.action == Action.BLOCK:
                    await send({"type": "websocket.close", "code": 1008, "reason": "Security Policy Violation"})
                    return
                elif scan_res.action == Action.REDACT and scan_res.sanitized_text:
                    msg["text"] = scan_res.sanitized_text
            await send(msg)

        await self.app(scope, secure_receive, secure_send)

    def _parse_headers(self, raw_headers: List[Tuple[bytes, bytes]]) -> Dict[str, str]:
        parsed = {}
        for k, v in raw_headers:
            parsed[k.decode("latin-1").lower()] = v.decode("latin-1")
        return parsed

    def _extract_text_from_body(self, body: bytes, content_type: str) -> Optional[str]:
        if not body:
            return None
        try:
            decoded = body.decode("utf-8")
        except UnicodeDecodeError:
            return None

        if "application/json" in content_type:
            try:
                data = json.loads(decoded)
                if isinstance(data, dict):
                    # Search common prompt fields: prompt, message, text, input, query
                    for key in ("prompt", "message", "text", "input", "query", "content"):
                        if key in data and isinstance(data[key], str):
                            return data[key]
                    return decoded
                elif isinstance(data, str):
                    return data
            except Exception:
                pass
        return decoded

    async def _send_block_response(
        self,
        send: Callable,
        request_id: str,
        reason: str,
        status_code: int = 403,
    ) -> None:
        payload = json.dumps({
            "error": "security_policy_violation",
            "message": f"Blocked by LLMFirewall: {reason}",
            "request_id": request_id,
        }).encode("utf-8")

        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode("utf-8")),
            (b"x-llmfirewall-action", b"block"),
            (b"x-request-id", request_id.encode("utf-8")),
        ]

        await send({"type": "http.response.start", "status": status_code, "headers": headers})
        await send({"type": "http.response.body", "body": payload, "more_body": False})
