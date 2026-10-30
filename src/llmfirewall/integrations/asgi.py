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
                elif scan_res.action == Action.REDACT and scan_res.sanitized_text:
                    new_body = self._apply_redaction_to_body(
                        req_body,
                        headers_dict.get("content-type", ""),
                        scan_text,
                        scan_res.sanitized_text,
                    )
                    if new_body is not None:
                        req_body = new_body
                        cached_messages = [{"type": "http.request", "body": new_body, "more_body": False}]
                        self._update_scope_content_length(scope, len(new_body))

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
        is_streaming_response = False

        async def wrapping_send(msg: Dict[str, Any]) -> None:
            nonlocal response_started, captured_status, captured_headers, response_body_buffer, is_streaming_response

            if msg["type"] == "http.response.start":
                captured_status = msg.get("status", 200)
                captured_headers = list(msg.get("headers", []))
                parsed_res_headers = self._parse_headers(captured_headers)
                content_type = parsed_res_headers.get("content-type", "")
                transfer_encoding = parsed_res_headers.get("transfer-encoding", "")
                is_streaming_response = (
                    "text/event-stream" in content_type
                    or "application/x-ndjson" in content_type
                    or "chunked" in transfer_encoding
                )
                if not self.inspect_response or captured_status >= 400 or is_streaming_response:
                    response_started = True
                    captured_headers.append((b"x-request-id", request_id.encode()))
                    await send({
                        "type": "http.response.start",
                        "status": captured_status,
                        "headers": captured_headers,
                    })
                return

            if msg["type"] == "http.response.body":
                body_chunk = msg.get("body", b"")
                more_body = msg.get("more_body", False)

                if response_started:
                    # Pass-through or streaming response
                    if is_streaming_response and self.inspect_response and body_chunk:
                        try:
                            chunk_text = body_chunk.decode("utf-8")
                            chunk_scan = self.firewall.scan_output(chunk_text, context=context)
                            if chunk_scan.action == Action.BLOCK:
                                # Stream violation detected! Sever stream
                                return
                            elif chunk_scan.action == Action.REDACT and chunk_scan.sanitized_text:
                                body_chunk = chunk_scan.sanitized_text.encode("utf-8")
                        except UnicodeDecodeError:
                            pass
                    await send({
                        "type": "http.response.body",
                        "body": body_chunk,
                        "more_body": more_body,
                    })
                    return

                # Non-streaming response body buffering
                if self.inspect_response and captured_status < 400:
                    response_body_buffer += body_chunk
                    if more_body:
                        # Continue buffering until full response body is received
                        return

                    # Full body ready for inspection
                    res_text = ""
                    try:
                        res_text = response_body_buffer.decode("utf-8")
                    except UnicodeDecodeError:
                        pass

                    action_val = b"allow"
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
                            action_val = b"redact"

                    new_headers = []
                    has_cl = False
                    for h_name, h_val in captured_headers:
                        if h_name.lower() == b"content-length":
                            has_cl = True
                            new_headers.append((b"content-length", str(len(response_body_buffer)).encode("ascii")))
                        else:
                            new_headers.append((h_name, h_val))
                    if not has_cl and len(response_body_buffer) > 0:
                        new_headers.append((b"content-length", str(len(response_body_buffer)).encode("ascii")))
                    new_headers.append((b"x-llmfirewall-action", action_val))
                    new_headers.append((b"x-request-id", request_id.encode()))

                    response_started = True
                    await send({
                        "type": "http.response.start",
                        "status": captured_status,
                        "headers": new_headers,
                    })
                    await send({
                        "type": "http.response.body",
                        "body": response_body_buffer,
                        "more_body": False,
                    })
                    return

                # Pass through if inspect_response is False and not yet started
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

    def _apply_redaction_to_body(
        self,
        body: bytes,
        content_type: str,
        scan_text: str,
        sanitized_text: str,
    ) -> Optional[bytes]:
        """Apply sanitized text into request payload body."""
        if not body:
            return None
        if "application/json" in content_type:
            try:
                decoded = body.decode("utf-8")
                data = json.loads(decoded)
                if isinstance(data, dict):
                    for key in ("prompt", "message", "text", "input", "query", "content"):
                        if key in data and isinstance(data[key], str) and data[key] == scan_text:
                            data[key] = sanitized_text
                            return json.dumps(data).encode("utf-8")
                    for k, v in data.items():
                        if isinstance(v, str) and scan_text in v:
                            data[k] = v.replace(scan_text, sanitized_text)
                            return json.dumps(data).encode("utf-8")
                elif isinstance(data, str):
                    return json.dumps(sanitized_text).encode("utf-8")
            except Exception:
                pass
        try:
            decoded = body.decode("utf-8")
            if scan_text in decoded:
                return decoded.replace(scan_text, sanitized_text).encode("utf-8")
            return sanitized_text.encode("utf-8")
        except UnicodeDecodeError:
            return None

    def _update_scope_content_length(self, scope: Dict[str, Any], new_length: int) -> None:
        """Update content-length header in ASGI scope."""
        if "headers" in scope and isinstance(scope["headers"], list):
            new_headers = []
            has_cl = False
            for k, v in scope["headers"]:
                if k.lower() == b"content-length":
                    has_cl = True
                    new_headers.append((b"content-length", str(new_length).encode("ascii")))
                else:
                    new_headers.append((k, v))
            if has_cl:
                scope["headers"] = new_headers

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
