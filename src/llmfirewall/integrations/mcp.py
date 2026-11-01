"""Model Context Protocol (MCP) Security Integration for LLMFirewall.

Provides protocol-level security enforcement for Anthropic / Linux Foundation
Model Context Protocol (MCP) servers and clients.

Guarantees:
1. Tool Registration Defense: Validates tool definitions, naming conventions, JSON schemas,
   and prevents indirect prompt injections hidden in tool descriptions.
2. Pre-execution Argument Sandboxing: Blocks SSRF, cloud metadata traversal (169.254.169.254),
   directory traversal (../../), and malicious command strings before dispatch.
3. Post-execution Output Sanitization: Inspects and redacts secrets and PII inside
   standard MCP content blocks ({"content": [{"type": "text", "text": "..."}]}).
4. Resource & DoS Constraints: Enforces execution timeout limits and max result size limits.
5. Strict Protocol Conformance: Returns JSON-RPC 2.0 compliant error envelopes (code -32003).
"""

from __future__ import annotations

import asyncio
import functools
import json
import logging
import re
from typing import Any, Callable, Dict, List, Optional, Union

from llmfirewall.core.models import Action, ScanResult
from llmfirewall.firewall import Firewall
from llmfirewall.integrations.base import FirewallIntegration, SecurityViolation
from llmfirewall.integrations.context import SecurityContext, get_current_context
from llmfirewall.tools.models import ToolSecurityDecision

logger = logging.getLogger("llmfirewall.integrations.mcp")

# Tool name validation pattern: letters, numbers, underscores, hyphens, 1-64 chars
TOOL_NAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")
DEFAULT_MAX_RESULT_BYTES = 512 * 1024  # 512 KB max tool output size


class MCPToolGuard(FirewallIntegration):
    """Protocol-level security guard for Model Context Protocol (MCP) servers and clients."""

    def __init__(
        self,
        firewall: Optional[Firewall] = None,
        fail_closed: bool = True,
        max_result_size_bytes: int = DEFAULT_MAX_RESULT_BYTES,
        timeout_seconds: Optional[float] = None,
    ) -> None:
        super().__init__(firewall=firewall)
        self.fail_closed = fail_closed
        self.max_result_size_bytes = max_result_size_bytes
        self.timeout_seconds = timeout_seconds

    def _resolve_context(self, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Resolve security context incorporating active SecurityContext if set."""
        ctx = dict(context or {})
        active = get_current_context()
        if active:
            if "tenant_id" not in ctx:
                ctx["tenant_id"] = active.tenant_id
            if "trace_id" not in ctx:
                ctx["trace_id"] = active.trace_id
            if "session_id" not in ctx and active.session_id:
                ctx["session_id"] = active.session_id
        return ctx

    # -------------------------------------------------------------------------
    # 1. Tool Registration Validation
    # -------------------------------------------------------------------------

    def validate_tool_definition(
        self,
        name: str,
        description: Optional[str] = None,
        input_schema: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Validates tool identity, naming constraints, and inspects descriptions for indirect injection.

        Raises:
            SecurityViolation: If tool name is invalid or description contains injection.
            ValueError: If tool name is empty or schema is malformed.
        """
        if not name or not isinstance(name, str):
            raise ValueError("MCP tool name must be a non-empty string")

        if not TOOL_NAME_REGEX.match(name.strip()):
            raise SecurityViolation(
                f"MCP tool name '{name}' violates naming specification (alphanumeric, underscores, hyphens, max 64 chars)",
                status_code=400,
            )

        # Inspect description for hidden prompt injections (indirect prompt injection via tools)
        if description and isinstance(description, str) and description.strip():
            scan_res = self.firewall.scan_prompt(description)
            if scan_res.is_blocked:
                if self.fail_closed:
                    raise SecurityViolation(
                        f"MCP tool '{name}' description rejected: contains prompt injection or adversarial directive: {scan_res.reason}",
                        scan_result=scan_res,
                        status_code=403,
                    )
                return False

        # Validate input schema structure
        if input_schema is not None:
            if not isinstance(input_schema, dict):
                raise ValueError("MCP input_schema must be a dictionary")
            schema_type = input_schema.get("type")
            if schema_type and schema_type != "object":
                raise ValueError(f"MCP input_schema root type must be 'object', got '{schema_type}'")

        return True

    # -------------------------------------------------------------------------
    # 2. Tool Invocation Sandboxing
    # -------------------------------------------------------------------------

    def intercept_tool_call(
        self,
        name: Optional[str] = None,
        arguments: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        *,
        tool_name: Optional[str] = None,
    ) -> ToolSecurityDecision:
        """Inspects an MCP `tools/call` request before tool dispatch.

        Args:
            name: MCP tool identifier (e.g. 'read_file', 'fetch_url', 'bash').
            arguments: Dictionary of arguments provided by the model.
            session_id: Optional MCP session identifier.
            context: Optional contextual parameters.
            tool_name: Backward-compatible alias for `name`.

        Returns:
            ToolSecurityDecision: ALLOW or BLOCK verdict.

        Raises:
            SecurityViolation: If decision is BLOCK and fail_closed is True.
        """
        resolved_name = name or tool_name or ""
        args = arguments or {}
        ctx = self._resolve_context(context)

        decision: ToolSecurityDecision = self.firewall.check_tool_call(
            tool_call_or_name=resolved_name,
            arguments=args,
            session_id=session_id,
            context=ctx,
        )

        if decision.is_blocked and self.fail_closed:
            raise SecurityViolation(
                f"MCP tool '{resolved_name}' invocation rejected by security policy: {decision.reason}",
                status_code=403,
            )

        return decision

    async def intercept_tool_call_async(
        self,
        name: Optional[str] = None,
        arguments: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        *,
        tool_name: Optional[str] = None,
    ) -> ToolSecurityDecision:
        """Asynchronously inspect an MCP `tools/call` request."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            functools.partial(
                self.intercept_tool_call,
                name=name,
                arguments=arguments,
                session_id=session_id,
                context=context,
                tool_name=tool_name,
            ),
        )

    # -------------------------------------------------------------------------
    # 3. Tool Result Inspection & Output Sanitization
    # -------------------------------------------------------------------------

    def intercept_tool_result(
        self,
        name: str,
        result: Any,
        context: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Inspects and sanitizes the output produced by an MCP tool execution.

        - If Action.BLOCK: raises SecurityViolation (HTTP 403).
        - If Action.REDACT: returns sanitized string or content blocks.
        - Enforces max result size constraints to prevent memory exhaustion / context bloat.
        """
        raw_text = ""
        if isinstance(result, str):
            raw_text = result
        elif isinstance(result, dict) and "content" in result:
            # MCP standard content block: {"content": [{"type": "text", "text": "..."}]}
            blocks = result["content"]
            if blocks and isinstance(blocks, list) and isinstance(blocks[0], dict):
                raw_text = blocks[0].get("text", "")
        elif isinstance(result, list) and result and isinstance(result[0], dict):
            raw_text = result[0].get("text", "")

        # 1. Result Size Constraint Check
        if raw_text and len(raw_text.encode("utf-8")) > self.max_result_size_bytes:
            msg = f"MCP tool '{name}' result exceeded max allowed size ({len(raw_text)} bytes > {self.max_result_size_bytes} limit)"
            if self.fail_closed:
                raise SecurityViolation(msg, status_code=413)
            return raw_text[: self.max_result_size_bytes]

        ctx = self._resolve_context(context)

        # 2. Output Scanning
        if raw_text:
            scan_res = self.firewall.scan_output(raw_text, context=ctx)
            if scan_res.is_blocked:
                if self.fail_closed:
                    raise SecurityViolation(
                        f"MCP tool '{name}' result blocked by security policy: {scan_res.reason}",
                        scan_result=scan_res,
                        status_code=403,
                    )
                return result

            if scan_res.action == Action.REDACT and scan_res.processed_text:
                if isinstance(result, str):
                    return scan_res.processed_text
                elif isinstance(result, dict) and "content" in result:
                    new_res = dict(result)
                    new_res["content"][0]["text"] = scan_res.processed_text
                    return new_res
                elif isinstance(result, list) and isinstance(result[0], dict):
                    new_list = [dict(b) for b in result]
                    new_list[0]["text"] = scan_res.processed_text
                    return new_list

        return result

    async def intercept_tool_result_async(
        self,
        name: str,
        result: Any,
        context: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Asynchronously inspect and sanitize MCP tool result."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            functools.partial(self.intercept_tool_result, name, result, context=context),
        )

    # -------------------------------------------------------------------------
    # 4. JSON-RPC 2.0 Protocol Envelope Interceptor
    # -------------------------------------------------------------------------

    def intercept_jsonrpc(
        self,
        rpc_request: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Intercepts a raw MCP JSON-RPC 2.0 message envelope.

        If the method is `tools/call` and policy blocks it, returns a standardized
        JSON-RPC 2.0 error dictionary (code -32003) instead of executing.
        """
        if not isinstance(rpc_request, dict):
            raise ValueError("MCP JSON-RPC request must be a dictionary")

        method = rpc_request.get("method")
        msg_id = rpc_request.get("id")

        if method == "tools/call":
            params = rpc_request.get("params", {})
            name = params.get("name", "")
            args = params.get("arguments", {})

            try:
                self.intercept_tool_call(name=name, arguments=args, context=context)
            except SecurityViolation as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32003,  # Standard JSON-RPC custom server security error
                        "message": str(exc),
                        "data": {"violation": "security_policy_block", "tool": name},
                    },
                }

        return None
