"""Model Context Protocol (MCP) Security Integration for LLMFirewall.

Provides protocol-level security enforcement for Anthropic / Linux Foundation
Model Context Protocol (MCP) servers and clients.

Guarantees:
1. Pre-execution argument sandboxing on `tools/call` requests (blocking SSRF,
   directory traversal, shell injection, and oversized payloads).
2. Content redaction and secret scanning on MCP tool execution outputs.
3. Strict failure isolation adhering to JSON-RPC 2.0 error specifications.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Union

from llmfirewall.core.models import Action
from llmfirewall.firewall import Firewall
from llmfirewall.integrations.base import FirewallIntegration, SecurityViolation
from llmfirewall.tools.models import ToolSecurityDecision


class MCPToolGuard(FirewallIntegration):
    """Protocol-level security guard for Model Context Protocol (MCP) servers and clients."""

    def __init__(
        self,
        firewall: Optional[Firewall] = None,
        fail_closed: bool = True,
    ) -> None:
        super().__init__(firewall=firewall)
        self.fail_closed = fail_closed

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
        decision: ToolSecurityDecision = self.firewall.check_tool_call(
            tool_call_or_name=resolved_name,
            arguments=args,
            session_id=session_id,
            context=context,
        )

        if decision.is_blocked and self.fail_closed:
            raise SecurityViolation(
                f"MCP tool '{resolved_name}' invocation rejected by security policy: {decision.reason}",
                status_code=403,
            )

        return decision

    def intercept_tool_result(
        self,
        name: str,
        result: Any,
        context: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Inspects and sanitizes the output produced by an MCP tool execution.
        
        - If Action.BLOCK: raises SecurityViolation.
        - If Action.REDACT: returns sanitized string or content blocks.
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

        if raw_text:
            scan_res = self.firewall.scan_output(raw_text, context=context)
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

    def intercept_jsonrpc(
        self,
        rpc_request: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Intercepts a raw MCP JSON-RPC 2.0 message envelope.
        
        If the method is `tools/call` and policy blocks it, returns a standardized
        JSON-RPC 2.0 error dictionary instead of executing.
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
