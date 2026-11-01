"""Anthropic Python SDK Integration for LLMFirewall.

Provides non-intrusive prompt inspection, system prompt leak protection,
content block semantics preservation (text, tool_use, tool_result), PII redaction,
output filtering, and sliding-window stream defense for both synchronous (Anthropic)
and asynchronous (AsyncAnthropic) clients.

Zero mandatory external dependencies: works with the official `anthropic` SDK or duck-typed mocks.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import json
import logging
from typing import Any, AsyncGenerator, Callable, Dict, Generator, List, Optional, Tuple, Union

from llmfirewall.core.models import Action, ScanResult
from llmfirewall.firewall import Firewall
from llmfirewall.integrations.base import FirewallIntegration, SecurityViolation
from llmfirewall.integrations.context import SecurityContext, get_current_context
from llmfirewall.integrations.stream import StreamingTextGuard
from llmfirewall.tools.models import ToolSecurityDecision

logger = logging.getLogger("llmfirewall.integrations.anthropic")


class AnthropicGuard(FirewallIntegration):
    """Security guard for Anthropic Claude messages, completions, tool uses, and streams."""

    def __init__(
        self,
        firewall: Optional[Firewall] = None,
        inspect_inputs: bool = True,
        inspect_outputs: bool = True,
        inspect_tools: bool = True,
        fail_closed: bool = True,
    ) -> None:
        super().__init__(firewall=firewall)
        self.inspect_inputs = inspect_inputs
        self.inspect_outputs = inspect_outputs
        self.inspect_tools = inspect_tools
        self.fail_closed = fail_closed
        self.stream_guard = StreamingTextGuard(firewall=self.firewall, fail_closed=self.fail_closed)

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

    def guard_messages(
        self,
        messages: List[Dict[str, Any]],
        system: Optional[Union[str, List[Dict[str, Any]]]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[Dict[str, Any]], Optional[Union[str, List[Dict[str, Any]]]]]:
        """Inspect and sanitize input messages and system prompts preserving content blocks.

        - If Action.BLOCK: raises SecurityViolation (HTTP 403).
        - If Action.REDACT: updates message text or block content with sanitized text.
        - Preserves tool_use, tool_result, and multimodal content block semantics.
        """
        if not self.inspect_inputs:
            return messages, system

        ctx = self._resolve_context(context)
        sanitized_system = system

        # 1. System Prompt Inspection (string or list of content blocks)
        if system:
            if isinstance(system, str) and system.strip():
                scan_sys = self.firewall.scan_prompt(system, context=ctx)
                if scan_sys.is_blocked and self.fail_closed:
                    raise SecurityViolation(
                        f"Anthropic system prompt blocked by policy: {scan_sys.reason}",
                        scan_result=scan_sys,
                        status_code=403,
                    )
                if scan_sys.action == Action.REDACT and scan_sys.processed_text:
                    sanitized_system = scan_sys.processed_text
            elif isinstance(system, list):
                sanitized_sys_blocks: List[Any] = []
                for b in system:
                    if isinstance(b, dict) and b.get("type") == "text":
                        text_val = b.get("text", "")
                        if text_val and isinstance(text_val, str) and text_val.strip():
                            scan_sys = self.firewall.scan_prompt(text_val, context=ctx)
                            if scan_sys.is_blocked and self.fail_closed:
                                raise SecurityViolation(
                                    f"Anthropic system content block blocked by policy: {scan_sys.reason}",
                                    scan_result=scan_sys,
                                    status_code=403,
                                raid_code=403)
                            if scan_sys.action == Action.REDACT and scan_sys.processed_text:
                                new_b = dict(b)
                                new_b["text"] = scan_sys.processed_text
                                sanitized_sys_blocks.append(new_b)
                            else:
                                sanitized_sys_blocks.append(b)
                        else:
                            sanitized_sys_blocks.append(b)
                    else:
                        sanitized_sys_blocks.append(b)
                sanitized_system = sanitized_sys_blocks

        # 2. Messages Inspection
        sanitized_messages: List[Dict[str, Any]] = []
        for msg in messages:
            if not isinstance(msg, dict):
                sanitized_messages.append(msg)
                continue

            role = msg.get("role", "user")
            content = msg.get("content")

            # Case A: Simple string content
            if isinstance(content, str) and content.strip():
                scan_res: ScanResult = self.firewall.scan_prompt(content, context=ctx)
                if scan_res.is_blocked:
                    if self.fail_closed:
                        raise SecurityViolation(
                            f"Anthropic {role} message blocked by policy: {scan_res.reason}",
                            scan_result=scan_res,
                            status_code=403,
                        )
                    return messages, system

                if scan_res.action == Action.REDACT and scan_res.processed_text:
                    new_msg = dict(msg)
                    new_msg["content"] = scan_res.processed_text
                    sanitized_messages.append(new_msg)
                else:
                    sanitized_messages.append(msg)

            # Case B: Structured content block list (Text, ToolUse, ToolResult, Image)
            elif isinstance(content, list):
                sanitized_blocks: List[Any] = []
                for block in content:
                    if not isinstance(block, dict):
                        sanitized_blocks.append(block)
                        continue

                    block_type = block.get("type")

                    # Text block
                    if block_type == "text":
                        text_val = block.get("text", "")
                        if text_val and isinstance(text_val, str) and text_val.strip():
                            scan_res = self.firewall.scan_prompt(text_val, context=ctx)
                            if scan_res.is_blocked:
                                if self.fail_closed:
                                    raise SecurityViolation(
                                        f"Anthropic {role} message content block blocked by policy: {scan_res.reason}",
                                        scan_result=scan_res,
                                        status_code=403,
                                    )
                                return messages, system

                            if scan_res.action == Action.REDACT and scan_res.processed_text:
                                new_b = dict(block)
                                new_b["text"] = scan_res.processed_text
                                sanitized_blocks.append(new_b)
                            else:
                                sanitized_blocks.append(block)
                        else:
                            sanitized_blocks.append(block)

                    # Tool Result block
                    elif block_type == "tool_result":
                        res_val = block.get("content", "")
                        if isinstance(res_val, str) and res_val.strip():
                            scan_res = self.firewall.scan_output(res_val, context=ctx)
                            if scan_res.is_blocked:
                                if self.fail_closed:
                                    raise SecurityViolation(
                                        f"Anthropic tool_result block blocked by policy: {scan_res.reason}",
                                        scan_result=scan_res,
                                        status_code=403,
                                    )
                                return messages, system

                            if scan_res.action == Action.REDACT and scan_res.processed_text:
                                new_b = dict(block)
                                new_b["content"] = scan_res.processed_text
                                sanitized_blocks.append(new_b)
                            else:
                                sanitized_blocks.append(block)
                        else:
                            sanitized_blocks.append(block)
                    else:
                        sanitized_blocks.append(block)

                new_msg = dict(msg)
                new_msg["content"] = sanitized_blocks
                sanitized_messages.append(new_msg)
            else:
                sanitized_messages.append(msg)

        return sanitized_messages, sanitized_system

    def guard_response(
        self,
        response: Any,
        context: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Inspect output completion response from Anthropic Claude.

        - If Action.BLOCK: raises SecurityViolation (HTTP 403).
        - If Action.REDACT: replaces content block text with sanitized text.
        - Sandboxes tool_use blocks if present.
        """
        if not self.inspect_outputs or response is None:
            return response

        ctx = self._resolve_context(context)

        # 1. Object-like Response (Official Anthropic Message)
        if hasattr(response, "content") and response.content:
            for block in response.content:
                # TextBlock
                if getattr(block, "type", None) == "text" or hasattr(block, "text"):
                    raw_text = getattr(block, "text", "")
                    if raw_text:
                        scan_res = self.firewall.scan_output(raw_text, context=ctx)
                        if scan_res.is_blocked:
                            if self.fail_closed:
                                raise SecurityViolation(
                                    f"Anthropic output response blocked by policy: {scan_res.reason}",
                                    scan_result=scan_res,
                                    status_code=403,
                                )
                            return response

                        if scan_res.action == Action.REDACT and scan_res.processed_text:
                            block.text = scan_res.processed_text

                # ToolUseBlock
                elif getattr(block, "type", None) == "tool_use" and self.inspect_tools:
                    tool_name = getattr(block, "name", "tool")
                    tool_input = getattr(block, "input", {})
                    self._sandbox_tool_use(tool_name, tool_input, context=ctx)

        # 2. Dictionary-like Response
        elif isinstance(response, dict) and response.get("content"):
            content_list = response["content"]
            if isinstance(content_list, list):
                for block in content_list:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "text":
                        raw_text = block.get("text", "")
                        if raw_text:
                            scan_res = self.firewall.scan_output(raw_text, context=ctx)
                            if scan_res.is_blocked:
                                if self.fail_closed:
                                    raise SecurityViolation(
                                        f"Anthropic output response blocked by policy: {scan_res.reason}",
                                        scan_result=scan_res,
                                        status_code=403,
                                    )
                                return response

                            if scan_res.action == Action.REDACT and scan_res.processed_text:
                                block["text"] = scan_res.processed_text

                    elif block.get("type") == "tool_use" and self.inspect_tools:
                        self._sandbox_tool_use(
                            block.get("name", "tool"),
                            block.get("input", {}),
                            context=ctx,
                        )

        return response

    def _sandbox_tool_use(
        self,
        name: str,
        arguments_raw: Union[str, Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Inspect model tool_use blocks for SSRF and traversal."""
        args_dict: Dict[str, Any] = {}
        if isinstance(arguments_raw, str):
            try:
                args_dict = json.loads(arguments_raw)
            except Exception:
                args_dict = {"raw_args": arguments_raw}
        elif isinstance(arguments_raw, dict):
            args_dict = arguments_raw

        decision: ToolSecurityDecision = self.firewall.check_tool_call(
            tool_call_or_name=name,
            arguments=args_dict,
            context=context,
        )
        if decision.is_blocked and self.fail_closed:
            raise SecurityViolation(
                f"Anthropic tool_use '{name}' blocked by security policy: {decision.reason}",
                status_code=403,
            )

    def protect_stream(
        self,
        stream: Any,
        context: Optional[Dict[str, Any]] = None,
    ) -> Generator[str, None, None]:
        """Wrap and yield safe text tokens from an Anthropic synchronous streaming response."""
        ctx = self._resolve_context(context)

        def token_generator():
            for event in stream:
                text = ""
                # Anthropic message stream event: content_block_delta
                if hasattr(event, "delta") and hasattr(event.delta, "text"):
                    text = event.delta.text or ""
                elif isinstance(event, dict) and event.get("delta"):
                    text = event["delta"].get("text", "")
                if text:
                    yield text

        return self.stream_guard.protect_stream(token_generator(), context=ctx)

    def protect_async_stream(
        self,
        async_stream: Any,
        context: Optional[Dict[str, Any]] = None,
    ) -> AsyncGenerator[str, None]:
        """Wrap and yield safe text tokens from an Anthropic asynchronous streaming response."""
        ctx = self._resolve_context(context)

        async def token_generator():
            async for event in async_stream:
                text = ""
                if hasattr(event, "delta") and hasattr(event.delta, "text"):
                    text = event.delta.text or ""
                elif isinstance(event, dict) and event.get("delta"):
                    text = event["delta"].get("text", "")
                if text:
                    yield text

        return self.stream_guard.protect_async_stream(token_generator(), context=ctx)


def wrap_anthropic(
    client: Any,
    firewall: Optional[Firewall] = None,
    fail_closed: bool = True,
    inspect_inputs: bool = True,
    inspect_outputs: bool = True,
    inspect_tools: bool = True,
) -> Any:
    """Wraps an Anthropic or AsyncAnthropic client instance with automated LLMFirewall guardrails.

    Supports:
    - Synchronous `client.messages.create`
    - Asynchronous `async_client.messages.create`
    - Synchronous & asynchronous streaming
    - Content blocks (text, tool_use, tool_result)
    - System prompt inspection

    Usage:
        import anthropic
        from llmfirewall.integrations.anthropic import wrap_anthropic

        client = wrap_anthropic(anthropic.Anthropic())
        # All client.messages.create calls are now automatically secured!
    """
    guard = AnthropicGuard(
        firewall=firewall,
        fail_closed=fail_closed,
        inspect_inputs=inspect_inputs,
        inspect_outputs=inspect_outputs,
        inspect_tools=inspect_tools,
    )

    orig_create = client.messages.create
    is_async = inspect.iscoroutinefunction(orig_create) or asyncio.iscoroutinefunction(orig_create)

    if is_async:
        @functools.wraps(orig_create)
        async def guarded_async_create(*args: Any, **kwargs: Any) -> Any:
            messages = kwargs.get("messages")
            system = kwargs.get("system")
            if messages:
                sanitized_msgs, sanitized_sys = guard.guard_messages(messages, system=system)
                kwargs["messages"] = sanitized_msgs
                if sanitized_sys is not None:
                    kwargs["system"] = sanitized_sys

            is_stream = kwargs.get("stream", False)
            resp = await orig_create(*args, **kwargs)

            if is_stream:
                return guard.protect_async_stream(resp)
            return guard.guard_response(resp)

        client.messages.create = guarded_async_create
    else:
        @functools.wraps(orig_create)
        def guarded_sync_create(*args: Any, **kwargs: Any) -> Any:
            messages = kwargs.get("messages")
            system = kwargs.get("system")
            if messages:
                sanitized_msgs, sanitized_sys = guard.guard_messages(messages, system=system)
                kwargs["messages"] = sanitized_msgs
                if sanitized_sys is not None:
                    kwargs["system"] = sanitized_sys

            is_stream = kwargs.get("stream", False)
            resp = orig_create(*args, **kwargs)

            if is_stream:
                return guard.protect_stream(resp)
            return guard.guard_response(resp)

        client.messages.create = guarded_sync_create

    setattr(client, "_llmfirewall_guard", guard)
    return client
