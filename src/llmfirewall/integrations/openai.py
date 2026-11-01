"""OpenAI Python SDK Integration for LLMFirewall.

Provides non-intrusive pre-execution prompt inspection, structured message defense,
tool call argument sandboxing, PII sanitization, output filtering, and sliding-window
stream protection for both synchronous (OpenAI) and asynchronous (AsyncOpenAI) clients.

Zero mandatory external dependencies: works seamlessly with the official `openai` SDK,
custom gateways, or duck-typed client mocks.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import json
import logging
from typing import Any, AsyncGenerator, Callable, Dict, Generator, List, Optional, Union

from llmfirewall.core.models import Action, ScanResult
from llmfirewall.firewall import Firewall
from llmfirewall.integrations.base import FirewallIntegration, SecurityViolation
from llmfirewall.integrations.context import SecurityContext, get_current_context
from llmfirewall.integrations.stream import StreamingTextGuard
from llmfirewall.tools.models import ToolSecurityDecision

logger = logging.getLogger("llmfirewall.integrations.openai")


class OpenAIGuard(FirewallIntegration):
    """Security guard for OpenAI chat completions, responses, and token streams."""

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
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Inspect and sanitize input messages (supporting string and structured content blocks).

        - If Action.BLOCK: raises SecurityViolation (HTTP 403).
        - If Action.REDACT: updates message content with sanitized text.
        - Preserves message roles, metadata, and non-text parts.
        """
        if not self.inspect_inputs or not messages:
            return messages

        sanitized_messages: List[Dict[str, Any]] = []
        ctx = self._resolve_context(context)

        for msg in messages:
            if not isinstance(msg, dict):
                sanitized_messages.append(msg)
                continue

            role = msg.get("role", "user")
            content = msg.get("content")

            # Case 1: Simple string content
            if isinstance(content, str) and content.strip():
                scan_res: ScanResult = self.firewall.scan_prompt(content, context=ctx)
                if scan_res.is_blocked:
                    if self.fail_closed:
                        raise SecurityViolation(
                            f"OpenAI {role} message blocked by policy: {scan_res.reason}",
                            scan_result=scan_res,
                            status_code=403,
                        )
                    return messages

                if scan_res.action == Action.REDACT and scan_res.processed_text:
                    new_msg = dict(msg)
                    new_msg["content"] = scan_res.processed_text
                    sanitized_messages.append(new_msg)
                else:
                    sanitized_messages.append(msg)

            # Case 2: Structured multimodal or content parts list: [{"type": "text", "text": "..."}]
            elif isinstance(content, list):
                sanitized_parts: List[Any] = []
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        text_val = part.get("text", "")
                        if text_val and isinstance(text_val, str) and text_val.strip():
                            scan_res = self.firewall.scan_prompt(text_val, context=ctx)
                            if scan_res.is_blocked:
                                if self.fail_closed:
                                    raise SecurityViolation(
                                        f"OpenAI structured {role} message block blocked by policy: {scan_res.reason}",
                                        scan_result=scan_res,
                                        status_code=403,
                                    )
                                return messages

                            if scan_res.action == Action.REDACT and scan_res.processed_text:
                                new_part = dict(part)
                                new_part["text"] = scan_res.processed_text
                                sanitized_parts.append(new_part)
                            else:
                                sanitized_parts.append(part)
                        else:
                            sanitized_parts.append(part)
                    else:
                        sanitized_parts.append(part)
                new_msg = dict(msg)
                new_msg["content"] = sanitized_parts
                sanitized_messages.append(new_msg)
            else:
                sanitized_messages.append(msg)

        return sanitized_messages

    def guard_response(
        self,
        response: Any,
        context: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Inspect output completion response and tool calls from OpenAI.

        - If Action.BLOCK: raises SecurityViolation (HTTP 403).
        - If Action.REDACT: replaces choice message content with sanitized text.
        """
        if not self.inspect_outputs or response is None:
            return response

        ctx = self._resolve_context(context)

        # 1. Inspect Object-like response (standard official OpenAI model)
        if hasattr(response, "choices") and response.choices:
            for choice in response.choices:
                msg = getattr(choice, "message", None)
                if not msg:
                    continue

                # Content scanning
                content = getattr(msg, "content", None)
                if isinstance(content, str) and content.strip():
                    scan_res = self.firewall.scan_output(content, context=ctx)
                    if scan_res.is_blocked:
                        if self.fail_closed:
                            raise SecurityViolation(
                                f"OpenAI output completion blocked by policy: {scan_res.reason}",
                                scan_result=scan_res,
                                status_code=403,
                            )
                        return response

                    if scan_res.action == Action.REDACT and scan_res.processed_text:
                        msg.content = scan_res.processed_text

                # Tool calls argument sandboxing
                if self.inspect_tools and hasattr(msg, "tool_calls") and msg.tool_calls:
                    for tc in msg.tool_calls:
                        func = getattr(tc, "function", None)
                        if func and hasattr(func, "arguments"):
                            self._sandbox_tool_call(
                                getattr(func, "name", "tool"),
                                getattr(func, "arguments", "{}"),
                                context=ctx,
                            )

        # 2. Inspect Dictionary-like response (mock or direct JSON)
        elif isinstance(response, dict) and response.get("choices"):
            for choice in response["choices"]:
                if not isinstance(choice, dict):
                    continue
                msg = choice.get("message", {})
                content = msg.get("content")
                if isinstance(content, str) and content.strip():
                    scan_res = self.firewall.scan_output(content, context=ctx)
                    if scan_res.is_blocked:
                        if self.fail_closed:
                            raise SecurityViolation(
                                f"OpenAI output completion blocked by policy: {scan_res.reason}",
                                scan_result=scan_res,
                                status_code=403,
                            )
                        return response

                    if scan_res.action == Action.REDACT and scan_res.processed_text:
                        msg["content"] = scan_res.processed_text

                # Tool calls in dict
                if self.inspect_tools and msg.get("tool_calls"):
                    for tc in msg["tool_calls"]:
                        fn_obj = tc.get("function", {})
                        self._sandbox_tool_call(
                            fn_obj.get("name", "tool"),
                            fn_obj.get("arguments", "{}"),
                            context=ctx,
                        )

        return response

    def _sandbox_tool_call(
        self,
        name: str,
        arguments_raw: Union[str, Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Inspect model-generated tool call arguments for SSRF and traversal."""
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
                f"OpenAI tool call '{name}' blocked by security policy: {decision.reason}",
                status_code=403,
            )

    def protect_stream(
        self,
        stream: Any,
        context: Optional[Dict[str, Any]] = None,
    ) -> Generator[str, None, None]:
        """Wrap and yield safe text tokens from a synchronous OpenAI streaming response."""
        ctx = self._resolve_context(context)

        def token_generator():
            for chunk in stream:
                text = ""
                if hasattr(chunk, "choices") and chunk.choices:
                    delta = getattr(chunk.choices[0], "delta", None)
                    if delta and hasattr(delta, "content"):
                        text = delta.content or ""
                elif isinstance(chunk, dict) and chunk.get("choices"):
                    delta = chunk["choices"][0].get("delta", {})
                    text = delta.get("content", "")
                if text:
                    yield text

        return self.stream_guard.protect_stream(token_generator(), context=ctx)

    def protect_async_stream(
        self,
        async_stream: Any,
        context: Optional[Dict[str, Any]] = None,
    ) -> AsyncGenerator[str, None]:
        """Wrap and yield safe text tokens from an asynchronous OpenAI streaming response."""
        ctx = self._resolve_context(context)

        async def token_generator():
            async for chunk in async_stream:
                text = ""
                if hasattr(chunk, "choices") and chunk.choices:
                    delta = getattr(chunk.choices[0], "delta", None)
                    if delta and hasattr(delta, "content"):
                        text = delta.content or ""
                elif isinstance(chunk, dict) and chunk.get("choices"):
                    delta = chunk["choices"][0].get("delta", {})
                    text = delta.get("content", "")
                if text:
                    yield text

        return self.stream_guard.protect_async_stream(token_generator(), context=ctx)


def wrap_openai(
    client: Any,
    firewall: Optional[Firewall] = None,
    fail_closed: bool = True,
    inspect_inputs: bool = True,
    inspect_outputs: bool = True,
    inspect_tools: bool = True,
) -> Any:
    """Wraps an OpenAI or AsyncOpenAI client instance with automated LLMFirewall guardrails.

    Supports:
    - Synchronous `client.chat.completions.create`
    - Asynchronous `async_client.chat.completions.create`
    - Synchronous & asynchronous streaming
    - Structured content blocks (multimodal/tools)
    - Model tool call argument sandboxing

    Usage:
        import openai
        from llmfirewall.integrations.openai import wrap_openai

        client = wrap_openai(openai.OpenAI())
        # All completions calls are now automatically secured!
    """
    guard = OpenAIGuard(
        firewall=firewall,
        fail_closed=fail_closed,
        inspect_inputs=inspect_inputs,
        inspect_outputs=inspect_outputs,
        inspect_tools=inspect_tools,
    )

    orig_create = client.chat.completions.create
    is_async = inspect.iscoroutinefunction(orig_create) or asyncio.iscoroutinefunction(orig_create)

    if is_async:
        @functools.wraps(orig_create)
        async def guarded_async_create(*args: Any, **kwargs: Any) -> Any:
            messages = kwargs.get("messages")
            if messages:
                kwargs["messages"] = guard.guard_messages(messages)

            is_stream = kwargs.get("stream", False)
            resp = await orig_create(*args, **kwargs)

            if is_stream:
                return guard.protect_async_stream(resp)
            return guard.guard_response(resp)

        client.chat.completions.create = guarded_async_create
    else:
        @functools.wraps(orig_create)
        def guarded_sync_create(*args: Any, **kwargs: Any) -> Any:
            messages = kwargs.get("messages")
            if messages:
                kwargs["messages"] = guard.guard_messages(messages)

            is_stream = kwargs.get("stream", False)
            resp = orig_create(*args, **kwargs)

            if is_stream:
                return guard.protect_stream(resp)
            return guard.guard_response(resp)

        client.chat.completions.create = guarded_sync_create

    setattr(client, "_llmfirewall_guard", guard)
    return client
