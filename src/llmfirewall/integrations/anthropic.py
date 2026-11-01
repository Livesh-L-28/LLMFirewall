"""Anthropic Python SDK Integration for LLMFirewall.

Provides non-intrusive prompt inspection, system prompt leak protection,
PII redaction, and response content filtering for Anthropic Claude clients.
Zero mandatory external dependencies: works with official `anthropic` SDK or duck-typed mocks.
"""

from __future__ import annotations

import functools
from typing import Any, Callable, Dict, Generator, List, Optional, Union

from llmfirewall.core.models import Action, ScanResult
from llmfirewall.firewall import Firewall
from llmfirewall.integrations.base import FirewallIntegration, SecurityViolation
from llmfirewall.integrations.stream import StreamingTextGuard


class AnthropicGuard(FirewallIntegration):
    """Security guard for Anthropic Claude messages, completions, and streams."""

    def __init__(
        self,
        firewall: Optional[Firewall] = None,
        inspect_inputs: bool = True,
        inspect_outputs: bool = True,
        fail_closed: bool = True,
    ) -> None:
        super().__init__(firewall=firewall)
        self.inspect_inputs = inspect_inputs
        self.inspect_outputs = inspect_outputs
        self.fail_closed = fail_closed
        self.stream_guard = StreamingTextGuard(firewall=self.firewall, fail_closed=self.fail_closed)

    def guard_messages(
        self,
        messages: List[Dict[str, Any]],
        system: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> tuple[List[Dict[str, Any]], Optional[str]]:
        """Inspect and sanitize input messages and system prompt.
        
        - If Action.BLOCK: raises SecurityViolation (HTTP 403).
        - If Action.REDACT: updates message content with sanitized text.
        """
        if not self.inspect_inputs:
            return messages, system

        ctx = dict(context or {})
        sanitized_system = system

        if system and isinstance(system, str) and system.strip():
            scan_sys = self.firewall.scan_prompt(system, context=ctx)
            if scan_sys.is_blocked and self.fail_closed:
                raise SecurityViolation(
                    f"Anthropic system prompt blocked by policy: {scan_sys.reason}",
                    scan_result=scan_sys,
                    status_code=403,
                )
            if scan_sys.action == Action.REDACT and scan_sys.processed_text:
                sanitized_system = scan_sys.processed_text

        sanitized_messages: List[Dict[str, Any]] = []
        for msg in messages:
            if not isinstance(msg, dict):
                sanitized_messages.append(msg)
                continue

            content = msg.get("content")
            if isinstance(content, str) and content.strip():
                scan_res: ScanResult = self.firewall.scan_prompt(content, context=ctx)
                if scan_res.is_blocked:
                    if self.fail_closed:
                        raise SecurityViolation(
                            f"Anthropic user message blocked by policy: {scan_res.reason}",
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
            else:
                sanitized_messages.append(msg)

        return sanitized_messages, sanitized_system

    def guard_response(
        self,
        response: Any,
        context: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Inspect output completion response from Anthropic Claude.
        
        - If Action.BLOCK: raises SecurityViolation.
        - If Action.REDACT: replaces content block text with sanitized text.
        """
        if not self.inspect_outputs or response is None:
            return response

        # Anthropic response: response.content is a list of TextBlock objects or dicts
        raw_text = ""
        if hasattr(response, "content") and response.content:
            first_block = response.content[0]
            raw_text = getattr(first_block, "text", "")
        elif isinstance(response, dict) and response.get("content"):
            content_list = response["content"]
            if content_list and isinstance(content_list[0], dict):
                raw_text = content_list[0].get("text", "")

        if raw_text:
            scan_res = self.firewall.scan_output(raw_text, context=context)
            if scan_res.is_blocked:
                if self.fail_closed:
                    raise SecurityViolation(
                        f"Anthropic output response blocked by policy: {scan_res.reason}",
                        scan_result=scan_res,
                        status_code=403,
                    )
                return response

            if scan_res.action == Action.REDACT and scan_res.processed_text:
                if hasattr(response, "content") and response.content:
                    if hasattr(response.content[0], "text"):
                        response.content[0].text = scan_res.processed_text
                elif isinstance(response, dict) and response.get("content"):
                    response["content"][0]["text"] = scan_res.processed_text

        return response

    def protect_stream(
        self,
        stream: Any,
        context: Optional[Dict[str, Any]] = None,
    ) -> Generator[str, None, None]:
        """Wrap and yield safe text tokens from an Anthropic streaming response."""
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

        return self.stream_guard.protect_stream(token_generator(), context=context)


def wrap_anthropic(
    client: Any,
    firewall: Optional[Firewall] = None,
    fail_closed: bool = True,
) -> Any:
    """Wraps an Anthropic client instance with automated LLMFirewall security guardrails.
    
    Usage:
        import anthropic
        from llmfirewall.integrations.anthropic import wrap_anthropic
        
        client = wrap_anthropic(anthropic.Anthropic())
        # All client.messages.create calls are now automatically secured!
    """
    guard = AnthropicGuard(firewall=firewall, fail_closed=fail_closed)

    orig_create = client.messages.create

    @functools.wraps(orig_create)
    def guarded_create(*args: Any, **kwargs: Any) -> Any:
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

    client.messages.create = guarded_create
    setattr(client, "_llmfirewall_guard", guard)
    return client
