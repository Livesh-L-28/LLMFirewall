"""OpenAI Python SDK Integration for LLMFirewall.

Provides non-intrusive pre-execution prompt inspection, PII sanitization,
output content filtering, and sliding-window stream protection for OpenAI clients.
Zero mandatory external dependencies: works with official `openai` SDK or duck-typed mocks.
"""

from __future__ import annotations

import functools
from typing import Any, Callable, Dict, Generator, List, Optional, Union

from llmfirewall.core.models import Action, ScanResult
from llmfirewall.firewall import Firewall
from llmfirewall.integrations.base import FirewallIntegration, SecurityViolation
from llmfirewall.integrations.stream import StreamingTextGuard


class OpenAIGuard(FirewallIntegration):
    """Security guard for OpenAI chat completions, responses, and streams."""

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
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Inspect and sanitize input messages.
        
        - If Action.BLOCK: raises SecurityViolation (HTTP 403).
        - If Action.REDACT: updates message content with sanitized text.
        - Preserves message roles and non-text structures.
        """
        if not self.inspect_inputs or not messages:
            return messages

        sanitized_messages: List[Dict[str, Any]] = []
        ctx = dict(context or {})

        for msg in messages:
            if not isinstance(msg, dict):
                sanitized_messages.append(msg)
                continue

            role = msg.get("role", "user")
            content = msg.get("content")

            # Only inspect string content for user or system messages
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
            else:
                sanitized_messages.append(msg)

        return sanitized_messages

    def guard_response(
        self,
        response: Any,
        context: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Inspect output completion response from OpenAI.
        
        - If Action.BLOCK: raises SecurityViolation.
        - If Action.REDACT: replaces choice message content with sanitized text.
        """
        if not self.inspect_outputs or response is None:
            return response

        # Extract text from object or dict choices
        text_content = ""
        choice_obj = None

        if hasattr(response, "choices") and response.choices:
            choice_obj = response.choices[0]
            if hasattr(choice_obj, "message") and hasattr(choice_obj.message, "content"):
                text_content = choice_obj.message.content or ""
        elif isinstance(response, dict) and response.get("choices"):
            choices = response["choices"]
            if choices and isinstance(choices[0], dict):
                msg = choices[0].get("message", {})
                text_content = msg.get("content", "")

        if text_content:
            scan_res = self.firewall.scan_output(text_content, context=context)
            if scan_res.is_blocked:
                if self.fail_closed:
                    raise SecurityViolation(
                        f"OpenAI output completion blocked by policy: {scan_res.reason}",
                        scan_result=scan_res,
                        status_code=403,
                    )
                return response

            if scan_res.action == Action.REDACT and scan_res.processed_text:
                if hasattr(response, "choices") and response.choices:
                    response.choices[0].message.content = scan_res.processed_text
                elif isinstance(response, dict) and response.get("choices"):
                    response["choices"][0]["message"]["content"] = scan_res.processed_text

        return response

    def protect_stream(
        self,
        stream: Any,
        context: Optional[Dict[str, Any]] = None,
    ) -> Generator[str, None, None]:
        """Wrap and yield safe text tokens from an OpenAI streaming response."""
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

        return self.stream_guard.protect_stream(token_generator(), context=context)


def wrap_openai(
    client: Any,
    firewall: Optional[Firewall] = None,
    fail_closed: bool = True,
) -> Any:
    """Wraps an OpenAI client instance with automated LLMFirewall security guardrails.
    
    Usage:
        import openai
        from llmfirewall.integrations.openai import wrap_openai
        
        client = wrap_openai(openai.OpenAI())
        # All client.chat.completions.create calls are now automatically secured!
    """
    guard = OpenAIGuard(firewall=firewall, fail_closed=fail_closed)

    orig_create = client.chat.completions.create

    @functools.wraps(orig_create)
    def guarded_create(*args: Any, **kwargs: Any) -> Any:
        messages = kwargs.get("messages")
        if messages:
            kwargs["messages"] = guard.guard_messages(messages)

        is_stream = kwargs.get("stream", False)
        resp = orig_create(*args, **kwargs)

        if is_stream:
            return guard.protect_stream(resp)
        return guard.guard_response(resp)

    client.chat.completions.create = guarded_create
    setattr(client, "_llmfirewall_guard", guard)
    return client
