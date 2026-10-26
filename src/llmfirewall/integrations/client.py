"""High-Level Developer Client Adapters for LLMFirewall v1.1.0 (Phase 51).

Provides clean, ergonomic synchronous and asynchronous client interfaces
for securing prompts, completions, streaming responses, and multi-turn sessions.
"""

from __future__ import annotations

import asyncio
import functools
from typing import Any, AsyncGenerator, AsyncIterable, Callable, Dict, Generator, Iterable, List, Optional
import uuid

from llmfirewall.core.exceptions import BlockedOutputError, BlockedPromptError
from llmfirewall.core.models import Action, ScanResult
from llmfirewall.firewall import Firewall
from llmfirewall.integrations.base import SecurityViolation
from llmfirewall.integrations.stream import StreamingTextGuard
from llmfirewall.policy import Policy


class ClientSessionContext:
    """Synchronous session wrapper for multi-turn conversational guardrails."""

    def __init__(self, client: "LLMFirewallClient", session_id: str, base_context: Optional[Dict[str, Any]] = None) -> None:
        self.client = client
        self.session_id = session_id
        self.base_context = base_context or {}
        self.turn_count = 0

    def __enter__(self) -> "ClientSessionContext":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        pass

    def scan_prompt(self, text: str, extra_context: Optional[Dict[str, Any]] = None) -> ScanResult:
        self.turn_count += 1
        ctx = {**self.base_context, "session_id": self.session_id, "turn": self.turn_count, **(extra_context or {})}
        return self.client.scan_prompt(text, context=ctx)

    def scan_output(self, text: str, prompt: Optional[str] = None, extra_context: Optional[Dict[str, Any]] = None) -> ScanResult:
        ctx = {**self.base_context, "session_id": self.session_id, "turn": self.turn_count, **(extra_context or {})}
        return self.client.scan_output(text, prompt=prompt, context=ctx)

    def protect_stream(self, stream: Iterable[str], extra_context: Optional[Dict[str, Any]] = None) -> Generator[str, None, None]:
        ctx = {**self.base_context, "session_id": self.session_id, "turn": self.turn_count, **(extra_context or {})}
        return self.client.protect_stream(stream, context=ctx)


class AsyncClientSessionContext:
    """Asynchronous session wrapper for multi-turn conversational guardrails."""

    def __init__(self, client: "AsyncLLMFirewallClient", session_id: str, base_context: Optional[Dict[str, Any]] = None) -> None:
        self.client = client
        self.session_id = session_id
        self.base_context = base_context or {}
        self.turn_count = 0

    async def __aenter__(self) -> "AsyncClientSessionContext":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        pass

    async def scan_prompt(self, text: str, extra_context: Optional[Dict[str, Any]] = None) -> ScanResult:
        self.turn_count += 1
        ctx = {**self.base_context, "session_id": self.session_id, "turn": self.turn_count, **(extra_context or {})}
        return await self.client.scan_prompt(text, context=ctx)

    async def scan_output(self, text: str, prompt: Optional[str] = None, extra_context: Optional[Dict[str, Any]] = None) -> ScanResult:
        ctx = {**self.base_context, "session_id": self.session_id, "turn": self.turn_count, **(extra_context or {})}
        return await self.client.scan_output(text, prompt=prompt, context=ctx)

    def protect_stream(self, stream: AsyncIterable[str], extra_context: Optional[Dict[str, Any]] = None) -> AsyncGenerator[str, None]:
        ctx = {**self.base_context, "session_id": self.session_id, "turn": self.turn_count, **(extra_context or {})}
        return self.client.protect_stream(stream, context=ctx)


class LLMFirewallClient:
    """Synchronous developer client adapter for LLMFirewall."""

    def __init__(
        self,
        firewall: Optional[Firewall] = None,
        policy: Optional[Policy] = None,
        fail_closed: bool = True,
    ) -> None:
        if firewall:
            self.firewall = firewall
        elif policy:
            self.firewall = Firewall(policy=policy)
        else:
            self.firewall = Firewall()
        self.fail_closed = fail_closed
        self.stream_guard = StreamingTextGuard(firewall=self.firewall, fail_closed=self.fail_closed)

    def scan_prompt(self, text: str, context: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Scan a prompt and enforce fail-closed security if blocked."""
        res = self.firewall.scan_prompt(text, context=context)
        if res.action == Action.BLOCK and self.fail_closed:
            raise SecurityViolation(f"Prompt blocked by firewall: {res.reason}", scan_result=res, status_code=403)
        return res

    def scan_output(self, text: str, prompt: Optional[str] = None, context: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Scan an LLM output and enforce fail-closed security if blocked."""
        res = self.firewall.scan_output(text, context=context)
        if res.action == Action.BLOCK and self.fail_closed:
            raise SecurityViolation(f"Output blocked by firewall: {res.reason}", scan_result=res, status_code=403)
        return res

    def protect_stream(self, stream: Iterable[str], context: Optional[Dict[str, Any]] = None) -> Generator[str, None, None]:
        """Wrap and yield safe streaming text chunks."""
        return self.stream_guard.protect_stream(stream, context=context)

    def protect_call(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Protect an LLM function execution, validating prompt and output."""
        # Find string prompt in args or kwargs
        prompt_val = ""
        prompt_arg_idx: Optional[int] = None
        prompt_kwarg_key: Optional[str] = None

        for idx, a in enumerate(args):
            if isinstance(a, str):
                prompt_val = a
                prompt_arg_idx = idx
                break
        if not prompt_val:
            for k in ("prompt", "text", "query", "message", "input"):
                if k in kwargs and isinstance(kwargs[k], str):
                    prompt_val = kwargs[k]
                    prompt_kwarg_key = k
                    break

        if prompt_val:
            in_res = self.scan_prompt(prompt_val)
            if in_res.action == Action.REDACT and in_res.sanitized_text:
                if prompt_arg_idx is not None:
                    args_list = list(args)
                    args_list[prompt_arg_idx] = in_res.sanitized_text
                    args = tuple(args_list)
                elif prompt_kwarg_key is not None:
                    kwargs[prompt_kwarg_key] = in_res.sanitized_text

        output = func(*args, **kwargs)

        if isinstance(output, str):
            out_res = self.scan_output(output, prompt=prompt_val)
            if out_res.action == Action.REDACT and out_res.sanitized_text:
                return out_res.sanitized_text

        return output

    def session(self, session_id: Optional[str] = None, context: Optional[Dict[str, Any]] = None) -> ClientSessionContext:
        """Create a multi-turn session guardrail context."""
        sess_id = session_id or str(uuid.uuid4())
        return ClientSessionContext(self, session_id=sess_id, base_context=context)


class AsyncLLMFirewallClient:
    """Asynchronous developer client adapter for asyncio LLM workflows."""

    def __init__(
        self,
        firewall: Optional[Firewall] = None,
        policy: Optional[Policy] = None,
        fail_closed: bool = True,
    ) -> None:
        if firewall:
            self.firewall = firewall
        elif policy:
            self.firewall = Firewall(policy=policy)
        else:
            self.firewall = Firewall()
        self.fail_closed = fail_closed
        self.stream_guard = StreamingTextGuard(firewall=self.firewall, fail_closed=self.fail_closed)

    async def scan_prompt(self, text: str, context: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Asynchronously scan a prompt (runs in threadpool executor to maintain non-blocking IO)."""
        loop = asyncio.get_running_loop()
        res = await loop.run_in_executor(None, functools.partial(self.firewall.scan_prompt, text, context=context))
        if res.action == Action.BLOCK and self.fail_closed:
            raise SecurityViolation(f"Prompt blocked by firewall: {res.reason}", scan_result=res, status_code=403)
        return res

    async def scan_output(self, text: str, prompt: Optional[str] = None, context: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Asynchronously scan an output."""
        loop = asyncio.get_running_loop()
        res = await loop.run_in_executor(None, functools.partial(self.firewall.scan_output, text, prompt=prompt, context=context))
        if res.action == Action.BLOCK and self.fail_closed:
            raise SecurityViolation(f"Output blocked by firewall: {res.reason}", scan_result=res, status_code=403)
        return res

    def protect_stream(self, stream: AsyncIterable[str], context: Optional[Dict[str, Any]] = None) -> AsyncGenerator[str, None]:
        """Wrap and yield safe streaming text chunks asynchronously."""
        return self.stream_guard.protect_async_stream(stream, context=context)

    async def protect_call(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Protect an async LLM function execution."""
        prompt_val = ""
        prompt_arg_idx: Optional[int] = None
        prompt_kwarg_key: Optional[str] = None

        for idx, a in enumerate(args):
            if isinstance(a, str):
                prompt_val = a
                prompt_arg_idx = idx
                break
        if not prompt_val:
            for k in ("prompt", "text", "query", "message", "input"):
                if k in kwargs and isinstance(kwargs[k], str):
                    prompt_val = kwargs[k]
                    prompt_kwarg_key = k
                    break

        if prompt_val:
            in_res = await self.scan_prompt(prompt_val)
            if in_res.action == Action.REDACT and in_res.sanitized_text:
                if prompt_arg_idx is not None:
                    args_list = list(args)
                    args_list[prompt_arg_idx] = in_res.sanitized_text
                    args = tuple(args_list)
                elif prompt_kwarg_key is not None:
                    kwargs[prompt_kwarg_key] = in_res.sanitized_text

        if asyncio.iscoroutinefunction(func):
            output = await func(*args, **kwargs)
        else:
            loop = asyncio.get_running_loop()
            output = await loop.run_in_executor(None, lambda: func(*args, **kwargs))

        if isinstance(output, str):
            out_res = await self.scan_output(output, prompt=prompt_val)
            if out_res.action == Action.REDACT and out_res.sanitized_text:
                return out_res.sanitized_text

        return output

    def session(self, session_id: Optional[str] = None, context: Optional[Dict[str, Any]] = None) -> AsyncClientSessionContext:
        """Create an async multi-turn session guardrail context."""
        sess_id = session_id or str(uuid.uuid4())
        return AsyncClientSessionContext(self, session_id=sess_id, base_context=context)
