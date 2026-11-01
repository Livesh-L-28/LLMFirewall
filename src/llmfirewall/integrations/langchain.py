"""LangChain and LCEL (LangChain Expression Language) Security Integration for LLMFirewall.

Provides non-intrusive security hooks and composable Runnables for:
1. `FirewallRunnable`: First-class LCEL component composable with `|` (e.g. `guard | prompt | model | guard`).
2. `FirewallCallbackHandler`: Full callback lifecycle handler for LLM, ChatModel, Agent, and Tool execution.

Works seamlessly with `langchain-core` / `langchain` when installed, and provides
zero-dependency duck-typed Runnable and Callback implementations when uninstalled.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import json
import logging
from typing import Any, AsyncIterator, Callable, Dict, Iterator, List, Optional, Sequence, Union

from llmfirewall.core.exceptions import BlockedOutputError, BlockedPromptError
from llmfirewall.core.models import Action, ScanResult
from llmfirewall.firewall import Firewall
from llmfirewall.integrations.base import FirewallIntegration, SecurityViolation
from llmfirewall.integrations.context import SecurityContext, get_current_context
from llmfirewall.tools.models import ToolCall, ToolSecurityDecision

logger = logging.getLogger("llmfirewall.integrations.langchain")

try:
    from langchain_core.callbacks.base import BaseCallbackHandler, AsyncCallbackHandler
    from langchain_core.messages import BaseMessage
    from langchain_core.outputs import LLMResult
    from langchain_core.runnables import Runnable, RunnableConfig
    HAS_LANGCHAIN = True
except ImportError:
    try:
        from langchain.callbacks.base import BaseCallbackHandler  # type: ignore
        from langchain.schema import BaseMessage, LLMResult  # type: ignore
        HAS_LANGCHAIN = True
        AsyncCallbackHandler = object  # type: ignore
        Runnable = object  # type: ignore
    except ImportError:
        HAS_LANGCHAIN = False
        BaseCallbackHandler = object  # type: ignore
        AsyncCallbackHandler = object  # type: ignore
        Runnable = object  # type: ignore


class FirewallRunnable(FirewallIntegration):
    """Composable LCEL Runnable component for input scanning, output verification, and redaction.

    Usage:
        from llmfirewall.integrations.langchain import FirewallRunnable

        input_guard = FirewallRunnable(direction="input")
        output_guard = FirewallRunnable(direction="output")

        # Compose with standard LCEL pipe syntax:
        chain = input_guard | prompt_template | model | output_guard | output_parser
    """

    def __init__(
        self,
        firewall: Optional[Firewall] = None,
        direction: str = "input",  # "input" or "output"
        fail_closed: bool = True,
        input_keys: Optional[List[str]] = None,
    ) -> None:
        super().__init__(firewall=firewall)
        if direction not in ("input", "output"):
            raise ValueError(f"direction must be 'input' or 'output', got '{direction}'")
        self.direction = direction
        self.fail_closed = fail_closed
        self.input_keys = input_keys or ["input", "prompt", "question", "text", "query", "messages"]

    def _resolve_context(self, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Extract security context from LCEL RunnableConfig or active thread context."""
        ctx: Dict[str, Any] = {}
        active = get_current_context()
        if active:
            ctx.update(active.safe_dict())

        if config and isinstance(config, dict):
            metadata = config.get("metadata", {})
            if isinstance(metadata, dict):
                ctx.update(metadata)
            configurable = config.get("configurable", {})
            if isinstance(configurable, dict):
                for k in ("tenant_id", "session_id", "agent_id", "trace_id"):
                    if k in configurable:
                        ctx[k] = configurable[k]
        return ctx

    def invoke(self, input_data: Any, config: Optional[Dict[str, Any]] = None) -> Any:
        """Synchronously execute security inspection on the incoming LCEL data."""
        ctx = self._resolve_context(config)

        # 1. Plain String Input
        if isinstance(input_data, str):
            if not input_data.strip():
                return input_data

            if self.direction == "input":
                scan_res = self.firewall.scan_prompt(input_data, context=ctx)
            else:
                scan_res = self.firewall.scan_output(input_data, context=ctx)

            if scan_res.is_blocked:
                if self.fail_closed:
                    raise SecurityViolation(
                        f"LangChain LCEL {self.direction} blocked by policy: {scan_res.reason}",
                        scan_result=scan_res,
                        status_code=403,
                    )
                return input_data

            if scan_res.action == Action.REDACT and scan_res.processed_text:
                return scan_res.processed_text
            return input_data

        # 2. Dictionary Input (e.g. {"input": "...", "chat_history": [...]})
        elif isinstance(input_data, dict):
            sanitized = dict(input_data)
            for k, v in input_data.items():
                if k in self.input_keys and isinstance(v, str) and v.strip():
                    if self.direction == "input":
                        scan_res = self.firewall.scan_prompt(v, context=ctx)
                    else:
                        scan_res = self.firewall.scan_output(v, context=ctx)

                    if scan_res.is_blocked:
                        if self.fail_closed:
                            raise SecurityViolation(
                                f"LangChain LCEL input key '{k}' blocked: {scan_res.reason}",
                                scan_result=scan_res,
                                status_code=403,
                            )
                        return input_data

                    if scan_res.action == Action.REDACT and scan_res.processed_text:
                        sanitized[k] = scan_res.processed_text

                # Message objects list inside dict
                elif k in self.input_keys and isinstance(v, list):
                    sanitized_list = []
                    for item in v:
                        content = getattr(item, "content", None)
                        if isinstance(content, str) and content.strip():
                            if self.direction == "input":
                                scan_res = self.firewall.scan_prompt(content, context=ctx)
                            else:
                                scan_res = self.firewall.scan_output(content, context=ctx)

                            if scan_res.is_blocked and self.fail_closed:
                                raise SecurityViolation(
                                    f"LangChain message content in key '{k}' blocked: {scan_res.reason}",
                                    scan_result=scan_res,
                                    status_code=403,
                                )

                            if scan_res.action == Action.REDACT and scan_res.processed_text:
                                if hasattr(item, "model_copy"):
                                    item = item.model_copy(update={"content": scan_res.processed_text})
                                elif hasattr(item, "content"):
                                    try:
                                        item.content = scan_res.processed_text
                                    except Exception:
                                        pass
                        sanitized_list.append(item)
                    sanitized[k] = sanitized_list

            return sanitized

        # 3. Message object with .content attribute
        elif hasattr(input_data, "content") and isinstance(input_data.content, str):
            content = input_data.content
            if content.strip():
                if self.direction == "input":
                    scan_res = self.firewall.scan_prompt(content, context=ctx)
                else:
                    scan_res = self.firewall.scan_output(content, context=ctx)

                if scan_res.is_blocked:
                    if self.fail_closed:
                        raise SecurityViolation(
                            f"LangChain message content blocked by policy: {scan_res.reason}",
                            scan_result=scan_res,
                            status_code=403,
                        )
                    return input_data

                if scan_res.action == Action.REDACT and scan_res.processed_text:
                    if hasattr(input_data, "model_copy"):
                        return input_data.model_copy(update={"content": scan_res.processed_text})
                    try:
                        input_data.content = scan_res.processed_text
                    except Exception:
                        pass
            return input_data

        return input_data

    async def ainvoke(self, input_data: Any, config: Optional[Dict[str, Any]] = None) -> Any:
        """Asynchronously execute security inspection using threadpool executor."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, functools.partial(self.invoke, input_data, config=config))

    def stream(self, input_data: Any, config: Optional[Dict[str, Any]] = None) -> Iterator[Any]:
        """Stream output for LCEL compatibility."""
        yield self.invoke(input_data, config=config)

    async def astream(self, input_data: Any, config: Optional[Dict[str, Any]] = None) -> AsyncIterator[Any]:
        """Async stream output for LCEL compatibility."""
        res = await self.ainvoke(input_data, config=config)
        yield res

    def batch(self, inputs: List[Any], config: Optional[Union[Dict[str, Any], List[Dict[str, Any]]]] = None) -> List[Any]:
        """Batch execution for LCEL."""
        return [self.invoke(inp, config=config if isinstance(config, dict) else None) for inp in inputs]

    async def abatch(self, inputs: List[Any], config: Optional[Union[Dict[str, Any], List[Dict[str, Any]]]] = None) -> List[Any]:
        """Async batch execution for LCEL."""
        tasks = [self.ainvoke(inp, config=config if isinstance(config, dict) else None) for inp in inputs]
        return await asyncio.gather(*tasks)

    # -------------------------------------------------------------------------
    # LCEL Composition Pipe Operators (`|`)
    # -------------------------------------------------------------------------

    def __or__(self, other: Any) -> Any:
        """Support standard LCEL `guard | other` pipeline composition."""
        return RunnableSequence([self, other])

    def __ror__(self, other: Any) -> Any:
        """Support standard LCEL `other | guard` pipeline composition."""
        return RunnableSequence([other, self])


class RunnableSequence:
    """Lightweight duck-typed sequence supporting LCEL composition."""

    def __init__(self, steps: List[Any]) -> None:
        self.steps = steps

    def __or__(self, other: Any) -> "RunnableSequence":
        return RunnableSequence(self.steps + [other])

    def invoke(self, input_data: Any, config: Optional[Dict[str, Any]] = None) -> Any:
        val = input_data
        for step in self.steps:
            if hasattr(step, "invoke"):
                val = step.invoke(val, config=config)
            elif callable(step):
                val = step(val)
            else:
                val = step
        return val

    async def ainvoke(self, input_data: Any, config: Optional[Dict[str, Any]] = None) -> Any:
        val = input_data
        for step in self.steps:
            if hasattr(step, "ainvoke"):
                val = await step.ainvoke(val, config=config)
            elif hasattr(step, "invoke"):
                val = step.invoke(val, config=config)
            elif inspect.iscoroutinefunction(step):
                val = await step(val)
            elif callable(step):
                val = step(val)
            else:
                val = step
        return val


class FirewallCallbackHandler(FirewallIntegration, BaseCallbackHandler):
    """LangChain callback handler inspecting prompt inputs, agent tool calls, and LLM outputs.

    Protects:
    1. on_llm_start: Inspects incoming prompt strings or ChatMessages for injections and sensitive data.
    2. on_tool_start: Intercepts tool calls and validates tool name & arguments against tool security policies.
    3. on_llm_end: Inspects outgoing LLM completions before downstream chains consume them.
    4. on_tool_end: Inspects tool result strings for sensitive leaks or credentials.
    """

    def __init__(
        self,
        firewall: Optional[Firewall] = None,
        inspect_prompts: bool = True,
        inspect_outputs: bool = True,
        inspect_tools: bool = True,
        raise_on_block: bool = True,
    ) -> None:
        if not HAS_LANGCHAIN:
            raise ImportError(
                "LangChain is not installed. To use the LangChain integration, "
                "install it via: pip install 'llmfirewall-core[langchain]'"
            )
        BaseCallbackHandler.__init__(self)
        FirewallIntegration.__init__(self, firewall=firewall)
        self.inspect_prompts = inspect_prompts
        self.inspect_outputs = inspect_outputs
        self.inspect_tools = inspect_tools
        self.raise_on_block = raise_on_block

    def _resolve_context(self, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        ctx = dict(metadata or {})
        active = get_current_context()
        if active:
            ctx.update(active.safe_dict())
        return ctx

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        *,
        run_id: Optional[Any] = None,
        parent_run_id: Optional[Any] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Any:
        """Inspect prompt strings before submission to LLM."""
        if not self.inspect_prompts:
            return

        ctx = self._resolve_context(metadata)
        for p in prompts:
            res: ScanResult = self.firewall.check_prompt(p, context=ctx)
            if res.decision.action == Action.BLOCK and self.raise_on_block:
                raise SecurityViolation(
                    f"LangChain prompt rejected by security policy: {res.decision.reason}",
                    scan_result=res,
                    request_id=res.request_id,
                )

    def on_chat_model_start(
        self,
        serialized: Dict[str, Any],
        messages: List[List[Any]],
        *,
        run_id: Optional[Any] = None,
        parent_run_id: Optional[Any] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Any:
        """Inspect chat messages before submission to ChatModel."""
        if not self.inspect_prompts:
            return

        ctx = self._resolve_context(metadata)
        for msg_list in messages:
            for m in msg_list:
                content = getattr(m, "content", "")
                if isinstance(content, str) and content.strip():
                    res = self.firewall.check_prompt(content, context=ctx)
                    if res.decision.action == Action.BLOCK and self.raise_on_block:
                        raise SecurityViolation(
                            f"LangChain chat message rejected by security policy: {res.decision.reason}",
                            scan_result=res,
                            request_id=res.request_id,
                        )

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id: Optional[Any] = None,
        parent_run_id: Optional[Any] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        inputs: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Any:
        """Inspect agent tool invocations before execution (SSRF, paths, dangerous tools)."""
        if not self.inspect_tools:
            return

        ctx = self._resolve_context(metadata)
        tool_name = serialized.get("name") or serialized.get("id", ["tool"])[-1]
        args: Dict[str, Any] = {}
        if inputs and isinstance(inputs, dict):
            args = inputs
        elif input_str:
            try:
                args = json.loads(input_str)
            except Exception:
                args = {"query": input_str}

        decision: ToolSecurityDecision = self.firewall.check_tool_call(
            tool_call_or_name=tool_name,
            arguments=args,
            context=ctx,
        )
        if decision.is_blocked and self.raise_on_block:
            raise SecurityViolation(
                f"LangChain tool call '{tool_name}' blocked by security policy: {decision.reason}",
                status_code=403,
            )

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: Optional[Any] = None,
        parent_run_id: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Any:
        """Inspect tool execution outputs before sending back to LLM."""
        if not self.inspect_tools or not isinstance(output, str):
            return

        ctx = self._resolve_context(metadata)
        tool_res_dec = self.firewall.check_tool_result("langchain_tool", output=output)
        if tool_res_dec.is_blocked and self.raise_on_block:
            raise SecurityViolation(
                f"LangChain tool result blocked by security policy: {tool_res_dec.reason}",
                status_code=403,
            )

    def on_llm_end(
        self,
        response: Any,
        *,
        run_id: Optional[Any] = None,
        parent_run_id: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Any:
        """Inspect LLM generations before completing chain."""
        if not self.inspect_outputs or not hasattr(response, "generations"):
            return

        ctx = self._resolve_context(metadata)
        for gen_list in response.generations:
            for g in gen_list:
                text = getattr(g, "text", "")
                if text:
                    res = self.firewall.check_output(text)
                    if res.decision.action == Action.BLOCK and self.raise_on_block:
                        raise SecurityViolation(
                            f"LangChain LLM output rejected by security policy: {res.decision.reason}",
                            scan_result=res,
                            status_code=403,
                        )


# Backward-compatible alias
LLMFirewallCallbackHandler = FirewallCallbackHandler
