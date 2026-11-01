"""LangGraph Ecosystem Integration for LLMFirewall.

LangGraph applications execute stateful multi-agent graphs where state dictionaries
flow between nodes, conditional edges, subgraphs, and human-in-the-loop checkpoints.

This integration provides:
1. `guard_node`: Decorator protecting both synchronous and asynchronous LangGraph node execution.
   - Inspects input state keys with `scan_prompt` (injections, PII, prompt hijacking).
   - Inspects output state keys with `scan_output` (credential leaks, unsafe completions).
   - Enforces multi-agent tenant isolation.
   - Preserves distributed security context across state transitions.
2. `LangGraphStateGuard`: State dictionary inspection and sanitization engine.
3. `get_graph_callbacks`: Helper returning `FirewallCallbackHandler` instances for LangGraph runnable configs.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import logging
from typing import Any, Callable, Dict, List, Optional, Union

from llmfirewall.core.models import Action, ScanResult
from llmfirewall.firewall import Firewall
from llmfirewall.integrations.base import FirewallIntegration, SecurityViolation
from llmfirewall.integrations.context import SecurityContext, get_current_context, set_current_context
from llmfirewall.integrations.langchain import FirewallCallbackHandler, HAS_LANGCHAIN

logger = logging.getLogger("llmfirewall.integrations.langgraph")


class LangGraphStateGuard(FirewallIntegration):
    """Guard inspecting and sanitizing LangGraph state dictionaries."""

    def __init__(
        self,
        firewall: Optional[Firewall] = None,
        inspect_inputs: bool = True,
        inspect_outputs: bool = True,
        fail_closed: bool = True,
        tenant_id: Optional[str] = None,
        error_key: Optional[str] = None,
    ) -> None:
        super().__init__(firewall=firewall)
        self.inspect_inputs = inspect_inputs
        self.inspect_outputs = inspect_outputs
        self.fail_closed = fail_closed
        self.tenant_id = tenant_id
        self.error_key = error_key

    def _resolve_context(self, state: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Extract and resolve contextual attributes from state and distributed context."""
        ctx = dict(context or {})

        # 1. State-embedded security context or tenant
        state_ctx = state.get("_security_context")
        if isinstance(state_ctx, dict):
            ctx.update(state_ctx)
        elif isinstance(state_ctx, SecurityContext):
            ctx.update(state_ctx.safe_dict())

        if "tenant_id" not in ctx:
            if "tenant_id" in state:
                ctx["tenant_id"] = str(state["tenant_id"])
            elif self.tenant_id:
                ctx["tenant_id"] = self.tenant_id
            else:
                ctx["tenant_id"] = "default-tenant"

        if "session_id" not in ctx and "session_id" in state:
            ctx["session_id"] = str(state["session_id"])

        # 2. Ambient thread context or default current
        active = get_current_context() or SecurityContext.current(tenant_id=ctx.get("tenant_id"))
        for k in ("tenant_id", "trace_id", "session_id", "agent_id"):
            if k not in ctx and getattr(active, k, None):
                ctx[k] = getattr(active, k)

        return ctx

    def inspect_state(
        self,
        state: Dict[str, Any],
        target_keys: Optional[List[str]] = None,
        direction: str = "input",  # "input" or "output"
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Inspects string or message fields inside a LangGraph state dictionary."""
        if not isinstance(state, dict):
            return state

        ctx = self._resolve_context(state, context)

        # Multi-agent Tenant Isolation Check: verify state doesn't violate assigned node tenant
        if self.tenant_id and "tenant_id" in ctx:
            if ctx["tenant_id"] != self.tenant_id:
                msg = f"Tenant isolation violation in LangGraph state: expected '{self.tenant_id}', got '{ctx['tenant_id']}'"
                if self.fail_closed:
                    raise SecurityViolation(msg, status_code=403)
                if self.error_key:
                    err_state = dict(state)
                    err_state[self.error_key] = msg
                    return err_state
                return state

        keys = target_keys if target_keys is not None else list(state.keys())
        sanitized_state = dict(state)

        for k in keys:
            if k not in sanitized_state or k == "_security_context":
                continue

            val = sanitized_state[k]

            # 1. Single string field in state
            if isinstance(val, str) and val.strip():
                if direction == "input":
                    scan_res: ScanResult = self.firewall.scan_prompt(val, context=ctx)
                else:
                    scan_res: ScanResult = self.firewall.scan_output(val, context=ctx)

                if scan_res.is_blocked:
                    if self.fail_closed:
                        raise SecurityViolation(
                            f"LangGraph state key '{k}' blocked by policy: {scan_res.reason}",
                            scan_result=scan_res,
                            status_code=403,
                        )
                    if self.error_key:
                        sanitized_state[self.error_key] = scan_res.reason
                    return sanitized_state

                if scan_res.action == Action.REDACT and scan_res.processed_text:
                    sanitized_state[k] = scan_res.processed_text

            # 2. List of messages in state (e.g. ChatMessages)
            elif isinstance(val, list):
                sanitized_list = []
                for item in val:
                    content = getattr(item, "content", None)
                    if content is None and isinstance(item, dict):
                        content = item.get("content")

                    if isinstance(content, str) and content.strip():
                        if direction == "input":
                            scan_res = self.firewall.scan_prompt(content, context=ctx)
                        else:
                            scan_res = self.firewall.scan_output(content, context=ctx)

                        if scan_res.is_blocked:
                            if self.fail_closed:
                                raise SecurityViolation(
                                    f"LangGraph state message in '{k}' blocked: {scan_res.reason}",
                                    scan_result=scan_res,
                                    status_code=403,
                                )
                            if self.error_key:
                                sanitized_state[self.error_key] = scan_res.reason
                            return sanitized_state

                        if scan_res.action == Action.REDACT and scan_res.processed_text:
                            if hasattr(item, "model_copy"):
                                item = item.model_copy(update={"content": scan_res.processed_text})
                            elif hasattr(item, "content"):
                                try:
                                    item.content = scan_res.processed_text
                                except Exception:
                                    pass
                            elif isinstance(item, dict):
                                item = dict(item)
                                item["content"] = scan_res.processed_text
                    sanitized_list.append(item)
                sanitized_state[k] = sanitized_list

        # Propagate security context forward in state
        if "_security_context" not in sanitized_state and ctx:
            sanitized_state["_security_context"] = ctx

        return sanitized_state


def guard_node(
    node_fn: Optional[Callable] = None,
    *,
    guard: Optional[LangGraphStateGuard] = None,
    firewall: Optional[Firewall] = None,
    input_keys: Optional[List[str]] = None,
    output_keys: Optional[List[str]] = None,
    fail_closed: bool = True,
    tenant_id: Optional[str] = None,
    error_key: Optional[str] = None,
) -> Callable:
    """Decorator guarding a LangGraph node function (sync or async) against malicious inputs and leaks.

    Usage:
        @guard_node(input_keys=["messages"], output_keys=["agent_response"])
        def chatbot_node(state: Dict[str, Any]) -> Dict[str, Any]:
            ...

        @guard_node(input_keys=["query"])
        async def async_agent_node(state: Dict[str, Any]) -> Dict[str, Any]:
            ...
    """
    active_guard = guard if guard is not None else LangGraphStateGuard(
        firewall=firewall,
        fail_closed=fail_closed,
        tenant_id=tenant_id,
        error_key=error_key,
    )

    def decorator(fn: Callable) -> Callable:
        is_async = inspect.iscoroutinefunction(fn) or asyncio.iscoroutinefunction(fn)

        if is_async:
            @functools.wraps(fn)
            async def async_wrapper(state: Dict[str, Any], *args: Any, **kwargs: Any) -> Any:
                guarded_state = active_guard.inspect_state(state, target_keys=input_keys, direction="input")
                output_state = await fn(guarded_state, *args, **kwargs)
                if isinstance(output_state, dict):
                    if "_security_context" in guarded_state and "_security_context" not in output_state:
                        output_state["_security_context"] = guarded_state["_security_context"]
                    return active_guard.inspect_state(output_state, target_keys=output_keys, direction="output")
                return output_state

            return async_wrapper
        else:
            @functools.wraps(fn)
            def sync_wrapper(state: Dict[str, Any], *args: Any, **kwargs: Any) -> Any:
                guarded_state = active_guard.inspect_state(state, target_keys=input_keys, direction="input")
                output_state = fn(guarded_state, *args, **kwargs)
                if isinstance(output_state, dict):
                    if "_security_context" in guarded_state and "_security_context" not in output_state:
                        output_state["_security_context"] = guarded_state["_security_context"]
                    return active_guard.inspect_state(output_state, target_keys=output_keys, direction="output")
                return output_state

            return sync_wrapper

    if node_fn is not None:
        return decorator(node_fn)
    return decorator


def get_graph_callbacks(firewall: Optional[Firewall] = None) -> List[Any]:
    """Returns a list of LangChain callback handlers compatible with LangGraph runnable configs."""
    return [FirewallCallbackHandler(firewall=firewall)]
