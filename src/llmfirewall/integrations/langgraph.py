"""LangGraph Ecosystem Integration for LLMFirewall.

LangGraph applications execute stateful multi-agent graphs where state dictionaries
flow between nodes. This integration provides:
1. `guard_node`: Decorator protecting LangGraph node execution (sanitizing input state,
   blocking injection, and verifying node outputs).
2. `get_graph_callbacks`: Helper returning `FirewallCallbackHandler` instances for LangGraph configs.
"""

from __future__ import annotations

import functools
from typing import Any, Callable, Dict, List, Optional, Union

from llmfirewall.core.models import Action, ScanResult
from llmfirewall.firewall import Firewall
from llmfirewall.integrations.base import FirewallIntegration, SecurityViolation
from llmfirewall.integrations.langchain import FirewallCallbackHandler, HAS_LANGCHAIN


class LangGraphStateGuard(FirewallIntegration):
    """Guard inspecting and sanitizing LangGraph state dictionaries."""

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

    def inspect_state(
        self,
        state: Dict[str, Any],
        target_keys: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Inspects string or message fields inside a LangGraph state dictionary."""
        if not isinstance(state, dict):
            return state

        keys = target_keys if target_keys is not None else list(state.keys())
        sanitized_state = dict(state)
        ctx = dict(context or {})

        for k in keys:
            if k not in sanitized_state:
                continue

            val = sanitized_state[k]

            # Single string field in state
            if isinstance(val, str) and val.strip():
                scan_res = self.firewall.scan_prompt(val, context=ctx)
                if scan_res.is_blocked:
                    if self.fail_closed:
                        raise SecurityViolation(
                            f"LangGraph state key '{k}' blocked by security policy: {scan_res.reason}",
                            scan_result=scan_res,
                            status_code=403,
                        )
                    return state

                if scan_res.action == Action.REDACT and scan_res.processed_text:
                    sanitized_state[k] = scan_res.processed_text

            # List of messages in state
            elif isinstance(val, list):
                sanitized_list = []
                for item in val:
                    # Message object with content attribute or dict
                    content = getattr(item, "content", None)
                    if content is None and isinstance(item, dict):
                        content = item.get("content")

                    if isinstance(content, str) and content.strip():
                        scan_res = self.firewall.scan_prompt(content, context=ctx)
                        if scan_res.is_blocked:
                            if self.fail_closed:
                                raise SecurityViolation(
                                    f"LangGraph state message in '{k}' blocked: {scan_res.reason}",
                                    scan_result=scan_res,
                                    status_code=403,
                                )
                            return state

                        if scan_res.action == Action.REDACT and scan_res.processed_text:
                            if hasattr(item, "content"):
                                # If immutable, shallow copy or model_copy
                                if hasattr(item, "model_copy"):
                                    item = item.model_copy(update={"content": scan_res.processed_text})
                                else:
                                    try:
                                        item.content = scan_res.processed_text
                                    except Exception:
                                        pass
                            elif isinstance(item, dict):
                                item = dict(item)
                                item["content"] = scan_res.processed_text
                    sanitized_list.append(item)
                sanitized_state[k] = sanitized_list

        return sanitized_state


def guard_node(
    node_fn: Optional[Callable] = None,
    *,
    guard: Optional[LangGraphStateGuard] = None,
    firewall: Optional[Firewall] = None,
    input_keys: Optional[List[str]] = None,
    output_keys: Optional[List[str]] = None,
    fail_closed: bool = True,
) -> Callable:
    """Decorator guarding a LangGraph node function against malicious prompts and PII leaks.
    
    Usage:
        @guard_node(input_keys=["messages"])
        def chatbot_node(state: Dict[str, Any]) -> Dict[str, Any]:
            ...
    """
    active_guard = guard if guard is not None else LangGraphStateGuard(firewall=firewall, fail_closed=fail_closed)

    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(state: Dict[str, Any], *args: Any, **kwargs: Any) -> Any:
            guarded_state = active_guard.inspect_state(state, target_keys=input_keys)
            output_state = fn(guarded_state, *args, **kwargs)
            if isinstance(output_state, dict):
                return active_guard.inspect_state(output_state, target_keys=output_keys)
            return output_state

        return wrapper

    if node_fn is not None:
        return decorator(node_fn)
    return decorator


def get_graph_callbacks(firewall: Optional[Firewall] = None) -> List[Any]:
    """Returns a list of LangChain callback handlers compatible with LangGraph runnable configs."""
    if not HAS_LANGCHAIN:
        return []
    return [FirewallCallbackHandler(firewall=firewall)]
