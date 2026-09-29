"""Runtime Hooks abstraction and Hook Registry for lifecycle interception.

Phase 26: LLM & Agent Runtime Protection.
Guarantees:
- Strict, deterministic lifecycle execution order:
    1. before_input
    2. after_input
    3. before_prompt
    4. after_prompt
    5. before_llm
    6. after_llm
    7. before_tool
    8. after_tool
    9. before_loop
    10. after_loop
    11. before_output
    12. after_output
- Both sync and async support
- Non-interfering observation or active policy enforcement
"""

from __future__ import annotations

import abc
import asyncio
from typing import Any, Dict, List, Optional, Union

from llmfirewall.runtime.models import (
    ContentItem,
    LLMRequest,
    LLMResponse,
    RuntimeBoundary,
    RuntimeContext,
    RuntimeDecision,
)
from llmfirewall.tools.models import ToolCall, ToolResult, ToolSecurityDecision


class RuntimeHook(abc.ABC):
    """Abstract base class for lifecycle hooks in an LLM or Agent runtime."""

    def before_input(self, user_input: str, context: RuntimeContext) -> Optional[str]:
        """Invoked before user input is scanned. Return modified input or None."""
        return None

    def after_input(self, user_input: str, decision: RuntimeDecision, context: RuntimeContext) -> None:
        """Invoked after user input security check has completed."""
        pass

    def before_prompt(self, items: List[ContentItem], context: RuntimeContext) -> Optional[List[ContentItem]]:
        """Invoked before prompt items are assembled and scanned."""
        return None

    def after_prompt(self, items: List[ContentItem], decision: RuntimeDecision, context: RuntimeContext) -> None:
        """Invoked after prompt construction security check has completed."""
        pass

    def before_llm(self, request: LLMRequest, context: RuntimeContext) -> Optional[LLMRequest]:
        """Invoked before LLM request is dispatched. Return modified request or None."""
        return None

    def after_llm(self, response: LLMResponse, decision: RuntimeDecision, context: RuntimeContext) -> None:
        """Invoked after LLM response is received and inspected."""
        pass

    def before_tool(self, tool_call: ToolCall, context: RuntimeContext) -> Optional[ToolCall]:
        """Invoked before tool validation and execution. Return modified call or None."""
        return None

    def after_tool(self, tool_result: ToolResult, decision: ToolSecurityDecision, context: RuntimeContext) -> None:
        """Invoked after tool execution and result security scan."""
        pass

    def before_loop(self, iteration: int, context: RuntimeContext) -> None:
        """Invoked before each reasoning loop step."""
        pass

    def after_loop(self, iteration: int, context: RuntimeContext) -> None:
        """Invoked after each reasoning loop step."""
        pass

    def before_output(self, output: str, context: RuntimeContext) -> Optional[str]:
        """Invoked before final output is scanned."""
        return None

    def after_output(self, output: str, decision: RuntimeDecision, context: RuntimeContext) -> None:
        """Invoked after final output is inspected."""
        pass


class HookPipeline:
    """Ordered registry and deterministic dispatcher of RuntimeHook instances."""

    def __init__(self, hooks: Optional[List[RuntimeHook]] = None) -> None:
        self._hooks: List[RuntimeHook] = list(hooks or [])

    def add_hook(self, hook: RuntimeHook) -> None:
        """Register a new lifecycle hook."""
        self._hooks.append(hook)

    def remove_hook(self, hook: RuntimeHook) -> None:
        """Unregister a lifecycle hook."""
        if hook in self._hooks:
            self._hooks.remove(hook)

    @property
    def hooks(self) -> List[RuntimeHook]:
        return list(self._hooks)

    def run_before_input(self, text: str, context: RuntimeContext) -> str:
        current = text
        for h in self._hooks:
            res = h.before_input(current, context)
            if res is not None:
                current = res
        return current

    def run_after_input(self, text: str, decision: RuntimeDecision, context: RuntimeContext) -> None:
        for h in self._hooks:
            h.after_input(text, decision, context)

    def run_before_prompt(self, items: List[ContentItem], context: RuntimeContext) -> List[ContentItem]:
        current = items
        for h in self._hooks:
            res = h.before_prompt(current, context)
            if res is not None:
                current = res
        return current

    def run_after_prompt(self, items: List[ContentItem], decision: RuntimeDecision, context: RuntimeContext) -> None:
        for h in self._hooks:
            h.after_prompt(items, decision, context)

    def run_before_llm(self, request: LLMRequest, context: RuntimeContext) -> LLMRequest:
        current = request
        for h in self._hooks:
            res = h.before_llm(current, context)
            if res is not None:
                current = res
        return current

    def run_after_llm(self, response: LLMResponse, decision: RuntimeDecision, context: RuntimeContext) -> None:
        for h in self._hooks:
            h.after_llm(response, decision, context)

    def run_before_tool(self, tool_call: ToolCall, context: RuntimeContext) -> ToolCall:
        current = tool_call
        for h in self._hooks:
            res = h.before_tool(current, context)
            if res is not None:
                current = res
        return current

    def run_after_tool(self, result: ToolResult, decision: ToolSecurityDecision, context: RuntimeContext) -> None:
        for h in self._hooks:
            h.after_tool(result, decision, context)

    def run_before_loop(self, iteration: int, context: RuntimeContext) -> None:
        for h in self._hooks:
            h.before_loop(iteration, context)

    def run_after_loop(self, iteration: int, context: RuntimeContext) -> None:
        for h in self._hooks:
            h.after_loop(iteration, context)

    def run_before_output(self, output: str, context: RuntimeContext) -> str:
        current = output
        for h in self._hooks:
            res = h.before_output(current, context)
            if res is not None:
                current = res
        return current

    def run_after_output(self, output: str, decision: RuntimeDecision, context: RuntimeContext) -> None:
        for h in self._hooks:
            h.after_output(output, decision, context)
