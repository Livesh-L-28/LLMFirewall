"""LangChain callback and tool-guard integration for LLMFirewall.

Provides non-intrusive security hooks into LangChain LLM, Agent, Chain, and Tool lifecycles.
Optional integration: requires langchain_core or langchain to be installed.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Sequence, Union

from llmfirewall.core.exceptions import BlockedOutputError, BlockedPromptError
from llmfirewall.core.models import Action, ScanResult
from llmfirewall.firewall import Firewall
from llmfirewall.integrations.base import FirewallIntegration, SecurityViolation
from llmfirewall.tools.models import ToolCall, ToolSecurityDecision

try:
    from langchain_core.callbacks.base import BaseCallbackHandler
    from langchain_core.messages import BaseMessage
    from langchain_core.outputs import LLMResult
    HAS_LANGCHAIN = True
except ImportError:
    try:
        from langchain.callbacks.base import BaseCallbackHandler  # type: ignore
        from langchain.schema import BaseMessage, LLMResult  # type: ignore
        HAS_LANGCHAIN = True
    except ImportError:
        HAS_LANGCHAIN = False
        BaseCallbackHandler = object  # type: ignore


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
                "LangChain is not installed. To use the LangChain integration, install it via: "
                "pip install langchain or pip install 'llmfirewall[langchain]'"
            )
        BaseCallbackHandler.__init__(self)
        FirewallIntegration.__init__(self, firewall=firewall)
        self.inspect_prompts = inspect_prompts
        self.inspect_outputs = inspect_outputs
        self.inspect_tools = inspect_tools
        self.raise_on_block = raise_on_block

    def protect(self, *args: Any, **kwargs: Any) -> Any:
        return self

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

        for p in prompts:
            res: ScanResult = self.firewall.check_prompt(p, context=metadata)
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

        for msg_list in messages:
            for m in msg_list:
                content = getattr(m, "content", "")
                if isinstance(content, str) and content.strip():
                    res = self.firewall.check_prompt(content, context=metadata)
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
            context=metadata,
        )
        if decision.is_blocked and self.raise_on_block:
            raise SecurityViolation(
                f"LangChain tool call '{tool_name}' blocked by security policy: {decision.reason}",
                request_id=decision.id,
            )

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: Optional[Any] = None,
        parent_run_id: Optional[Any] = None,
        **kwargs: Any,
    ) -> Any:
        """Inspect tool execution outputs before sending back to LLM."""
        if not self.inspect_tools or not isinstance(output, str):
            return

        tool_res_dec = self.firewall.check_tool_result("langchain_tool", output=output)
        if tool_res_dec.is_blocked and self.raise_on_block:
            raise SecurityViolation(
                f"LangChain tool result blocked by security policy: {tool_res_dec.reason}",
                request_id=tool_res_dec.id,
            )

    def on_llm_end(
        self,
        response: Any,
        *,
        run_id: Optional[Any] = None,
        parent_run_id: Optional[Any] = None,
        **kwargs: Any,
    ) -> Any:
        """Inspect LLM generations before completing chain."""
        if not self.inspect_outputs or not hasattr(response, "generations"):
            return

        for gen_list in response.generations:
            for g in gen_list:
                text = getattr(g, "text", "")
                if text:
                    res = self.firewall.check_output(text)
                    if res.decision.action == Action.BLOCK and self.raise_on_block:
                        raise SecurityViolation(
                            f"LangChain LLM output rejected by security policy: {res.decision.reason}",
                            scan_result=res,
                            request_id=res.request_id,
                        )
