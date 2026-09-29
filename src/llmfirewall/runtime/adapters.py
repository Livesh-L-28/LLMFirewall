"""Provider adapters for normalizing LLM requests and responses.

Phase 26: LLM & Agent Runtime Protection.
Guarantees:
- Normalized LLMRequest and LLMResponse abstractions
- Zero mandatory external provider SDK dependencies
- Clean translation of OpenAI-compatible, Anthropic-style, and generic payload structures
"""

from __future__ import annotations

import abc
import uuid
from typing import Any, Dict, List, Optional

from llmfirewall.runtime.models import LLMMessage, LLMRequest, LLMResponse, TrustLevel
from llmfirewall.tools.models import ToolCall


class LLMProviderAdapter(abc.ABC):
    """Abstract adapter converting between provider-specific schemas and normalized runtime representations."""

    @abc.abstractmethod
    def prepare_request(self, payload: Any) -> LLMRequest:
        """Convert a provider-specific request payload to normalized LLMRequest."""
        pass

    @abc.abstractmethod
    def inspect_response(self, response: Any) -> LLMResponse:
        """Convert a provider-specific completion or response object to normalized LLMResponse."""
        pass


class GenericProviderAdapter(LLMProviderAdapter):
    """Universal adapter supporting dictionary and OpenAI-compatible chat completion shapes."""

    def prepare_request(self, payload: Any) -> LLMRequest:
        if isinstance(payload, LLMRequest):
            return payload
        if isinstance(payload, str):
            return LLMRequest(
                messages=[LLMMessage(role="user", content=payload, trust=TrustLevel.USER)],
            )
        if isinstance(payload, list):
            # List of message dicts
            msgs = []
            for item in payload:
                if isinstance(item, dict):
                    role = item.get("role", "user")
                    trust = TrustLevel.SYSTEM if role == "system" else (TrustLevel.TOOL if role == "tool" else TrustLevel.USER)
                    msgs.append(LLMMessage(
                        role=role,
                        content=str(item.get("content", "")),
                        trust=trust,
                        tool_calls=item.get("tool_calls"),
                        name=item.get("name"),
                    ))
                elif isinstance(item, LLMMessage):
                    msgs.append(item)
            return LLMRequest(messages=msgs)
        if isinstance(payload, dict):
            raw_msgs = payload.get("messages", [])
            msgs = []
            for item in raw_msgs:
                if isinstance(item, dict):
                    role = item.get("role", "user")
                    trust = TrustLevel.SYSTEM if role == "system" else (TrustLevel.TOOL if role == "tool" else TrustLevel.USER)
                    msgs.append(LLMMessage(
                        role=role,
                        content=str(item.get("content", "")),
                        trust=trust,
                        tool_calls=item.get("tool_calls"),
                        name=item.get("name"),
                    ))
                elif isinstance(item, LLMMessage):
                    msgs.append(item)
            return LLMRequest(
                messages=msgs,
                model=str(payload.get("model", "default-model")),
                parameters={k: v for k, v in payload.items() if k not in ("messages", "model")},
            )
        return LLMRequest(messages=[LLMMessage(role="user", content=str(payload), trust=TrustLevel.USER)])

    def inspect_response(self, response: Any) -> LLMResponse:
        if isinstance(response, LLMResponse):
            return response
        if isinstance(response, str):
            return LLMResponse(content=response)
        if isinstance(response, dict):
            content = ""
            tool_calls: List[ToolCall] = []
            usage = response.get("usage", {})
            model = response.get("model")

            # Check OpenAI choices format
            choices = response.get("choices", [])
            if choices and isinstance(choices, list):
                first = choices[0]
                if isinstance(first, dict):
                    msg = first.get("message", {})
                    content = msg.get("content") or ""
                    raw_tools = msg.get("tool_calls", [])
                    for t in raw_tools:
                        if isinstance(t, dict):
                            fn = t.get("function", {})
                            tool_name = fn.get("name", t.get("name", "unknown_tool"))
                            args = fn.get("arguments", t.get("arguments", {}))
                            call_id = t.get("id")
                            tool_calls.append(ToolCall(
                                id=call_id or str(uuid.uuid4()),
                                tool_name=tool_name,
                                arguments=args if isinstance(args, dict) else {},
                            ))
            else:
                content = str(response.get("content", response.get("output", "")))

            return LLMResponse(
                content=content,
                tool_calls=tool_calls,
                model=model,
                usage=usage if isinstance(usage, dict) else {},
                metadata={"raw_keys": list(response.keys())},
            )

        # Attribute-based object (e.g. OpenAI ChatCompletion instance)
        content = getattr(response, "content", "")
        tool_calls = []
        if hasattr(response, "choices"):
            try:
                msg = response.choices[0].message
                content = getattr(msg, "content", "") or ""
                if hasattr(msg, "tool_calls") and msg.tool_calls:
                    for tc in msg.tool_calls:
                        fn = getattr(tc, "function", None)
                        name = getattr(fn, "name", "unknown_tool") if fn else "unknown_tool"
                        args = getattr(fn, "arguments", {}) if fn else {}
                        cid = getattr(tc, "id", None)
                        tool_calls.append(ToolCall(
                            id=cid or str(uuid.uuid4()),
                            tool_name=name,
                            arguments=args if isinstance(args, dict) else {},
                        ))
            except Exception:
                pass

        usage = {}
        if hasattr(response, "usage") and response.usage:
            usage = {
                "prompt_tokens": getattr(response.usage, "prompt_tokens", 0),
                "completion_tokens": getattr(response.usage, "completion_tokens", 0),
                "total_tokens": getattr(response.usage, "total_tokens", 0),
            }

        return LLMResponse(
            content=str(content),
            tool_calls=tool_calls,
            model=getattr(response, "model", None),
            usage=usage,
        )
