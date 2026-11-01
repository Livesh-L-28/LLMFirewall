"""LLMFirewall Integrations Registry and Lazy Importers.

Phase 25: Framework & Ecosystem Integrations.
Supported Ecosystems:
- FastAPI (Middleware, Dependencies, Route Helpers)
- Flask (FirewallExtension)
- Django (FirewallMiddleware)
- LangChain (FirewallCallbackHandler)
- LlamaIndex (FirewallNodePostprocessor)
- Generic Python Functions (@protect decorator, SecurityViolation)
"""

from __future__ import annotations

import importlib
import sys
from typing import Any, Dict, List, Optional

from llmfirewall.integrations.asgi import LLMFirewallASGIMiddleware
from llmfirewall.integrations.base import (
    FirewallIntegration,
    SecurityViolation,
    protect,
)
from llmfirewall.integrations.client import (
    AsyncClientSessionContext,
    AsyncLLMFirewallClient,
    ClientSessionContext,
    LLMFirewallClient,
)
from llmfirewall.integrations.stream import StreamingTextGuard
from llmfirewall.integrations.openai import OpenAIGuard, wrap_openai
from llmfirewall.integrations.anthropic import AnthropicGuard, wrap_anthropic
from llmfirewall.integrations.langgraph import LangGraphStateGuard, guard_node, get_graph_callbacks
from llmfirewall.integrations.mcp import MCPToolGuard


class IntegrationRegistry:
    """Registry detailing availability, configuration, and factory methods for integrations."""

    _AVAILABLE = {
        "fastapi": "llmfirewall.integrations.fastapi.middleware:FirewallMiddleware",
        "asgi": "llmfirewall.integrations.asgi:LLMFirewallASGIMiddleware",
        "flask": "llmfirewall.integrations.flask:FirewallExtension",
        "django": "llmfirewall.integrations.django:FirewallMiddleware",
        "langchain": "llmfirewall.integrations.langchain:FirewallCallbackHandler",
        "llamaindex": "llmfirewall.integrations.llamaindex:FirewallNodePostprocessor",
        "openai": "llmfirewall.integrations.openai:OpenAIGuard",
        "anthropic": "llmfirewall.integrations.anthropic:AnthropicGuard",
        "langgraph": "llmfirewall.integrations.langgraph:LangGraphStateGuard",
        "mcp": "llmfirewall.integrations.mcp:MCPToolGuard",
    }

    @classmethod
    def list_available(cls) -> List[str]:
        """List all supported framework integration identifiers."""
        return sorted(list(cls._AVAILABLE.keys()))

    @classmethod
    def is_installed(cls, name: str) -> bool:
        """Check if third-party dependency for integration is installed in the current environment."""
        if name.lower() in ("asgi", "openai", "anthropic", "langgraph", "mcp"):
            # Universal adapters work with zero mandatory third-party dependencies!
            return True
        dep_modules = {
            "fastapi": "fastapi",
            "flask": "flask",
            "django": "django",
            "langchain": "langchain_core",
            "llamaindex": "llama_index.core",
        }
        mod_name = dep_modules.get(name.lower())
        if not mod_name:
            return False
        try:
            importlib.import_module(mod_name)
            return True
        except ImportError:
            return False

    @classmethod
    def get_status(cls) -> Dict[str, Dict[str, Any]]:
        """Return status matrix of all integrations."""
        status = {}
        for name in cls.list_available():
            status[name] = {
                "available": True,
                "installed": cls.is_installed(name),
            }
        return status


__all__ = [
    # Core Base & Decorators
    "FirewallIntegration",
    "SecurityViolation",
    "protect",
    "IntegrationRegistry",
    # Developer Integrations 2.0 (Phase 51)
    "LLMFirewallASGIMiddleware",
    "LLMFirewallClient",
    "AsyncLLMFirewallClient",
    "StreamingTextGuard",
    "ClientSessionContext",
    "AsyncClientSessionContext",
    # Ecosystem Integrations (Week 4 Sprint)
    "OpenAIGuard",
    "wrap_openai",
    "AnthropicGuard",
    "wrap_anthropic",
    "LangGraphStateGuard",
    "guard_node",
    "get_graph_callbacks",
    "MCPToolGuard",
]
