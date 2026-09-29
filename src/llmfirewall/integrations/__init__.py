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

from llmfirewall.integrations.base import (
    FirewallIntegration,
    SecurityViolation,
    protect,
)


class IntegrationRegistry:
    """Registry detailing availability, configuration, and factory methods for integrations."""

    _AVAILABLE = {
        "fastapi": "llmfirewall.integrations.fastapi.middleware:FirewallMiddleware",
        "flask": "llmfirewall.integrations.flask:FirewallExtension",
        "django": "llmfirewall.integrations.django:FirewallMiddleware",
        "langchain": "llmfirewall.integrations.langchain:FirewallCallbackHandler",
        "llamaindex": "llmfirewall.integrations.llamaindex:FirewallNodePostprocessor",
    }

    @classmethod
    def list_available(cls) -> List[str]:
        """List all supported framework integration identifiers."""
        return sorted(list(cls._AVAILABLE.keys()))

    @classmethod
    def is_installed(cls, name: str) -> bool:
        """Check if third-party dependency for integration is installed in the current environment."""
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
    "FirewallIntegration",
    "SecurityViolation",
    "protect",
    "IntegrationRegistry",
]
