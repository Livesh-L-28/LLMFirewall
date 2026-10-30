"""LLMFirewall Developer Experience & Scaffolding Engine.

Provides deterministic framework detection, recipe scaffolding, and
integration validation for developers and AI coding agents.
"""

from llmfirewall.developer.detector import (
    DetectionResult,
    detect_project_frameworks,
)
from llmfirewall.developer.templates import (
    ScaffoldResult,
    generate_scaffold,
    list_supported_recipes,
)
from llmfirewall.developer.validator import (
    ValidationCheck,
    ValidationReport,
    validate_integration,
)

__all__ = [
    "DetectionResult",
    "detect_project_frameworks",
    "ScaffoldResult",
    "generate_scaffold",
    "list_supported_recipes",
    "ValidationCheck",
    "ValidationReport",
    "validate_integration",
]
