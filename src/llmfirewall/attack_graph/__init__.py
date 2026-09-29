"""Phase 33 — Attack Graph & AI Threat Modeling module for LLMFirewall."""

from llmfirewall.attack_graph.engine import (
    AttackGraph,
    AttackGraphMetrics,
)
from llmfirewall.attack_graph.models import (
    AttackEvidence,
    AttackGraphDiff,
    AttackGraphSnapshot,
    AttackNode,
    AttackPath,
    AttackStep,
    AttackTechnique,
    ConfidenceLevel,
    ControlEffectiveness,
    EntryPoint,
    EntryPointType,
    EvidenceType,
    MitigationStatus,
    PathStatus,
    ThreatModel,
    TrustBoundary,
)
from llmfirewall.attack_graph.reporting import (
    format_attack_graph_sarif,
    format_attack_paths_human,
    format_attack_paths_json,
    format_threat_model_human,
)
from llmfirewall.attack_graph.rules import (
    AttackRule,
    AttackRuleRegistry,
    PreconditionEvaluator,
    STANDARD_RULES,
)
from llmfirewall.attack_graph.techniques import (
    AttackTechniqueRegistry,
    default_technique_registry,
)

__all__ = [
    # Engine
    "AttackGraph",
    "AttackGraphMetrics",
    # Models & Enums
    "PathStatus",
    "EvidenceType",
    "MitigationStatus",
    "ControlEffectiveness",
    "EntryPointType",
    "ConfidenceLevel",
    "AttackEvidence",
    "AttackTechnique",
    "AttackNode",
    "AttackStep",
    "AttackPath",
    "TrustBoundary",
    "EntryPoint",
    "ThreatModel",
    "AttackGraphSnapshot",
    "AttackGraphDiff",
    # Techniques
    "AttackTechniqueRegistry",
    "default_technique_registry",
    # Rules
    "AttackRule",
    "AttackRuleRegistry",
    "PreconditionEvaluator",
    "STANDARD_RULES",
    # Reporting
    "format_attack_paths_human",
    "format_threat_model_human",
    "format_attack_paths_json",
    "format_attack_graph_sarif",
]
