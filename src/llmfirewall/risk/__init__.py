"""Risk module exports for Phase 16 Risk Scoring and Phase 37 AI Security Risk & Prioritization Engine."""

from llmfirewall.risk.blast_radius import BlastRadiusEstimator, BlastRadiusReport
from llmfirewall.risk.config import RiskConfig
from llmfirewall.risk.correlation import (
    AttackChainType,
    CorrelatedAttackChain,
    CorrelationReport,
    FindingCorrelationEngine,
)
from llmfirewall.risk.engine import RiskEngine
from llmfirewall.risk.models import (
    RiskAssessment,
    RiskDiff,
    RiskFactor,
    RiskFactorType,
    RiskHistoryEntry,
    RiskLevel,
    RiskSnapshot,
    RiskTreatment,
    RiskUncertainty,
)
from llmfirewall.risk.prioritizer import RiskPrioritizationEngine
from llmfirewall.risk.reporting import (
    format_risk_detail_human,
    format_risk_diff_human,
    format_risk_human,
    format_risk_json,
    format_risk_yaml,
)
from llmfirewall.risk.session import (
    SessionRiskSummary,
    SessionRiskTracker,
    SessionTurnRecord,
)
from llmfirewall.risk.advanced_correlation import (
    AdvancedSecurityCorrelator,
    AttackProgressionStage,
    CorrelatedEntityRef,
    EvidenceTimelineItem,
    ExplainableCorrelation,
    IncidentSecurityContext,
)

__all__ = [
    # Core Engine & Config
    "RiskEngine",
    "RiskConfig",
    "RiskPrioritizationEngine",
    # Correlation Engine (Phase 50 & Phase 58)
    "AttackChainType",
    "CorrelatedAttackChain",
    "CorrelationReport",
    "FindingCorrelationEngine",
    "AdvancedSecurityCorrelator",
    "AttackProgressionStage",
    "CorrelatedEntityRef",
    "EvidenceTimelineItem",
    "ExplainableCorrelation",
    "IncidentSecurityContext",
    # Blast Radius (Phase 50)
    "BlastRadiusReport",
    "BlastRadiusEstimator",
    # Session Risk Tracking (Phase 50)
    "SessionTurnRecord",
    "SessionRiskSummary",
    "SessionRiskTracker",
    # Models & Enums
    "RiskAssessment",
    "RiskLevel",
    "RiskUncertainty",
    "RiskTreatment",
    "RiskFactorType",
    "RiskFactor",
    "RiskHistoryEntry",
    "RiskSnapshot",
    "RiskDiff",
    # Reporting
    "format_risk_human",
    "format_risk_detail_human",
    "format_risk_diff_human",
    "format_risk_json",
    "format_risk_yaml",
]
