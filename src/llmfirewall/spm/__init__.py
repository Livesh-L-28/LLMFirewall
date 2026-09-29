"""Phase 35 — AI Security Posture Management (AI-SPM).

Continuously calculable, evidence-based security posture evaluation,
control effectiveness tracking, attack surface analysis, security gap detection,
and baseline regression analysis for AI systems.
"""

from llmfirewall.spm.engine import PostureEngine, PostureMetrics
from llmfirewall.spm.models import (
    AttackSurfaceRecord,
    ControlEffectiveness,
    ControlPostureRecord,
    ControlPresence,
    PostureDiff,
    PostureDimension,
    PostureSnapshot,
    PostureState,
    SecurityGap,
    SecurityGapStatus,
    SecurityPosture,
    TestCoverageRecord,
    TestFreshness,
    sanitize_posture_metadata,
)
from llmfirewall.spm.reporting import (
    format_posture_diff_human,
    format_posture_human,
    format_posture_json,
    format_posture_sarif,
    format_posture_summary_human,
)
from llmfirewall.spm.rules import PostureRule, PostureRuleContext, PostureRuleRegistry

__all__ = [
    # Engine & Telemetry
    "PostureEngine",
    "PostureMetrics",
    # Posture States & Dimensions
    "PostureState",
    "PostureDimension",
    "ControlPresence",
    "ControlEffectiveness",
    "SecurityGapStatus",
    "TestFreshness",
    # Posture Models & Records
    "ControlPostureRecord",
    "TestCoverageRecord",
    "AttackSurfaceRecord",
    "SecurityGap",
    "SecurityPosture",
    "PostureSnapshot",
    "PostureDiff",
    "sanitize_posture_metadata",
    # Rules
    "PostureRule",
    "PostureRuleContext",
    "PostureRuleRegistry",
    # Reporting
    "format_posture_human",
    "format_posture_summary_human",
    "format_posture_diff_human",
    "format_posture_json",
    "format_posture_sarif",
]
