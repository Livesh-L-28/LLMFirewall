"""Declarative Posture Rules, Evaluators, and Registry for Phase 35 — AI-SPM."""

from dataclasses import dataclass, field
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from llmfirewall.core.models import Severity
from llmfirewall.spm.models import (
    ControlEffectiveness,
    ControlPresence,
    PostureDimension,
    SecurityGap,
    SecurityGapStatus,
    TestFreshness,
)

logger = logging.getLogger("llmfirewall.spm.rules")


@dataclass
class _DummyRuleAsset:
    id: str = "unknown"
    type: str = "agent"
    name: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PostureRuleContext:
    """Rich evaluation context passed to declarative posture rules."""
    asset: Any = None
    controls: Dict[str, Any] = field(default_factory=dict)
    findings: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    attack_paths: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    test_coverage: Any = None
    attack_surface: Any = None
    configuration: Dict[str, Any] = field(default_factory=dict)
    policy_status: Dict[str, Any] = field(default_factory=dict)
    drift: Dict[str, Any] = field(default_factory=dict)
    kg: Optional[Any] = None
    asset_id: Optional[str] = None
    asset_type: Optional[str] = None

    def __post_init__(self) -> None:
        if self.asset is None:
            aid = self.asset_id or "unknown"
            atype = self.asset_type or "agent"
            self.asset = _DummyRuleAsset(id=aid, type=atype)
        elif isinstance(self.asset, str):
            self.asset = _DummyRuleAsset(id=self.asset, type=self.asset_type or "agent")
        if not self.asset_id:
            self.asset_id = getattr(self.asset, "id", "unknown")
        if not self.asset_type:
            self.asset_type = getattr(self.asset, "type", "agent")


class PostureRule:
    """Declarative security posture rule evaluating asset context and emitting SecurityGaps."""

    def __init__(
        self,
        rule_id: str,
        name: str,
        dimension: PostureDimension,
        severity: Severity,
        description: str,
        evaluator: Callable[[PostureRuleContext], Optional[SecurityGap]],
        remediation_guidance: Optional[str] = None,
        enabled: bool = True,
    ) -> None:
        self.rule_id = rule_id.strip()
        self.name = name.strip()
        self.dimension = dimension
        self.severity = severity
        self.description = description.strip()
        self.evaluator = evaluator
        self.remediation_guidance = remediation_guidance or ""
        self.enabled = enabled

    def evaluate(self, context: PostureRuleContext) -> Optional[SecurityGap]:
        if not self.enabled:
            return None
        try:
            res = self.evaluator(context)
            if isinstance(res, list):
                return res[0] if res else None
            return res
        except Exception as exc:
            logger.warning("Posture rule '%s' evaluation error on asset '%s': %s", self.rule_id, getattr(context.asset, "id", "unknown"), exc)
            return None


# -----------------------------------------------------------------------------
# Standard Rule Evaluators
# -----------------------------------------------------------------------------

def _eval_tool_auth_unknown(ctx: PostureRuleContext) -> Optional[SecurityGap]:
    """Flag if agent has tools but tool authorization is UNKNOWN or ABSENT."""
    if getattr(ctx.asset, "type", "") != "agent":
        return None

    tools = getattr(ctx.attack_surface, "tools", []) if ctx.attack_surface else []
    if not tools:
        return None

    # Check if authorization control exists
    auth_ctrl = None
    for cid, c in ctx.controls.items():
        if "auth" in cid.lower() or "rbac" in cid.lower():
            auth_ctrl = c
            break

    if auth_ctrl is None or auth_ctrl.presence in (ControlPresence.UNKNOWN, ControlPresence.ABSENT):
        return SecurityGap(
            asset_id=ctx.asset.id,
            dimension=PostureDimension.TOOL_SECURITY.value,
            title="Tool Authorization Not Configured or Verified",
            description=f"Agent has access to {len(tools)} callable tool(s) ({', '.join(tools[:3])}) but tool authorization policy is not configured or validated.",
            severity=Severity.HIGH,
            evidence=[
                f"Agent '{ctx.asset.id}' has {len(tools)} accessible tool(s): {', '.join(tools)}.",
                f"Tool authorization control presence is {auth_ctrl.presence.value if auth_ctrl else 'ABSENT'}.",
            ],
            related_control=auth_ctrl.control_id if auth_ctrl else "control:tool_authorization",
            remediation_guidance="Configure explicit ToolPermission guardrails or RBAC policy specifying callable tools.",
        )
    return None


def _eval_database_validation_missing(ctx: PostureRuleContext) -> Optional[SecurityGap]:
    """Flag if tool is a database or persistent storage and input/output validation is missing."""
    a_type = getattr(ctx.asset, "type", "")
    meta = getattr(ctx.asset, "metadata", {}) or {}
    category = meta.get("category", "").lower()
    name = getattr(ctx.asset, "name", "").lower()

    if a_type == "tool" and ("database" in category or "database" in name or "sql" in name):
        val_ctrl = next((c for cid, c in ctx.controls.items() if "validation" in cid.lower() or "firewall" in cid.lower()), None)
        if not val_ctrl or val_ctrl.effectiveness in (ControlEffectiveness.UNKNOWN, ControlEffectiveness.FAILED):
            return SecurityGap(
                asset_id=ctx.asset.id,
                dimension=PostureDimension.DATA_SECURITY.value,
                title="Database Tool Lacks Verified Input Validation",
                description="Database tool interacts with persistent datastore without verified input argument sanitization or parameterized validation.",
                severity=Severity.HIGH,
                evidence=[
                    f"Asset '{ctx.asset.id}' is classified as a sensitive database/datastore tool.",
                    "Input validation control is either unconfigured or has not been verified.",
                ],
                related_control=val_ctrl.control_id if val_ctrl else "control:input_validation",
                remediation_guidance="Enforce SQL parameterization and input argument schema validation guardrails.",
            )
    return None


def _eval_unmitigated_attack_path(ctx: PostureRuleContext) -> Optional[SecurityGap]:
    """Flag if supported or tested attack paths exist without active mitigating controls."""
    supported_paths = ctx.attack_paths.get("supported", []) + ctx.attack_paths.get("candidate", [])
    unmitigated = [p for p in supported_paths if p.get("mitigation_status") in ("UNMITIGATED", "PARTIAL")]

    if unmitigated:
        p = unmitigated[0]
        return SecurityGap(
            asset_id=ctx.asset.id,
            dimension=PostureDimension.ATTACK_SURFACE.value,
            title="Unmitigated AI Attack Path Reaches Asset",
            description=f"Candidate or supported multi-step attack path '{p.get('path_id')}' leads to asset without verified mitigation controls.",
            severity=Severity.HIGH,
            evidence=[
                f"Attack path '{p.get('path_id')}' status is {p.get('status')} [{p.get('mitigation_status')}].",
                f"Path sequence: {' -> '.join(p.get('node_sequence', [])) or p.get('source', '') + ' -> ' + p.get('target', '')}.",
                f"Assumptions: {', '.join(p.get('assumptions', [])) if p.get('assumptions') else 'Standard exposure.'}",
            ],
            related_attack_path=p.get("path_id"),
            remediation_guidance="Implement defensive guardrails (Prompt Firewall, RBAC, Output Redactor) along intermediate attack path hops.",
        )
    return None


def _eval_untested_control(ctx: PostureRuleContext) -> Optional[SecurityGap]:
    """Flag configured security controls that have never been tested."""
    untested_controls = [c for c in ctx.controls.values() if c.presence == ControlPresence.PRESENT and not c.tested]
    if untested_controls:
        c = untested_controls[0]
        return SecurityGap(
            asset_id=ctx.asset.id,
            dimension=PostureDimension.TESTING.value,
            title=f"Security Control '{c.name}' Never Tested",
            description=f"Defensive control '{c.control_id}' is configured but has zero empirical security test coverage.",
            severity=Severity.MEDIUM,
            evidence=[
                f"Control '{c.control_id}' presence is {c.presence.value}.",
                f"Test status: tested={c.tested}, effectiveness={c.effectiveness.value}.",
            ],
            related_control=c.control_id,
            remediation_guidance="Execute security evaluation test suites (Phase 30) targeting this control.",
        )
    return None


def _eval_stale_test_coverage(ctx: PostureRuleContext) -> Optional[SecurityGap]:
    """Flag if security test coverage became STALE because asset was modified after testing."""
    if ctx.test_coverage.is_stale:
        return SecurityGap(
            asset_id=ctx.asset.id,
            dimension=PostureDimension.TESTING.value,
            title="Security Test Coverage is STALE",
            description="The asset or its dependent components were modified after the most recent security test execution.",
            severity=Severity.MEDIUM,
            evidence=[
                f"Asset '{ctx.asset.id}' was modified after last test run.",
                f"Staleness reason: {ctx.test_coverage.stale_reason or 'Subsequent architectural change recorded.'}",
                f"Last tested epoch: {ctx.test_coverage.last_tested}, Asset last seen epoch: {getattr(ctx.asset, 'last_seen', 0.0)}.",
            ],
            remediation_guidance="Rerun security test suites against the updated asset configuration.",
        )
    return None


def _eval_open_critical_findings(ctx: PostureRuleContext) -> Optional[SecurityGap]:
    """Flag open HIGH or CRITICAL governance findings affecting the asset."""
    open_findings = ctx.findings.get("open", [])
    crit_findings = [f for f in open_findings if str(f.get("severity", "")).lower() in ("critical", "high")]

    if crit_findings:
        f = crit_findings[0]
        sev = Severity.CRITICAL if str(f.get("severity", "")).lower() == "critical" else Severity.HIGH
        return SecurityGap(
            asset_id=ctx.asset.id,
            dimension=PostureDimension.GOVERNANCE.value,
            title=f"Unresolved {sev.value} Security Finding: {f.get('category')}",
            description=f"Asset has an open finding [{f.get('finding_id', 'UNKNOWN')}]: {f.get('description', '')}",
            severity=sev,
            evidence=[
                f"Finding ID: {f.get('finding_id')}, category: {f.get('category')}, severity: {f.get('severity')}.",
                f"Description: {f.get('description')}.",
                f"First seen: {f.get('first_seen')}, Last observed: {f.get('last_seen')}.",
            ],
            remediation_guidance="Remediate the underlying policy violation or request an approved security waiver (Phase 31).",
        )
    return None


def _eval_policy_conflict(ctx: PostureRuleContext) -> Optional[SecurityGap]:
    """Flag if conflicting policies or ambiguous permissions govern this asset."""
    conflicts = ctx.policy_status.get("conflicts", [])
    if conflicts:
        return SecurityGap(
            asset_id=ctx.asset.id,
            dimension=PostureDimension.CONFIGURATION_SECURITY.value,
            title="Policy Conflict Detected Governing Asset",
            description=f"Multiple contradictory security policies or rules govern asset '{ctx.asset.id}'.",
            severity=Severity.HIGH,
            evidence=[
                f"Recorded policy conflicts ({len(conflicts)}): {'; '.join(str(c) for c in conflicts)}.",
                f"Active policy version: {ctx.policy_status.get('version', 'unknown')}.",
            ],
            remediation_guidance="Resolve conflicting policy rules in Policy-as-Code documents.",
        )
    return None


def _eval_entrypoint_unprotected(ctx: PostureRuleContext) -> Optional[SecurityGap]:
    """Flag external entry points lacking authentication or prompt firewall protection."""
    entry_points = getattr(ctx.attack_surface, "entry_points", []) if ctx.attack_surface else []
    if not entry_points:
        return None

    # Check if firewall / prompt injection control protects asset
    firewall_ctrl = next((c for cid, c in ctx.controls.items() if "injection" in cid.lower() or "firewall" in cid.lower()), None)
    if not firewall_ctrl or firewall_ctrl.presence in (ControlPresence.ABSENT, ControlPresence.UNKNOWN):
        return SecurityGap(
            asset_id=ctx.asset.id,
            dimension=PostureDimension.PROMPT_SECURITY.value,
            title="External Entry Point Lacks Prompt Firewall Protection",
            description=f"Asset exposes {len(entry_points)} external entry point(s) without verified prompt injection guardrail defense.",
            severity=Severity.HIGH,
            evidence=[
                f"Exposed entry points: {', '.join(entry_points)}.",
                f"Prompt firewall protection control presence is {firewall_ctrl.presence.value if firewall_ctrl else 'ABSENT'}.",
            ],
            related_control=firewall_ctrl.control_id if firewall_ctrl else "control:prompt_injection_detector",
            remediation_guidance="Enable PromptInjectionDetector in FirewallConfig.",
        )
    return None


def _eval_rag_access_control(ctx: PostureRuleContext) -> Optional[SecurityGap]:
    """Flag RAG pipelines without verified access control or document validation."""
    rag_srcs = getattr(ctx.attack_surface, "rag_sources", []) if ctx.attack_surface else []
    if getattr(ctx.asset, "type", "") in ("rag_source", "vector_store") or rag_srcs:
        sec_ctrl = next((c for cid, c in ctx.controls.items() if "rag" in cid.lower() or "access" in cid.lower()), None)
        if not sec_ctrl or sec_ctrl.presence in (ControlPresence.UNKNOWN, ControlPresence.ABSENT):
            return SecurityGap(
                asset_id=ctx.asset.id,
                dimension=PostureDimension.RAG_SECURITY.value,
                title="RAG Source Lacks Ingestion & Access Control Verification",
                description="RAG retrieval sources or vector indices operate without verified document trust boundaries or tenant isolation.",
                severity=Severity.MEDIUM,
                evidence=[
                    f"Asset interacts with RAG sources: {', '.join(rag_srcs) or ctx.asset.id}.",
                    "RAG access control / poisoning defense is UNKNOWN or ABSENT.",
                ],
                related_control=sec_ctrl.control_id if sec_ctrl else "control:rag_access_control",
                remediation_guidance="Implement document validation guardrails and RAG context inspection.",
            )
    return None


def _eval_memory_poisoning_untested(ctx: PostureRuleContext) -> Optional[SecurityGap]:
    """Flag persistent conversational memory stores without tested poisoning protection."""
    mem_stores = getattr(ctx.attack_surface, "memory_stores", []) if ctx.attack_surface else []
    if mem_stores:
        mem_ctrl = next((c for cid, c in ctx.controls.items() if "memory" in cid.lower()), None)
        if not mem_ctrl or not mem_ctrl.tested:
            return SecurityGap(
                asset_id=ctx.asset.id,
                dimension=PostureDimension.MEMORY_SECURITY.value,
                title="Persistent Memory Store Not Tested Against Poisoning",
                description="Agent interacts with persistent memory store without verified memory poisoning or prompt injection sanitization tests.",
                severity=Severity.MEDIUM,
                evidence=[
                    f"Memory stores active: {', '.join(mem_stores)}.",
                    "Memory defense test status: UNTESTED.",
                ],
                related_control=mem_ctrl.control_id if mem_ctrl else "control:memory_guardrail",
                remediation_guidance="Execute memory poisoning evaluation tests (Phase 30) for persistent conversational buffers.",
            )
    return None


# -----------------------------------------------------------------------------
# Standard Posture Rules List
# -----------------------------------------------------------------------------

STANDARD_POSTURE_RULES: List[PostureRule] = [
    PostureRule(
        rule_id="R-TOOL-AUTH-UNKNOWN",
        name="Tool Authorization Unknown or Absent",
        dimension=PostureDimension.TOOL_SECURITY,
        severity=Severity.HIGH,
        description="Callable tools lack verified authorization guardrails.",
        evaluator=_eval_tool_auth_unknown,
    ),
    PostureRule(
        rule_id="R-DATABASE-VALIDATION-MISSING",
        name="Database Tool Input Validation Missing",
        dimension=PostureDimension.DATA_SECURITY,
        severity=Severity.HIGH,
        description="Database tool lacks verified input parameterization or schema validation.",
        evaluator=_eval_database_validation_missing,
    ),
    PostureRule(
        rule_id="R-UNMITIGATED-ATTACK-PATH",
        name="Unmitigated AI Attack Path",
        dimension=PostureDimension.ATTACK_SURFACE,
        severity=Severity.HIGH,
        description="Multi-step AI attack path exists without defensive mitigation.",
        evaluator=_eval_unmitigated_attack_path,
    ),
    PostureRule(
        rule_id="R-UNTESTED-SECURITY-CONTROL",
        name="Security Control Configured But Untested",
        dimension=PostureDimension.TESTING,
        severity=Severity.MEDIUM,
        description="Defensive security control has zero empirical test coverage.",
        evaluator=_eval_untested_control,
    ),
    PostureRule(
        rule_id="R-STALE-TEST-COVERAGE",
        name="Security Test Coverage Stale",
        dimension=PostureDimension.TESTING,
        severity=Severity.MEDIUM,
        description="Asset was modified after most recent security test run.",
        evaluator=_eval_stale_test_coverage,
    ),
    PostureRule(
        rule_id="R-OPEN-CRITICAL-FINDING",
        name="Open High or Critical Governance Finding",
        dimension=PostureDimension.GOVERNANCE,
        severity=Severity.HIGH,
        description="Asset is affected by an unresolved high or critical finding.",
        evaluator=_eval_open_critical_findings,
    ),
    PostureRule(
        rule_id="R-POLICY-CONFLICT",
        name="Policy Conflict Governing Asset",
        dimension=PostureDimension.CONFIGURATION_SECURITY,
        severity=Severity.HIGH,
        description="Contradictory policy rules govern asset.",
        evaluator=_eval_policy_conflict,
    ),
    PostureRule(
        rule_id="R-ENTRYPOINT-UNPROTECTED",
        name="External Entry Point Unprotected",
        dimension=PostureDimension.PROMPT_SECURITY,
        severity=Severity.HIGH,
        description="External entry point lacks prompt firewall protection.",
        evaluator=_eval_entrypoint_unprotected,
    ),
    PostureRule(
        rule_id="R-RAG-ACCESS-CONTROL",
        name="RAG Source Access Control Missing",
        dimension=PostureDimension.RAG_SECURITY,
        severity=Severity.MEDIUM,
        description="RAG retrieval sources lack verified access control or document boundary verification.",
        evaluator=_eval_rag_access_control,
    ),
    PostureRule(
        rule_id="R-MEMORY-POISONING-UNTESTED",
        name="Memory Store Untested Against Poisoning",
        dimension=PostureDimension.MEMORY_SECURITY,
        severity=Severity.MEDIUM,
        description="Persistent memory store lacks tested poisoning protection.",
        evaluator=_eval_memory_poisoning_untested,
    ),
]


# -----------------------------------------------------------------------------
# Posture Rule Registry
# -----------------------------------------------------------------------------

class PostureRuleRegistry:
    """Thread-safe versioned registry for managing and evaluating declarative posture rules."""

    def __init__(self, rules_version: str = "1.0.0", load_defaults: bool = True) -> None:
        self.rules_version = rules_version
        self._lock = threading.RLock()
        self._rules: Dict[str, PostureRule] = {}

        if load_defaults:
            for r in STANDARD_POSTURE_RULES:
                self.register(r)

    def register(self, rule: PostureRule) -> None:
        with self._lock:
            self._rules[rule.rule_id] = rule

    def remove(self, rule_id: str) -> bool:
        with self._lock:
            return self._rules.pop(rule_id, None) is not None

    def get(self, rule_id: str) -> Optional[PostureRule]:
        with self._lock:
            return self._rules.get(rule_id)

    def list_rules(self, dimension: Optional[PostureDimension] = None) -> List[PostureRule]:
        with self._lock:
            rules = list(self._rules.values())
            if dimension:
                rules = [r for r in rules if r.dimension == dimension]
            return rules

    def evaluate(self, context: PostureRuleContext) -> List[SecurityGap]:
        """Evaluate all registered enabled rules against the asset context."""
        gaps: List[SecurityGap] = []
        with self._lock:
            rules_to_run = list(self._rules.values())

        for r in rules_to_run:
            gap = r.evaluate(context)
            if gap:
                gaps.append(gap)
        return gaps
