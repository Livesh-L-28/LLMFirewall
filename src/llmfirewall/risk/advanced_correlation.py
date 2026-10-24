"""Phase 58 — Advanced Security Intelligence & Explainable Correlation.

Extends existing risk, blast radius, session, and event correlation to connect
related findings, multi-turn sessions, asset inventory nodes, and attack paths.
Provides transparent, explainable incident context without creating a duplicate risk engine.
"""

from enum import Enum
import time
from typing import Any, Dict, List, Optional, Set
import uuid

from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.core.models import Finding, Severity, ThreatType
from llmfirewall.risk.blast_radius import BlastRadiusEstimator, BlastRadiusReport
from llmfirewall.risk.correlation import (
    AttackChainType,
    CorrelatedAttackChain,
    CorrelationReport,
    FindingCorrelationEngine,
)
from llmfirewall.risk.session import SessionRiskSummary, SessionRiskTracker


class AttackProgressionStage(str, Enum):
    """Lifecycle stages of an AI security attack progression."""
    INITIAL_ACCESS = "INITIAL_ACCESS"
    EXECUTION = "EXECUTION"
    PERSISTENCE = "PERSISTENCE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    DISCOVERY = "DISCOVERY"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    EXFILTRATION = "EXFILTRATION"
    IMPACT = "IMPACT"


class CorrelatedEntityRef(BaseModel):
    """Reference to an asset, tool, model, session, or finding connected in a correlation."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    entity_id: str = Field(..., description="Unique identifier of correlated entity")
    entity_type: str = Field(..., description="Type of entity: asset, tool, session, user, path")
    name: str = Field(..., description="Readable label or name")
    role: str = Field(default="affected", description="Role in attack: entry_point, intermediate, target, affected")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Auxiliary safe metadata")


class EvidenceTimelineItem(BaseModel):
    """Chronological event or finding record supporting correlation explainability."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    timestamp: float = Field(default_factory=time.time, description="Epoch timestamp")
    event_type: str = Field(..., description="Type of finding or event")
    description: str = Field(..., description="Clear human narrative of what occurred")
    source_id: str = Field(..., description="Identifier of the originating source or detector")
    severity: Severity = Field(default=Severity.INFO, description="Severity of the event")


class ExplainableCorrelation(BaseModel):
    """Fully explainable compound security correlation connecting findings, sessions, and assets."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    correlation_id: str = Field(default_factory=lambda: f"corr-{uuid.uuid4().hex[:10]}", description="Unique correlation ID")
    title: str = Field(..., description="Descriptive title of correlated threat sequence")
    chain_type: str = Field(..., description="Underlying attack chain classification")
    progression_stage: AttackProgressionStage = Field(..., description="Current highest attack progression stage")
    severity: Severity = Field(..., description="Highest aggregated severity")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in correlation validity")
    root_cause_explanation: str = Field(..., description="Transparent root-cause explanation")
    impact_narrative: str = Field(..., description="Explainable downstream impact description")
    recommended_containment: str = Field(..., description="Actionable immediate response advice")
    finding_ids: List[str] = Field(default_factory=list, description="IDs of correlated findings")
    session_ids: List[str] = Field(default_factory=list, description="IDs of correlated sessions")
    affected_asset_ids: List[str] = Field(default_factory=list, description="Assets impacted or targeted")
    attack_path_ids: List[str] = Field(default_factory=list, description="Matched attack graph paths")
    evidence_timeline: List[EvidenceTimelineItem] = Field(default_factory=list, description="Timeline of evidence items")
    entities: List[CorrelatedEntityRef] = Field(default_factory=list, description="All connected entities")


class IncidentSecurityContext(BaseModel):
    """Enriched security context synthesized across risk, assets, sessions, and paths."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    context_id: str = Field(default_factory=lambda: f"ctx-{uuid.uuid4().hex[:10]}", description="Unique context ID")
    session_id: Optional[str] = Field(default=None, description="Primary session ID if available")
    total_findings: int = Field(default=0, description="Count of evaluated findings")
    correlations: List[ExplainableCorrelation] = Field(default_factory=list, description="Explainable correlations")
    peak_severity: Severity = Field(default=Severity.INFO, description="Peak severity across all correlations")
    composite_risk_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Composite risk from risk engine")
    affected_assets: List[str] = Field(default_factory=list, description="List of unique affected asset identifiers")
    active_attack_paths: List[str] = Field(default_factory=list, description="List of relevant attack graph path IDs")
    containment_steps: List[str] = Field(default_factory=list, description="Deduplicated recommended containment steps")
    narrative_summary: str = Field(default="", description="Executive explainable narrative of security state")
    blast_radius: Optional[BlastRadiusReport] = Field(default=None, description="Associated blast radius report")


class AdvancedSecurityCorrelator:
    """Connects findings, sessions, asset inventory, and attack paths into explainable incident context.
    
    Reuses the existing FindingCorrelationEngine, SessionRiskTracker, and BlastRadiusEstimator
    to avoid maintaining a divergent or duplicate risk engine.
    """

    def __init__(
        self,
        finding_correlator: Optional[FindingCorrelationEngine] = None,
        session_tracker: Optional[SessionRiskTracker] = None,
        blast_radius_estimator: Optional[BlastRadiusEstimator] = None,
    ) -> None:
        self.finding_correlator = finding_correlator or FindingCorrelationEngine()
        self.session_tracker = session_tracker
        self.blast_estimator = blast_radius_estimator or BlastRadiusEstimator()

    def correlate_incident(
        self,
        findings: List[Finding],
        session_id: Optional[str] = None,
        assets: Optional[List[Any]] = None,
        attack_paths: Optional[List[Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> IncidentSecurityContext:
        """Synthesize explainable correlations across findings, sessions, assets, and attack paths."""
        ctx = dict(context or {})
        if session_id:
            ctx["session_id"] = session_id

        # 1. Run underlying FindingCorrelationEngine (reuse existing engine)
        base_report: CorrelationReport = self.finding_correlator.correlate(findings, context=ctx)

        # 2. Extract asset references
        asset_refs: Dict[str, CorrelatedEntityRef] = {}
        if assets:
            for a in assets:
                aid = getattr(a, "id", None) or getattr(a, "name", str(a))
                aname = getattr(a, "name", str(aid))
                atype = getattr(a, "type", "asset")
                if hasattr(atype, "value"):
                    atype = atype.value
                asset_refs[aid] = CorrelatedEntityRef(
                    entity_id=str(aid),
                    entity_type=str(atype),
                    name=str(aname),
                    role="affected",
                )

        # 3. Extract attack path references
        path_ids: List[str] = []
        if attack_paths:
            for p in attack_paths:
                pid = getattr(p, "id", None) or getattr(p, "name", str(p))
                path_ids.append(str(pid))

        # 4. Synthesize explainable correlations
        explainable_list: List[ExplainableCorrelation] = []
        all_affected_assets: Set[str] = set()
        all_containment: List[str] = []
        peak_sev = Severity.INFO

        # Map each detected chain to an explainable correlation
        for chain in base_report.chains:
            stage = self._infer_progression_stage(chain.chain_type)
            chain_finding_ids = chain.involved_finding_ids
            timeline = [
                EvidenceTimelineItem(
                    timestamp=time.time(),
                    event_type=f.threat_type.value,
                    description=f"{f.metadata.get('rule_name', f.detector_name) if f.metadata else f.detector_name}: {f.description}",
                    source_id=f.detector_name,
                    severity=f.severity,
                )
                for f in findings if f.id in chain_finding_ids
            ]

            # Downstream entities
            chain_entities: List[CorrelatedEntityRef] = []
            if session_id:
                chain_entities.append(
                    CorrelatedEntityRef(
                        entity_id=session_id,
                        entity_type="session",
                        name=f"Session {session_id}",
                        role="entry_point",
                    )
                )

            # Match assets relevant to this chain
            chain_assets: List[str] = []
            for aid, aref in asset_refs.items():
                chain_assets.append(aid)
                chain_entities.append(aref)
                all_affected_assets.add(aid)

            # Build transparent root cause explanation
            root_cause = self._build_root_cause(chain, findings)
            impact = self._build_impact_narrative(chain, chain_assets)
            mitigation = chain.mitigation or "Isolate request and enforce fail-closed policy."
            all_containment.append(mitigation)

            if chain.severity.value == "critical":
                peak_sev = Severity.CRITICAL
            elif chain.severity.value == "high" and peak_sev != Severity.CRITICAL:
                peak_sev = Severity.HIGH
            elif chain.severity.value == "medium" and peak_sev not in (Severity.CRITICAL, Severity.HIGH):
                peak_sev = Severity.MEDIUM

            explainable_list.append(
                ExplainableCorrelation(
                    title=chain.name,
                    chain_type=chain.chain_type.value if hasattr(chain.chain_type, "value") else str(chain.chain_type),
                    progression_stage=stage,
                    severity=chain.severity,
                    confidence=chain.confidence,
                    root_cause_explanation=root_cause,
                    impact_narrative=impact,
                    recommended_containment=mitigation,
                    finding_ids=chain_finding_ids,
                    session_ids=[session_id] if session_id else [],
                    affected_asset_ids=chain_assets,
                    attack_path_ids=path_ids,
                    evidence_timeline=timeline,
                    entities=chain_entities,
                )
            )

        # 5. Compute blast radius using existing BlastRadiusEstimator
        blast_report: Optional[BlastRadiusReport] = None
        if findings:
            blast_report = self.blast_estimator.estimate(findings, context=ctx)
            if blast_report.reachable_systems:
                for sys_name in blast_report.reachable_systems:
                    all_affected_assets.add(sys_name)
            if blast_report.containment_steps:
                all_containment.extend(blast_report.containment_steps)

        # 6. Deduplicate containment steps
        deduped_containment: List[str] = []
        for step in all_containment:
            if step and step not in deduped_containment:
                deduped_containment.append(step)

        # 7. Synthesize narrative summary
        narrative = self._generate_executive_narrative(
            correlations=explainable_list,
            total_findings=len(findings),
            session_id=session_id,
            affected_assets=list(all_affected_assets),
            peak_sev=peak_sev,
        )

        # Compute composite risk score without second engine
        # Normalize base severity + multiplier boost
        sev_base = {
            Severity.CRITICAL: 0.90,
            Severity.HIGH: 0.70,
            Severity.MEDIUM: 0.45,
            Severity.LOW: 0.20,
            Severity.INFO: 0.05,
        }.get(peak_sev, 0.0)
        composite_score = min(1.0, round(sev_base * base_report.correlation_multiplier, 4)) if findings else 0.0

        return IncidentSecurityContext(
            session_id=session_id,
            total_findings=len(findings),
            correlations=explainable_list,
            peak_severity=peak_sev,
            composite_risk_score=composite_score,
            affected_assets=sorted(all_affected_assets),
            active_attack_paths=path_ids,
            containment_steps=deduped_containment,
            narrative_summary=narrative,
            blast_radius=blast_report,
        )

    def _infer_progression_stage(self, chain_type: Any) -> AttackProgressionStage:
        """Map chain taxonomy to MITRE-aligned progression stage."""
        c_str = str(chain_type.value if hasattr(chain_type, "value") else chain_type)
        if "EXFILTRATION" in c_str:
            return AttackProgressionStage.EXFILTRATION
        if "EXECUTION" in c_str:
            return AttackProgressionStage.EXECUTION
        if "PRIVILEGE" in c_str:
            return AttackProgressionStage.PRIVILEGE_ESCALATION
        if "RAG" in c_str:
            return AttackProgressionStage.PERSISTENCE
        return AttackProgressionStage.INITIAL_ACCESS

    def _build_root_cause(self, chain: CorrelatedAttackChain, findings: List[Finding]) -> str:
        """Generate human-readable root cause explanation."""
        involved = [f for f in findings if f.id in chain.involved_finding_ids]
        threats = ", ".join(sorted({f.threat_type.value for f in involved}))
        return (
            f"Correlation '{chain.name}' was initiated via threat vector(s) [{threats}]. "
            f"{chain.description}"
        )

    def _build_impact_narrative(self, chain: CorrelatedAttackChain, assets: List[str]) -> str:
        """Generate downstream impact narrative."""
        asset_str = f" across assets ({', '.join(assets)})" if assets else ""
        return (
            f"Compound attack {chain.name} with multiplier {chain.multiplier:.2f}x "
            f"poses threat level {chain.severity.value.upper()}{asset_str}. "
            "Downstream systems or sensitive data are at risk if execution proceeds."
        )

    def _generate_executive_narrative(
        self,
        correlations: List[ExplainableCorrelation],
        total_findings: int,
        session_id: Optional[str],
        affected_assets: List[str],
        peak_sev: Severity,
    ) -> str:
        """Create executive human narrative for incident responders."""
        if not correlations:
            if total_findings == 0:
                return "Security posture normal: No findings or compound attack patterns observed."
            return (
                f"Isolated activity: {total_findings} atomic finding(s) detected with peak severity "
                f"{peak_sev.value.upper()}, with no cross-vector correlation or multi-stage attack chains identified."
            )

        sess_str = f" within session '{session_id}'" if session_id else ""
        asset_str = f" impacting {len(affected_assets)} asset(s)" if affected_assets else ""
        chains_summary = "; ".join(f"{c.title} ({c.progression_stage.value})" for c in correlations)
        return (
            f"Active security incident identified{sess_str}{asset_str}: "
            f"{len(correlations)} correlated attack pattern(s) detected ({chains_summary}). "
            f"Peak severity is {peak_sev.value.upper()}."
        )
