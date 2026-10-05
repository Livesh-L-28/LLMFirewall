"""Deterministic Risk Engine implementation adhering strictly to 'Risk engine scores'."""

from collections import defaultdict
from typing import Any, Dict, List, Optional, Union

from llmfirewall.core.interfaces import BaseRiskEngine
from llmfirewall.core.models import Finding, RiskScore, Severity, ThreatType
from llmfirewall.detectors.collection import FindingCollection
from llmfirewall.risk.blast_radius import BlastRadiusEstimator, BlastRadiusReport
from llmfirewall.risk.config import RiskConfig
from llmfirewall.risk.correlation import CorrelationReport, FindingCorrelationEngine
from llmfirewall.risk.session import SessionRiskSummary, SessionRiskTracker


class RiskEngine(BaseRiskEngine):
    """Deterministic, transparent risk assessment engine.
    
    Adheres strictly to the architectural contract: 'Risk engine scores.'
    Computes normalized score [0.0, 1.0], category sub-scores, and overall risk level.
    Does NOT make policy decisions (Policy Engine decides).
    
    Scoring Methodology:
    -------------------
    1. Finding Normalization & Deduplication:
       - Findings with identical category, start_pos, and end_pos are treated as
         duplicates; only the entry with highest (severity_weight * confidence) is retained.
    2. Atomic Finding Weight:
       - finding_score = severity_weight[severity] * confidence * category_multiplier[threat_type]
    3. Category Sub-Score Aggregation:
       - For each category, sort findings descending by finding_score.
       - The primary finding contributes 100%. Subsequent findings (index k = 1, 2, ...)
         contribute with diminishing returns: finding_score * (decay_factor ** k).
       - category_score = min(1.0, primary + sum(subsequent * decay_factor**k))
    4. Composite Overall Score:
       - overall_score = min(1.0, max_category_score + 0.2 * remaining_categories_contribution)
       - Ensures a single critical finding produces an immediate high/critical score,
         while multiple distinct threat vectors compound transparently without overflow.
    5. Overall Risk Level:
       - Mapped via configured threshold boundaries: INFO < LOW < MEDIUM < HIGH < CRITICAL.
    """

    def __init__(
        self,
        config: Optional[RiskConfig] = None,
        inventory: Optional[Any] = None,
        kg: Optional[Any] = None,
        attack_graph: Optional[Any] = None,
        spm: Optional[Any] = None,
        compliance: Optional[Any] = None,
        governance: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
    ) -> None:
        self._config = config or RiskConfig()
        from llmfirewall.risk.prioritizer import RiskPrioritizationEngine
        self._prioritizer = RiskPrioritizationEngine(
            inventory=inventory,
            kg=kg,
            attack_graph=attack_graph,
            spm=spm,
            compliance=compliance,
            governance=governance,
            audit_logger=audit_logger,
        )
        self._correlation_engine = FindingCorrelationEngine()
        self._blast_radius_estimator = BlastRadiusEstimator()
        self._session_tracker = SessionRiskTracker()

    @property
    def config(self) -> RiskConfig:
        return self._config

    @property
    def prioritizer(self) -> Any:
        return self._prioritizer

    @property
    def correlation_engine(self) -> FindingCorrelationEngine:
        return self._correlation_engine

    @property
    def blast_radius_estimator(self) -> BlastRadiusEstimator:
        return self._blast_radius_estimator

    @property
    def session_tracker(self) -> SessionRiskTracker:
        return self._session_tracker

    def assess_asset_risk(self, asset_id: str) -> List[Any]:
        """Perform contextual, explainable risk assessment for an asset."""
        return self._prioritizer.assess_asset_risk(asset_id)

    def prioritize(self, asset_id: Optional[str] = None) -> List[Any]:
        """Prioritize security risks across assets or for a specific asset."""
        return self._prioritizer.prioritize(asset_id)

    def snapshot(self) -> Any:
        """Create a cryptographic baseline snapshot of system-wide risk."""
        return self._prioritizer.snapshot()

    def diff(self, previous: Any, current: Any) -> Any:
        """Compare risk snapshots and identify regressions (RISK_INCREASED)."""
        return self._prioritizer.diff(previous, current)

    def get_risk_history(self, asset_id: Optional[str] = None) -> List[Any]:
        """Retrieve historical state transitions in risk assessments."""
        return self._prioritizer.get_risk_history(asset_id)

    def correlate(
        self,
        findings: Union[List[Finding], FindingCollection],
        context: Optional[Dict[str, Any]] = None,
    ) -> CorrelationReport:
        """Detect multi-stage compound attack chains across findings."""
        raw_list = findings.findings if isinstance(findings, FindingCollection) else list(findings or [])
        return self._correlation_engine.correlate(raw_list, context=context)

    def estimate_blast_radius(
        self,
        findings: Union[List[Finding], FindingCollection],
        context: Optional[Dict[str, Any]] = None,
    ) -> BlastRadiusReport:
        """Quantify potential systemic blast radius and data exposure."""
        raw_list = findings.findings if isinstance(findings, FindingCollection) else list(findings or [])
        return self._blast_radius_estimator.estimate(raw_list, context=context)

    def track_session(
        self,
        session_id: str,
        findings: Union[List[Finding], FindingCollection],
        risk_score: Optional[float] = None,
        timestamp: Optional[float] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> SessionRiskSummary:
        """Record turn and compute cumulative session risk with temporal decay."""
        raw_list = findings.findings if isinstance(findings, FindingCollection) else list(findings or [])
        if risk_score is None:
            score_obj = self.evaluate(raw_list, context=context)
            score_val = score_obj.score
        else:
            score_val = risk_score
        return self._session_tracker.record_turn(
            session_id=session_id,
            findings=raw_list,
            risk_score=score_val,
            timestamp=timestamp,
        )

    def get_session_risk(
        self,
        session_id: str,
        current_time: Optional[float] = None,
    ) -> SessionRiskSummary:
        """Retrieve decayed multi-turn session risk summary."""
        return self._session_tracker.get_session_risk(session_id=session_id, current_time=current_time)

    def evaluate(
        self,
        findings: Union[List[Finding], FindingCollection],
        context: Optional[Dict[str, Any]] = None,
    ) -> RiskScore:
        """Evaluate a collection of findings and compute the quantified RiskScore.
        
        Args:
            findings: List of Finding instances or a FindingCollection.
            context: Optional contextual parameters.
            
        Returns:
            RiskScore: Normalized score, maximum severity, and per-category breakdowns.
        """
        raw_list = findings.findings if isinstance(findings, FindingCollection) else list(findings or [])

        # Edge Case 1: Empty findings
        if not raw_list:
            return RiskScore(
                score=0.0,
                max_severity=Severity.INFO,
                category_scores={},
                metadata={
                    "risk_level": Severity.INFO.value,
                    "findings_count": 0,
                    "deduplicated_count": 0,
                },
            )

        # 1. Deduplicate identical spans within the same threat category
        unique_findings = self._deduplicate_findings(raw_list)

        # 2. Maximum observed severity across all findings
        max_severity = max(f.severity for f in unique_findings)

        # 3. Calculate category sub-scores
        category_scores, category_findings_map = self._calculate_category_scores(unique_findings)

        # 4. Composite overall score
        overall_score = self._calculate_composite_score(category_scores)

        # 5. Risk 2.0: Finding Correlation & Context-Aware Dynamic Scoring
        correlation_report: Optional[CorrelationReport] = None
        blast_radius_report: Optional[BlastRadiusReport] = None
        contextual_mult = 1.0

        if context:
            # 5a. Correlation Engine
            if self._config.enable_correlation:
                correlation_report = self._correlation_engine.correlate(unique_findings, context=context)
                if correlation_report.is_compound_attack:
                    contextual_mult *= correlation_report.correlation_multiplier
                    if correlation_report.highest_severity == Severity.CRITICAL and max_severity < Severity.CRITICAL:
                        max_severity = Severity.CRITICAL

            # 5b. Dynamic Contextual Scaling
            if self._config.enable_dynamic_context:
                env = str(context.get("environment", "")).lower()
                if env in self._config.environmental_multipliers:
                    contextual_mult *= self._config.environmental_multipliers[env]

                if context.get("trust_boundary_traversed") or context.get("cross_boundary"):
                    contextual_mult *= self._config.trust_boundary_multiplier

                asset_crit = context.get("asset_criticality")
                if isinstance(asset_crit, (int, float)) and 0.0 <= asset_crit <= 1.0:
                    contextual_mult *= (0.8 + 0.4 * float(asset_crit))

            # 5c. Blast Radius Estimation
            blast_radius_report = self._blast_radius_estimator.estimate(unique_findings, context=context)

        # Apply contextual multiplier if any
        if contextual_mult != 1.0:
            overall_score = min(1.0, max(0.0, overall_score * contextual_mult))

        # 6. Determined risk level (mapped against score thresholds)
        risk_level = self._config.determine_risk_level(overall_score)

        meta: Dict[str, Any] = {
            "risk_level": risk_level.value,
            "findings_count": len(raw_list),
            "deduplicated_count": len(unique_findings),
            "category_count": len(category_scores),
        }
        if correlation_report and correlation_report.is_compound_attack:
            meta["correlation"] = correlation_report.model_dump(mode="json")
        if blast_radius_report:
            meta["blast_radius"] = blast_radius_report.model_dump(mode="json")
        if contextual_mult != 1.0:
            meta["contextual_multiplier"] = round(contextual_mult, 4)

        return RiskScore(
            score=round(overall_score, 4),
            max_severity=max_severity,
            category_scores={k: round(v, 4) for k, v in category_scores.items()},
            metadata=meta,
        )

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Eliminate duplicate findings with identical span and category, retaining highest score."""
        grouped: Dict[tuple, List[Finding]] = defaultdict(list)

        for f in findings:
            # Group key: (threat_type, start_pos, end_pos)
            key = (f.threat_type, f.start_pos, f.end_pos)
            grouped[key].append(f)

        deduped: List[Finding] = []
        for key, group in grouped.items():
            if len(group) == 1 or key[1] is None or key[2] is None:
                # If spans are not provided, do not arbitrarily merge different detections
                deduped.extend(group)
            else:
                # Retain the finding with the highest individual impact
                best = max(
                    group,
                    key=lambda x: (
                        self._config.severity_weights.get(x.severity, 0.5) * x.confidence
                    ),
                )
                deduped.append(best)

        return deduped

    def _calculate_category_scores(
        self, findings: List[Finding]
    ) -> tuple[Dict[str, float], Dict[str, List[Finding]]]:
        """Calculate normalized risk score for each threat category with diminishing returns."""
        by_category: Dict[str, List[Finding]] = defaultdict(list)
        for f in findings:
            by_category[f.threat_type.value].append(f)

        category_scores: Dict[str, float] = {}

        for cat_name, cat_findings in by_category.items():
            # Calculate atomic finding scores
            item_scores: List[float] = []
            for f in cat_findings:
                base_weight = self._config.severity_weights.get(f.severity, 0.5)
                multiplier = self._config.category_multipliers.get(f.threat_type, 1.0)
                item_score = base_weight * f.confidence * multiplier
                # Bounded in [0.0, 1.0]
                item_scores.append(min(1.0, max(0.0, item_score)))

            # Sort descending: primary finding contributes highest
            item_scores.sort(reverse=True)

            # Diminishing returns: primary + sum(secondary * decay_factor^k)
            cat_total = item_scores[0]
            for k, sec_score in enumerate(item_scores[1:], start=1):
                decay = self._config.decay_factor ** k
                cat_total += sec_score * decay

            category_scores[cat_name] = min(1.0, cat_total)

        return category_scores, by_category

    def _calculate_composite_score(self, category_scores: Dict[str, float]) -> float:
        """Combine category scores into an overall normalized score [0.0, 1.0]."""
        if not category_scores:
            return 0.0

        sorted_scores = sorted(category_scores.values(), reverse=True)
        primary_category_score = sorted_scores[0]

        # Additional distinct threat categories compound the risk with a 0.2 factor
        additional_threat_contribution = sum(
            s * 0.2 for s in sorted_scores[1:]
        )

        composite = primary_category_score + additional_threat_contribution
        return min(1.0, max(0.0, composite))
