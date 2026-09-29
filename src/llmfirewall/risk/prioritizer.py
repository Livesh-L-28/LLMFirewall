"""Evidence-driven risk prioritizer and contextual risk analyzer for Phase 37."""

import hashlib
import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from llmfirewall.audit import AuditLogger
from llmfirewall.core.models import Action, AuditEvent, Severity
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

logger = logging.getLogger("llmfirewall.risk.prioritizer")


class RiskPrioritizationEngine:
    """System-wide, evidence-driven risk prioritization engine explaining why issues are prioritized."""

    def __init__(
        self,
        inventory: Optional[Any] = None,
        kg: Optional[Any] = None,
        attack_graph: Optional[Any] = None,
        spm: Optional[Any] = None,
        compliance: Optional[Any] = None,
        governance: Optional[Any] = None,
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        self.inventory = inventory
        self.kg = kg
        self.attack_graph = attack_graph
        self.spm = spm
        self.compliance = compliance
        self.governance = governance
        self.audit_logger = audit_logger

        self._lock = threading.RLock()
        self._risk_store: Dict[str, RiskAssessment] = {}
        self._risk_history: List[RiskHistoryEntry] = []
        self._previous_snapshot: Optional[RiskSnapshot] = None

    def _emit_audit(self, event_type: str, details: Dict[str, Any]) -> None:
        if not self.audit_logger:
            return
        try:
            event = AuditEvent(
                scan_id=f"RISK-{details.get('asset_id') or 'event'}",
                action_taken=Action.ALLOW,
                risk_score=0.0,
                max_severity=Severity.LOW,
                metadata={"risk_event": event_type, **details},
            )
            self.audit_logger.emit(event)
        except Exception as exc:
            logger.warning("Failed to emit risk audit event %s: %s", event_type, exc)

    # -------------------------------------------------------------------------
    # Contextual Asset Risk Assessment
    # -------------------------------------------------------------------------

    def assess_asset_risk(self, asset_id: str) -> List[RiskAssessment]:
        """Perform evidence-driven risk analysis explaining prioritization for an asset."""
        now = time.time()
        self._emit_audit("RISK_ASSESSMENT_STARTED", {"asset_id": asset_id, "timestamp": now})

        # 1. Gather Asset Attributes
        asset = None
        if self.inventory:
            asset = self.inventory.get(asset_id)
        if not asset and self.kg:
            node = self.kg.get_node(asset_id)
            if node:
                from llmfirewall.inventory.models import Asset, AssetSource, AssetStatus
                asset = Asset(
                    id=node.id,
                    type=node.type,
                    name=node.properties.get("name") or node.id,
                    environment=node.properties.get("environment", "production"),
                    source=AssetSource.GRAPH,
                    status=AssetStatus.ACTIVE,
                    metadata=node.properties,
                )

        if not asset:
            from llmfirewall.inventory.models import Asset, AssetSource, AssetStatus
            asset = Asset(
                id=asset_id,
                type="agent" if "agent" in asset_id else "application",
                name=asset_id,
                environment="production",
                source=AssetSource.USER_REGISTERED,
                status=AssetStatus.ACTIVE,
            )

        meta = getattr(asset, "metadata", {}) or {}
        is_external = (
            getattr(asset, "exposure", "internal") == "external"
            or meta.get("exposure") == "external"
            or "external" in getattr(asset, "tags", [])
        )
        exposure_str = "external" if is_external else "internal"

        # Determine asset criticality
        crit_val = meta.get("criticality")
        if isinstance(crit_val, (int, float)):
            criticality = float(crit_val)
        elif crit_val == "critical":
            criticality = 0.9
        elif meta.get("sensitivity") in ("high", "restricted") or meta.get("data_classification") in ("restricted", "sensitive"):
            criticality = 0.8
        else:
            criticality = 0.5


        # 2. Risk Inheritance from Downstream Assets (Section 37.8)
        downstream_sensitive_targets: List[str] = []
        if self.kg:
            try:
                visited: Set[str] = set()
                queue = [asset_id]
                for _ in range(2):  # 2-hop traversal (e.g. Agent -> Tool -> DB)
                    next_queue = []
                    for curr in queue:
                        neighbors = self.kg.get_neighbors(curr, direction="outgoing")
                        for n in neighbors:
                            if n.id not in visited and n.id != asset_id:
                                visited.add(n.id)
                                next_queue.append(n.id)
                                n_meta = n.properties or {}
                                if (
                                    n_meta.get("sensitivity") in ("high", "restricted")
                                    or n_meta.get("criticality") in ("critical", "high")
                                    or "db" in n.id
                                    or "database" in n.id
                                    or "memory" in n.id
                                ):
                                    downstream_sensitive_targets.append(n.id)
                                    criticality = max(criticality, 0.85)
                    queue = next_queue
            except Exception as exc:
                logger.debug("Downstream risk inheritance traversal error: %s", exc)


        # 3. Gather Posture & Compliance Weaknesses
        open_gaps = []
        if self.spm:
            try:
                posture = self.spm.evaluate(asset_id)
                if posture and hasattr(posture, "security_gaps"):
                    open_gaps.extend(posture.security_gaps)
            except Exception as exc:
                logger.debug("SPM posture evaluation error during risk assessment: %s", exc)

        if self.compliance:
            try:
                comp_res = self.compliance.assess_asset(asset_id)
                for cr in comp_res:
                    open_gaps.extend(cr.gaps)
            except Exception as exc:
                logger.debug("Compliance assessment error during risk assessment: %s", exc)

        # 4. Attack Paths Involving Asset (Section 37.4)
        active_attack_paths = []
        if self.attack_graph and hasattr(self.attack_graph, "paths"):
            for p in self.attack_graph.paths:
                p_dict = p.to_dict() if hasattr(p, "to_dict") else (p if isinstance(p, dict) else {})
                if p_dict.get("status") != "BLOCKED" and (asset_id in str(p_dict) or p_dict.get("target") == asset_id):
                    active_attack_paths.append(p_dict)

        # 5. Evaluate Independent Risk Factors
        factors: List[RiskFactor] = []

        # Factor: Exposure
        exp_score = 0.9 if is_external else 0.4
        factors.append(RiskFactor(
            name="Asset Exposure",
            factor_type=RiskFactorType.EXPOSURE,
            score=exp_score,
            weight=1.2,
            description=f"Asset exposure is evaluated as {exposure_str.upper()}.",
            rationale="External exposure increases accessibility to untrusted user input." if is_external else "Internal asset requires prior perimeter compromise.",
        ))

        # Factor: Asset Criticality & Downstream Inheritance
        if downstream_sensitive_targets:
            factors.append(RiskFactor(
                name="Downstream Asset Criticality Inheritance",
                factor_type=RiskFactorType.ASSET_CRITICALITY,
                score=criticality,
                weight=1.3,
                description=f"Asset has direct execution or query access to sensitive downstream targets: {', '.join(downstream_sensitive_targets)}.",
                rationale="Compromise of this asset cascades to high-sensitivity downstream data stores.",
            ))
        else:
            factors.append(RiskFactor(
                name="Asset Criticality",
                factor_type=RiskFactorType.ASSET_CRITICALITY,
                score=criticality,
                weight=1.0,
                description=f"Base asset criticality score {criticality}.",
                rationale="Reflects the business and operational role of the asset.",
            ))

        # Factor: Data Sensitivity
        data_class = meta.get("data_classification") or meta.get("sensitivity") or "standard"
        sens_score = 0.9 if data_class in ("restricted", "secret") else (0.75 if data_class in ("sensitive", "confidential") else 0.4)
        factors.append(RiskFactor(
            name="Data Sensitivity Classification",
            factor_type=RiskFactorType.DATA_SENSITIVITY,
            score=sens_score,
            weight=1.1,
            description=f"Asset processes or accesses data classified as '{data_class}'.",
            rationale=f"Data classification '{data_class}' requires elevated confidentiality protections.",
        ))


        # Factor: Control Weakness
        control_weakness_score = 0.8 if len(open_gaps) >= 2 else (0.5 if len(open_gaps) == 1 else 0.1)
        factors.append(RiskFactor(
            name="Defensive Control Weakness",
            factor_type=RiskFactorType.CONTROL_WEAKNESS,
            score=control_weakness_score,
            weight=1.4,
            description=f"Identified {len(open_gaps)} open defensive posture or compliance gaps.",
            evidence_references=[getattr(g, "gap_id", "gap") for g in open_gaps],
            rationale="Absence or failure of required defensive controls enables adversary exploitation.",
        ))

        # Factor: Attack Path Reachability
        reach_score = 0.85 if active_attack_paths else 0.2
        factors.append(RiskFactor(
            name="Attack Path Reachability",
            factor_type=RiskFactorType.ATTACK_PATH_REACHABILITY,
            score=reach_score,
            weight=1.3,
            description=f"Correlated with {len(active_attack_paths)} unmitigated multi-step attack paths.",
            evidence_references=[p.get("path_id", "path") for p in active_attack_paths],
            rationale="Attack graph reachability establishes viable exploitation paths from threat actors.",
        ))

        # Compute Explainable Rationale and Deterministic Risk Level (Section 37.4 & 37.5)
        impact_score = round(max(0.2, criticality), 2)
        exploit_score = round(max(0.1, (control_weakness_score * 0.6) + (reach_score * 0.4)), 2)
        uncertainty = RiskUncertainty.CONFIRMED if open_gaps and active_attack_paths else (
            RiskUncertainty.SUPPORTED if open_gaps or active_attack_paths else RiskUncertainty.PARTIALLY_SUPPORTED
        )

        rationale_parts = []
        if is_external:
            rationale_parts.append("Externally reachable asset")
        else:
            rationale_parts.append("Internal asset")

        if downstream_sensitive_targets:
            rationale_parts.append(f"sensitive downstream capability ({', '.join(downstream_sensitive_targets[:2])})")

        if open_gaps:
            rationale_parts.append(f"{len(open_gaps)} open control gap(s)")

        if active_attack_paths:
            rationale_parts.append("unmitigated attack path")

        rationale = " + ".join(rationale_parts)

        # Deterministic Risk Level Mapping
        if is_external and (control_weakness_score >= 0.6 or active_attack_paths) and (impact_score >= 0.7 or downstream_sensitive_targets):
            level = RiskLevel.CRITICAL
        elif is_external and (downstream_sensitive_targets or control_weakness_score >= 0.4 or reach_score >= 0.6):
            level = RiskLevel.HIGH
        elif impact_score >= 0.8 and (control_weakness_score >= 0.4 or reach_score >= 0.5):
            level = RiskLevel.HIGH
        elif control_weakness_score >= 0.3 or reach_score >= 0.4 or is_external:
            level = RiskLevel.MEDIUM
        elif control_weakness_score > 0.0 or open_gaps:
            level = RiskLevel.LOW
        else:
            level = RiskLevel.INFORMATIONAL


        assessment_id = f"RISK-{hashlib.sha256(f'{asset_id}:{level.value}'.encode('utf-8')).hexdigest()[:8].upper()}"

        assessment = RiskAssessment(
            id=assessment_id,
            asset_id=asset_id,
            finding_id=None,
            attack_path_id=active_attack_paths[0].get("path_id") if active_attack_paths else None,
            control_id=None,
            title=f"Contextual Risk for Asset '{asset_id}'",
            level=level,
            impact=impact_score,
            exposure=exposure_str,
            exploitability=exploit_score,
            evidence_confidence=0.85 if uncertainty == RiskUncertainty.CONFIRMED else 0.6,
            asset_criticality=criticality,
            business_context=meta,
            uncertainty=uncertainty,
            factors=factors,
            rationale=rationale,
            treatment=RiskTreatment.OPEN,
            inherited_from=downstream_sensitive_targets[0] if downstream_sensitive_targets else None,
            remediation_guidance="Implement tool authorization guardrails and validate with automated security tests.",
            created_at=now,
            updated_at=now,
        )

        with self._lock:
            # Check history transition & regression
            prev = self._risk_store.get(assessment.id)
            if prev and prev.level != assessment.level:
                event_type = "INCREASED" if self._level_rank(assessment.level) > self._level_rank(prev.level) else "DECREASED"
                entry = RiskHistoryEntry(
                    risk_id=assessment.id,
                    asset_id=asset_id,
                    timestamp=now,
                    event_type=event_type,
                    previous_level=prev.level,
                    new_level=assessment.level,
                    reason=f"Risk level transitioned from {prev.level.value} to {assessment.level.value} based on updated control evidence.",
                )
                self._risk_history.append(entry)
                if event_type == "INCREASED":
                    self._emit_audit("RISK_INCREASED", {
                        "risk_id": assessment.id,
                        "asset_id": asset_id,
                        "previous_level": prev.level.value,
                        "new_level": assessment.level.value,
                    })
            elif not prev:
                entry = RiskHistoryEntry(
                    risk_id=assessment.id,
                    asset_id=asset_id,
                    timestamp=now,
                    event_type="CREATED",
                    previous_level=None,
                    new_level=assessment.level,
                    reason="Initial risk assessment established.",
                )
                self._risk_history.append(entry)

            self._risk_store[assessment.id] = assessment

        self._emit_audit("RISK_ASSESSMENT_COMPLETED", {
            "asset_id": asset_id,
            "risk_level": level.value,
            "impact": impact_score,
            "exploitability": exploit_score,
        })

        return [assessment]

    @staticmethod
    def _level_rank(level: RiskLevel) -> int:
        ranks = {
            RiskLevel.CRITICAL: 5,
            RiskLevel.HIGH: 4,
            RiskLevel.MEDIUM: 3,
            RiskLevel.LOW: 2,
            RiskLevel.INFORMATIONAL: 1,
            RiskLevel.UNKNOWN: 0,
        }
        return ranks.get(level, 0)

    # -------------------------------------------------------------------------
    # Prioritization Across System
    # -------------------------------------------------------------------------

    def prioritize(self, asset_id: Optional[str] = None) -> List[RiskAssessment]:
        """Evaluate and return sorted list of risk assessments descending by severity and exposure."""
        if asset_id:
            assessments = self.assess_asset_risk(asset_id)
        else:
            assets_to_eval = []
            if self.inventory:
                assets_to_eval = [a.id for a in self.inventory.list_assets()]
            elif self.kg:
                assets_to_eval = [n.id for n in self.kg.get_all_nodes()]
            if not assets_to_eval:
                assets_to_eval = ["application:default"]

            assessments = []
            for aid in assets_to_eval:
                assessments.extend(self.assess_asset_risk(aid))

        # Sort descending by level rank, then impact, then exploitability
        sorted_risks = sorted(
            assessments,
            key=lambda r: (self._level_rank(r.level), r.impact, r.exploitability),
            reverse=True,
        )
        return sorted_risks

    # -------------------------------------------------------------------------
    # History, Snapshots & Regressions
    # -------------------------------------------------------------------------

    def get_risk_history(self, asset_id: Optional[str] = None) -> List[RiskHistoryEntry]:
        with self._lock:
            if asset_id:
                return [h for h in self._risk_history if h.asset_id == asset_id]
            return list(self._risk_history)

    def snapshot(self, environment: str = "production") -> RiskSnapshot:
        """Create a cryptographic baseline snapshot of current risk posture."""
        risks = self.prioritize()
        risk_dict = {r.id: r for r in risks}
        summary = {
            "total_risks": len(risks),
            "critical": sum(1 for r in risks if r.level == RiskLevel.CRITICAL),
            "high": sum(1 for r in risks if r.level == RiskLevel.HIGH),
            "medium": sum(1 for r in risks if r.level == RiskLevel.MEDIUM),
            "low": sum(1 for r in risks if r.level == RiskLevel.LOW),
            "environment": environment,
        }
        snap = RiskSnapshot.create(risks=risk_dict, summary=summary)

        with self._lock:
            self._previous_snapshot = snap
        return snap

    def diff(self, previous: RiskSnapshot, current: RiskSnapshot) -> RiskDiff:
        """Compare two risk snapshots and detect risk regressions (RISK_INCREASED)."""
        regressions: List[str] = []
        level_changes: List[str] = []

        prev_keys = set(previous.risks.keys())
        curr_keys = set(current.risks.keys())

        new_risks = [current.risks[k] for k in curr_keys - prev_keys]
        resolved_risks = [previous.risks[k] for k in prev_keys - curr_keys]

        for k in sorted(list(prev_keys & curr_keys)):
            pr = previous.risks[k]
            cr = current.risks[k]

            if pr.level != cr.level:
                change_str = f"Risk '{k}' on asset '{cr.asset_id}': {pr.level.value} -> {cr.level.value}"
                level_changes.append(change_str)
                if self._level_rank(cr.level) > self._level_rank(pr.level):
                    reg_str = f"RISK_INCREASED: Risk '{k}' ({cr.title}) escalated from {pr.level.value} to {cr.level.value}."
                    regressions.append(reg_str)
                    self._emit_audit("RISK_INCREASED", {
                        "risk_id": cr.id,
                        "asset_id": cr.asset_id,
                        "previous_level": pr.level.value,
                        "new_level": cr.level.value,
                    })

        is_identical = (
            previous.snapshot_hash == current.snapshot_hash and
            len(regressions) == 0 and
            len(level_changes) == 0 and
            len(new_risks) == 0 and
            len(resolved_risks) == 0
        )

        return RiskDiff(
            is_identical=is_identical,
            regressions=regressions,
            level_changes=level_changes,
            new_risks=new_risks,
            resolved_risks=resolved_risks,
            summary={
                "regressions_count": len(regressions),
                "total_increased": len(regressions),
                "level_changes_count": len(level_changes),
                "new_risks_count": len(new_risks),
                "resolved_risks_count": len(resolved_risks),
            },
        )

