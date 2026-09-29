"""Compliance and control-mapping engine for Phase 36 — AI Security Compliance & Control Mapping."""

from datetime import datetime, timezone
import hashlib
import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from llmfirewall.audit import AuditLogger
from llmfirewall.compliance.catalog import ControlCatalog
from llmfirewall.compliance.models import (
    ApplicabilityStatus,
    ComplianceControl,
    ComplianceDiff,
    ComplianceEvidence,
    ComplianceException,
    ComplianceFramework,
    ComplianceGap,
    ComplianceSnapshot,
    ControlAssessment,
    ControlMapping,
    ControlState,
    CrossFrameworkMapping,
    EvidenceType,
    EvidenceValidity,
    ExceptionStatus,
    MappingType,
    RemediationStatus,
    sanitize_compliance_metadata,
)
from llmfirewall.compliance.rules import ComplianceRuleContext, ComplianceRuleRegistry
from llmfirewall.core.models import Action, AuditEvent, Severity

logger = logging.getLogger("llmfirewall.compliance.engine")


# -----------------------------------------------------------------------------
# Telemetry Metrics Collector
# -----------------------------------------------------------------------------

class ComplianceMetrics:
    """Thread-safe bounded Prometheus-compatible metrics collector for compliance operations."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.compliance_assessments_total = 0
        self.compliance_assessment_failures_total = 0
        self.controls_assessed_total = 0
        self.compliance_gaps_total = 0
        self.evidence_items_total = 0
        self.expired_evidence_total = 0
        self.compliance_regressions_total = 0
        self.frameworks_loaded_total = 0

    def inc_assessments(self, count: int = 1) -> None:
        with self._lock:
            self.compliance_assessments_total += count

    def inc_assessment_failures(self, count: int = 1) -> None:
        with self._lock:
            self.compliance_assessment_failures_total += count

    def inc_controls_assessed(self, count: int = 1) -> None:
        with self._lock:
            self.controls_assessed_total += count

    def inc_gaps(self, count: int = 1) -> None:
        with self._lock:
            self.compliance_gaps_total += count

    def inc_evidence(self, count: int = 1) -> None:
        with self._lock:
            self.evidence_items_total += count

    def inc_expired_evidence(self, count: int = 1) -> None:
        with self._lock:
            self.expired_evidence_total += count

    def inc_regressions(self, count: int = 1) -> None:
        with self._lock:
            self.compliance_regressions_total += count

    def inc_frameworks_loaded(self, count: int = 1) -> None:
        with self._lock:
            self.frameworks_loaded_total += count

    def to_dict(self) -> Dict[str, int]:
        with self._lock:
            return {
                "compliance_assessments_total": self.compliance_assessments_total,
                "compliance_assessment_failures_total": self.compliance_assessment_failures_total,
                "controls_assessed_total": self.controls_assessed_total,
                "compliance_gaps_total": self.compliance_gaps_total,
                "evidence_items_total": self.evidence_items_total,
                "expired_evidence_total": self.expired_evidence_total,
                "compliance_regressions_total": self.compliance_regressions_total,
                "frameworks_loaded_total": self.frameworks_loaded_total,
            }


# -----------------------------------------------------------------------------
# Compliance Engine
# -----------------------------------------------------------------------------

class ComplianceEngine:
    """Evidence-driven compliance and control-mapping engine for AI systems."""

    def __init__(
        self,
        catalog: Optional[ControlCatalog] = None,
        rule_registry: Optional[ComplianceRuleRegistry] = None,
        inventory: Optional[Any] = None,
        kg: Optional[Any] = None,
        attack_graph: Optional[Any] = None,
        spm: Optional[Any] = None,
        governance: Optional[Any] = None,
        audit_logger: Optional[AuditLogger] = None,
    ) -> None:
        self.catalog = catalog or ControlCatalog()
        self.rule_registry = rule_registry or ComplianceRuleRegistry()
        self.inventory = inventory
        self.kg = kg
        self.attack_graph = attack_graph
        self.spm = spm
        self.governance = governance
        self.audit_logger = audit_logger

        self.metrics = ComplianceMetrics()
        self.metrics.inc_frameworks_loaded(len(self.catalog.list_frameworks()))

        self._lock = threading.RLock()
        self._evidence_store: Dict[str, ComplianceEvidence] = {}
        self._asset_evidence: Dict[str, Set[str]] = {}
        self._control_evidence: Dict[str, Set[str]] = {}
        self._exceptions: Dict[str, ComplianceException] = {}
        self._control_mappings: List[ControlMapping] = []
        self._assessment_cache: Dict[str, ControlAssessment] = {}
        self._previous_snapshot: Optional[ComplianceSnapshot] = None

    # -------------------------------------------------------------------------
    # Audit Logging Helper
    # -------------------------------------------------------------------------

    def _emit_audit(self, event_type: str, details: Dict[str, Any]) -> None:
        if not self.audit_logger:
            return
        try:
            event = AuditEvent(
                scan_id=f"COMPLIANCE-{details.get('asset_id') or 'event'}",
                action_taken=Action.ALLOW,
                risk_score=0.0,
                max_severity=Severity.LOW,
                metadata={
                    "compliance_event": event_type,
                    **sanitize_compliance_metadata(details),
                },
            )
            self.audit_logger.emit(event)
        except Exception as exc:
            logger.warning("Failed to emit compliance audit event %s: %s", event_type, exc)

    # -------------------------------------------------------------------------
    # Evidence Management
    # -------------------------------------------------------------------------

    def add_evidence(self, evidence: ComplianceEvidence) -> None:
        """Register an evidence artifact with provenance and conflict detection."""
        with self._lock:
            # Check for conflicting evidence on this asset and control
            existing_ids = self._asset_evidence.get(evidence.asset_id, set()) & self._control_evidence.get(evidence.control_id, set())
            for eid in existing_ids:
                existing = self._evidence_store.get(eid)
                if not existing:
                    continue
                # Conflict detection: If one is valid positive policy and another is negative runtime/finding/failed test
                is_policy = existing.type == EvidenceType.POLICY or evidence.type == EvidenceType.POLICY
                is_runtime_or_test = (
                    existing.type in (EvidenceType.RUNTIME_EVENT, EvidenceType.SECURITY_TEST, EvidenceType.FINDING) or
                    evidence.type in (EvidenceType.RUNTIME_EVENT, EvidenceType.SECURITY_TEST, EvidenceType.FINDING)
                )
                if is_policy and is_runtime_or_test:
                    # Check if status contradicts
                    existing_disabled = "disable" in existing.content_reference.lower() or "fail" in existing.content_reference.lower()
                    new_disabled = "disable" in evidence.content_reference.lower() or "fail" in evidence.content_reference.lower()
                    if existing_disabled != new_disabled:
                        # Mark both as conflicting
                        evidence = ComplianceEvidence(
                            id=evidence.id,
                            type=evidence.type,
                            source=evidence.source,
                            asset_id=evidence.asset_id,
                            control_id=evidence.control_id,
                            collected_at=evidence.collected_at,
                            expires_at=evidence.expires_at,
                            last_verified=evidence.last_verified,
                            content_reference=evidence.content_reference,
                            status=EvidenceValidity.CONFLICTING,
                            attestation=evidence.attestation,
                            metadata=evidence.metadata,
                        )
                        updated_existing = ComplianceEvidence(
                            id=existing.id,
                            type=existing.type,
                            source=existing.source,
                            asset_id=existing.asset_id,
                            control_id=existing.control_id,
                            collected_at=existing.collected_at,
                            expires_at=existing.expires_at,
                            last_verified=existing.last_verified,
                            content_reference=existing.content_reference,
                            status=EvidenceValidity.CONFLICTING,
                            attestation=existing.attestation,
                            metadata=existing.metadata,
                        )
                        self._evidence_store[existing.id] = updated_existing

            self._evidence_store[evidence.id] = evidence
            self._asset_evidence.setdefault(evidence.asset_id, set()).add(evidence.id)
            self._control_evidence.setdefault(evidence.control_id, set()).add(evidence.id)
            self._assessment_cache.clear()

        self.metrics.inc_evidence()
        self._emit_audit("EVIDENCE_ADDED", {
            "evidence_id": evidence.id,
            "type": evidence.type.value,
            "control_id": evidence.control_id,
            "asset_id": evidence.asset_id,
            "status": evidence.status.value,
        })

    def add_manual_attestation(
        self,
        control_id: str,
        asset_id: str,
        attestor: str,
        statement: str,
        scope: str = "asset",
        duration_seconds: float = 90 * 86400,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ComplianceEvidence:
        """Register a formal human attestation as supporting evidence."""
        now = time.time()
        evid = ComplianceEvidence(
            type=EvidenceType.MANUAL_ATTESTATION,
            source=f"attestation:{attestor}",
            asset_id=asset_id,
            control_id=control_id,
            collected_at=now,
            expires_at=now + duration_seconds,
            last_verified=now,
            content_reference=f"attestation:{attestor}:{int(now)}",
            status=EvidenceValidity.VALID,
            attestation={
                "attestor": attestor,
                "timestamp": now,
                "scope": scope,
                "statement": statement,
                "expiration": now + duration_seconds,
            },
            metadata=sanitize_compliance_metadata(metadata or {}),
        )
        self.add_evidence(evid)
        return evid

    def get_evidence(self, evidence_id: str) -> Optional[ComplianceEvidence]:
        with self._lock:
            return self._evidence_store.get(evidence_id)

    def list_evidence(
        self,
        asset_id: Optional[str] = None,
        control_id: Optional[str] = None,
    ) -> List[ComplianceEvidence]:
        """List collected evidence filtered optionally by asset or control."""
        with self._lock:
            if asset_id and control_id:
                ids = self._asset_evidence.get(asset_id, set()) & self._control_evidence.get(control_id, set())
                return [self._evidence_store[eid] for eid in ids if eid in self._evidence_store]
            elif asset_id:
                ids = self._asset_evidence.get(asset_id, set())
                return [self._evidence_store[eid] for eid in ids if eid in self._evidence_store]
            elif control_id:
                ids = self._control_evidence.get(control_id, set())
                return [self._evidence_store[eid] for eid in ids if eid in self._evidence_store]
            return list(self._evidence_store.values())

    # -------------------------------------------------------------------------
    # Exception Management
    # -------------------------------------------------------------------------

    def add_exception(
        self,
        control_id: str,
        asset_id: str,
        reason: str,
        approved_by: str,
        duration_seconds: float = 30 * 86400,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ComplianceException:
        """Register a formally approved business exception or waiver."""
        if not approved_by or not approved_by.strip():
            raise ValueError("Exception requires an explicit approving officer or role (approved_by cannot be empty).")

        now = time.time()
        exc = ComplianceException(
            control_id=control_id,
            asset_id=asset_id,
            reason=reason,
            approved_by=approved_by.strip(),
            created_at=now,
            expires_at=now + duration_seconds,
            status=ExceptionStatus.ACTIVE,
            metadata=sanitize_compliance_metadata(metadata or {}),
        )
        with self._lock:
            self._exceptions[exc.exception_id] = exc
            self._assessment_cache.clear()

        self._emit_audit("COMPLIANCE_EXCEPTION_CREATED", {
            "exception_id": exc.exception_id,
            "control_id": control_id,
            "asset_id": asset_id,
            "approved_by": approved_by,
            "expires_at": exc.expires_at,
        })
        return exc

    def list_exceptions(self, active_only: bool = False) -> List[ComplianceException]:
        """List compliance exceptions and trigger automatic expiration checks."""
        now = time.time()
        results: List[ComplianceException] = []
        with self._lock:
            for exc in list(self._exceptions.values()):
                if exc.status == ExceptionStatus.ACTIVE and now > exc.expires_at:
                    # Mark expired
                    expired_exc = ComplianceException(
                        exception_id=exc.exception_id,
                        control_id=exc.control_id,
                        asset_id=exc.asset_id,
                        reason=exc.reason,
                        approved_by=exc.approved_by,
                        created_at=exc.created_at,
                        expires_at=exc.expires_at,
                        status=ExceptionStatus.EXPIRED,
                        metadata=exc.metadata,
                    )
                    self._exceptions[exc.exception_id] = expired_exc
                    self._emit_audit("COMPLIANCE_EXCEPTION_EXPIRED", {
                        "exception_id": exc.exception_id,
                        "control_id": exc.control_id,
                        "asset_id": exc.asset_id,
                    })
                    results.append(expired_exc)
                else:
                    results.append(exc)

        if active_only:
            return [e for e in results if e.is_active]
        return results

    # -------------------------------------------------------------------------
    # Control Mapping
    # -------------------------------------------------------------------------

    def add_mapping(self, mapping: ControlMapping) -> None:
        """Register a many-to-many relationship mapping."""
        with self._lock:
            self._control_mappings.append(mapping)
        self._emit_audit("CONTROL_MAPPED", {
            "mapping_id": mapping.mapping_id,
            "control_id": mapping.control_id,
            "asset_id": mapping.asset_id,
            "security_control_id": mapping.security_control_id,
            "posture_dimension": mapping.posture_dimension,
        })

    def list_mappings(self, control_id: Optional[str] = None) -> List[ControlMapping]:
        with self._lock:
            if control_id:
                return [m for m in self._control_mappings if m.control_id.lower() == control_id.lower()]
            return list(self._control_mappings)

    # -------------------------------------------------------------------------
    # Context Assembly & Subsystem Ingestion
    # -------------------------------------------------------------------------

    def _resolve_asset_object(self, asset_id: str) -> Any:
        """Resolve asset instance from Inventory or Knowledge Graph."""
        if self.inventory:
            asset = self.inventory.get(asset_id)
            if asset:
                return asset

        if self.kg:
            node = self.kg.get_node(asset_id)
            if node:
                from llmfirewall.inventory.models import Asset, AssetSource, AssetStatus
                return Asset(
                    id=node.id,
                    type=node.type,
                    name=node.properties.get("name") or node.id,
                    environment=node.properties.get("environment", "unknown"),
                    source=AssetSource.GRAPH,
                    status=AssetStatus.ACTIVE,
                    metadata=node.properties,
                )

        # Fallback synthetic asset
        from llmfirewall.inventory.models import Asset, AssetSource, AssetStatus
        parts = asset_id.split(":")
        atype = parts[0] if len(parts) > 1 else "application"
        return Asset(
            id=asset_id,
            type=atype,
            name=asset_id,
            environment="production",
            source=AssetSource.USER_REGISTERED,
            status=AssetStatus.ACTIVE,
        )

    def _gather_evidence_for_assessment(
        self,
        control: ComplianceControl,
        asset: Any,
    ) -> Tuple[List[ComplianceEvidence], Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
        """Gather and refresh evidence across Inventory, SPM, Knowledge Graph, Attack Graph, and Governance."""
        asset_id = getattr(asset, "id", str(asset))
        now = time.time()

        # 1. Existing registered evidence
        with self._lock:
            evid_ids = self._asset_evidence.get(asset_id, set()) & self._control_evidence.get(control.id, set())
            gathered: List[ComplianceEvidence] = []
            for eid in evid_ids:
                e = self._evidence_store.get(eid)
                if not e:
                    continue
                # Freshness check: Has asset changed since evidence was verified?
                asset_last_seen = getattr(asset, "last_seen", now)
                if asset_last_seen > e.last_verified + 1.0 or e.is_expired:
                    e = ComplianceEvidence(
                        id=e.id,
                        type=e.type,
                        source=e.source,
                        asset_id=e.asset_id,
                        control_id=e.control_id,
                        collected_at=e.collected_at,
                        expires_at=e.expires_at,
                        last_verified=e.last_verified,
                        content_reference=e.content_reference,
                        status=EvidenceValidity.STALE,
                        attestation=e.attestation,
                        metadata=e.metadata,
                    )
                    self._evidence_store[e.id] = e
                    self.metrics.inc_expired_evidence()
                    self._emit_audit("EVIDENCE_EXPIRED", {"evidence_id": e.id, "control_id": control.id, "asset_id": asset_id})
                gathered.append(e)

        # 2. Phase 34 Inventory Evidence
        if self.inventory and hasattr(asset, "metadata"):
            inv_evid = ComplianceEvidence(
                id=f"EVID-INV-{asset_id.replace(':', '_')}",
                type=EvidenceType.ASSET_INVENTORY,
                source="llmfirewall.inventory",
                asset_id=asset_id,
                control_id=control.id,
                collected_at=getattr(asset, "first_seen", now),
                last_verified=getattr(asset, "last_seen", now),
                content_reference=f"inventory_asset:{asset_id}",
                status=EvidenceValidity.VALID,
                metadata={"asset_type": getattr(asset, "type", "unknown")},
            )
            gathered.append(inv_evid)

        # 3. Phase 35 Posture & Security Controls
        security_controls: Dict[str, Any] = {}
        posture_obj = None
        if self.spm:
            try:
                posture_obj = self.spm.evaluate(asset_id)
                if posture_obj and hasattr(posture_obj, "security_controls"):
                    for sc_id, sc in posture_obj.security_controls.items():
                        security_controls[sc_id] = sc
                        # Map defensive control to compliance evidence
                        posture_evid = ComplianceEvidence(
                            id=f"EVID-POSTURE-{sc_id.replace(':', '_')}",
                            type=EvidenceType.POSTURE,
                            source="llmfirewall.spm",
                            asset_id=asset_id,
                            control_id=control.id,
                            collected_at=now,
                            last_verified=now,
                            content_reference=f"security_control:{sc_id}",
                            status=EvidenceValidity.VALID if getattr(sc, "effectiveness", None) == "VALIDATED" else EvidenceValidity.VALID,
                            metadata={"effectiveness": str(getattr(sc, "effectiveness", "CONFIGURED"))},
                        )
                        gathered.append(posture_evid)
            except Exception as exc:
                logger.debug("SPM posture evaluation error during compliance collection: %s", exc)

        # 4. Phase 30 / SPM Test Ingestion
        tests: List[Dict[str, Any]] = []
        if self.spm and hasattr(self.spm, "_ingested_test_results"):
            for t in self.spm._ingested_test_results:
                if t.get("asset_id") == asset_id:
                    tests.append(t)
                    # Create security test evidence
                    is_passed = t.get("passed", True)
                    test_evid = ComplianceEvidence(
                        id=f"EVID-TEST-{t.get('test_id', 't')}",
                        type=EvidenceType.SECURITY_TEST,
                        source="llmfirewall.testing",
                        asset_id=asset_id,
                        control_id=control.id,
                        collected_at=t.get("timestamp", now),
                        last_verified=now,
                        content_reference=f"test_run:{t.get('test_id', 'unknown')}",
                        status=EvidenceValidity.VALID if is_passed else EvidenceValidity.VALID,
                        metadata={"passed": is_passed, "name": t.get("name", "")},
                    )
                    gathered.append(test_evid)

        # 5. Phase 31 Governance Policies & Findings
        findings: List[Dict[str, Any]] = []
        policy_status: Dict[str, Any] = {}
        if self.governance:
            # Query policies assigned to this asset
            if hasattr(self.governance, "get_asset_policies"):
                pols = self.governance.get_asset_policies(asset_id)
                policy_status["assigned_policies"] = pols
                for p in pols:
                    pol_evid = ComplianceEvidence(
                        id=f"EVID-POL-{p.get('id', 'pol')}",
                        type=EvidenceType.POLICY,
                        source="llmfirewall.governance",
                        asset_id=asset_id,
                        control_id=control.id,
                        collected_at=now,
                        last_verified=now,
                        content_reference=f"governance_policy:{p.get('id')}",
                        status=EvidenceValidity.VALID,
                        metadata=p,
                    )
                    gathered.append(pol_evid)

        if self.spm and hasattr(self.spm, "_ingested_findings"):
            for f in self.spm._ingested_findings:
                if f.get("asset_id") == asset_id:
                    findings.append(f)
                    f_evid = ComplianceEvidence(
                        id=f"EVID-FIND-{f.get('finding_id', 'f')}",
                        type=EvidenceType.FINDING,
                        source="llmfirewall.findings",
                        asset_id=asset_id,
                        control_id=control.id,
                        collected_at=now,
                        last_verified=now,
                        content_reference=f"finding:{f.get('finding_id')}",
                        status=EvidenceValidity.VALID,
                        metadata=f,
                    )
                    gathered.append(f_evid)

        # 6. Phase 33 Attack Graph Paths
        attack_paths: List[Dict[str, Any]] = []
        if self.attack_graph and hasattr(self.attack_graph, "paths"):
            for p in self.attack_graph.paths:
                p_dict = p.to_dict() if hasattr(p, "to_dict") else (p if isinstance(p, dict) else {})
                target_node = p_dict.get("target") or p_dict.get("target_id")
                if target_node == asset_id or asset_id in str(p_dict):
                    attack_paths.append(p_dict)

        # Deduplicate gathered evidence by id
        dedup_evid = list({e.id: e for e in gathered}.values())

        return dedup_evid, security_controls, tests, findings, attack_paths, policy_status

    # -------------------------------------------------------------------------
    # Assessment Execution
    # -------------------------------------------------------------------------

    def assess_control(self, control_id: str, asset_id: str) -> ControlAssessment:
        """Evaluate an individual compliance control for a specific asset."""
        control = self.catalog.get_control(control_id)
        if not control:
            raise KeyError(f"Compliance control '{control_id}' not found in catalog.")

        asset = self._resolve_asset_object(asset_id)
        evid, sec_ctrls, tests, findings, attack_paths, pol_status = self._gather_evidence_for_assessment(control, asset)

        # Active exceptions
        exceptions = [ex for ex in self.list_exceptions(active_only=True) if ex.control_id.lower() == control.id.lower() and (ex.asset_id == asset_id or ex.asset_id == "*")]

        ctx = ComplianceRuleContext(
            control=control,
            asset=asset,
            evidence=evid,
            security_controls=sec_ctrls,
            posture=None,
            tests=tests,
            findings=findings,
            attack_paths=attack_paths,
            policy_status=pol_status,
            exceptions=exceptions,
            kg=self.kg,
        )

        assessment = self.rule_registry.evaluate(ctx)

        # Build Section 63 Complete Evidence Chain
        sec_ctrl_keys = list(sec_ctrls.keys())
        test_policy_finding = (
            [f"test:{t.get('test_id', 't')}:{t.get('passed', True)}" for t in tests] +
            [f"policy:{p.get('id', 'pol')}" for p in pol_status.get("assigned_policies", [])] +
            [f"finding:{f.get('finding_id', 'f')}:{f.get('status', 'open')}" for f in findings]
        )
        posture_str = "VALIDATED" if any(getattr(c, "effectiveness", None) == "VALIDATED" for c in sec_ctrls.values()) else ("CONFIGURED" if sec_ctrls else "MISSING")

        evidence_chain = {
            "framework_control": control.id,
            "requirement": control.requirements,
            "control": control.id,
            "asset": asset_id,
            "security_controls": sec_ctrl_keys,
            "posture": posture_str,
            "test_policy_finding": test_policy_finding,
            "evidence": [e.id for e in evid],
        }

        # Enrich assessment with related entities and evidence chain
        enriched_assessment = ControlAssessment(
            assessment_id=assessment.assessment_id,
            framework_id=control.framework_id,
            control_id=control.id,
            asset_id=asset_id,
            status=assessment.status,
            applicability=assessment.applicability,
            applicability_reason=assessment.applicability_reason,
            evidence=evid,
            missing_evidence=assessment.missing_evidence,
            gaps=assessment.gaps,
            exceptions=exceptions,
            related_attack_paths=attack_paths,
            related_findings=findings,
            related_security_controls=sec_ctrl_keys,
            evidence_chain=evidence_chain,
            assessed_at=time.time(),
            rules_version=self.rule_registry.rules_version,
        )

        # Audit events for gaps
        for g in enriched_assessment.gaps:
            self.metrics.inc_gaps()
            self._emit_audit("COMPLIANCE_GAP_CREATED", {
                "gap_id": g.gap_id,
                "control_id": control.id,
                "asset_id": asset_id,
                "severity": g.severity.value,
            })

        self.metrics.inc_controls_assessed()
        return enriched_assessment

    def assess_asset(
        self,
        asset_id: str,
        framework_id: Optional[str] = None,
    ) -> List[ControlAssessment]:
        """Perform compliance assessment across applicable framework controls for a single asset."""
        now = time.time()
        self._emit_audit("COMPLIANCE_ASSESSMENT_STARTED", {"asset_id": asset_id, "timestamp": now})

        frameworks = [self.catalog.get_framework(framework_id)] if framework_id else self.catalog.list_frameworks()
        controls_to_assess: List[ComplianceControl] = []
        for fw in frameworks:
            if fw:
                controls_to_assess.extend(fw.controls.values())

        assessments: List[ControlAssessment] = []
        for ctrl in controls_to_assess:
            res = self.assess_control(ctrl.id, asset_id)
            assessments.append(res)

        self.metrics.inc_assessments()
        self._emit_audit("COMPLIANCE_ASSESSMENT_COMPLETED", {
            "asset_id": asset_id,
            "controls_assessed": len(assessments),
            "evidenced": sum(1 for a in assessments if a.status == ControlState.EVIDENCED),
            "gaps": sum(len(a.gaps) for a in assessments),
        })
        return assessments

    def assess_environment(
        self,
        framework_id: Optional[str] = None,
    ) -> Dict[str, List[ControlAssessment]]:
        """Perform environment-wide compliance assessment aggregating controls across discovered assets."""
        assets_in_scope: List[str] = []
        if self.inventory:
            assets_in_scope = [a.id for a in self.inventory.list_assets()]
        elif self.kg:
            assets_in_scope = [n.id for n in self.kg.get_all_nodes()]
        else:
            with self._lock:
                assets_in_scope = list(self._asset_evidence.keys())

        if not assets_in_scope:
            assets_in_scope = ["application:default"]

        results: Dict[str, List[ControlAssessment]] = {}
        for aid in assets_in_scope:
            results[aid] = self.assess_asset(aid, framework_id=framework_id)

        return results

    # -------------------------------------------------------------------------
    # Factual Coverage Calculation (Section 33)
    # -------------------------------------------------------------------------

    @staticmethod
    def calculate_coverage(assessments: List[ControlAssessment]) -> Dict[str, Any]:
        """Calculate factual compliance coverage breakdown without deceptive marketing scores."""
        total = len(assessments)
        applicable = sum(1 for a in assessments if a.applicability == ApplicabilityStatus.APPLICABLE)
        not_applicable = sum(1 for a in assessments if a.applicability == ApplicabilityStatus.NOT_APPLICABLE)
        evidenced = sum(1 for a in assessments if a.status == ControlState.EVIDENCED)
        partially_evidenced = sum(1 for a in assessments if a.status == ControlState.PARTIALLY_EVIDENCED)
        implemented = sum(1 for a in assessments if a.status == ControlState.IMPLEMENTED)
        partially_implemented = sum(1 for a in assessments if a.status == ControlState.PARTIALLY_IMPLEMENTED)
        not_implemented = sum(1 for a in assessments if a.status == ControlState.NOT_IMPLEMENTED)
        failed = sum(1 for a in assessments if a.status == ControlState.FAILED)
        unknown = sum(1 for a in assessments if a.status == ControlState.UNKNOWN)
        not_assessed = sum(1 for a in assessments if a.status == ControlState.NOT_ASSESSED)

        return {
            "total_controls": total,
            "applicable_controls": applicable,
            "not_applicable_controls": not_applicable,
            "evidenced": evidenced,
            "partially_evidenced": partially_evidenced,
            "implemented": implemented,
            "partially_implemented": partially_implemented,
            "not_implemented": not_implemented,
            "failed": failed,
            "unknown": unknown,
            "not_assessed": not_assessed,
            "methodology_disclaimer": "This breakdown represents factual evidence mapping across applicable controls, NOT legal or regulatory certification.",
        }

    # -------------------------------------------------------------------------
    # Snapshots & Regression Diffing
    # -------------------------------------------------------------------------

    def snapshot(
        self,
        framework_id: Optional[str] = None,
        inventory_version: str = "1.0",
        posture_version: str = "1.0",
        graph_version: str = "1.0",
    ) -> ComplianceSnapshot:
        """Generate a tamper-evident, cryptographic snapshot of current compliance state."""
        env_assessments = self.assess_environment(framework_id=framework_id)
        flat_assessments: Dict[str, ControlAssessment] = {}
        all_gaps: List[ComplianceGap] = []
        all_evid: List[ComplianceEvidence] = []

        for aid, a_list in env_assessments.items():
            for a in a_list:
                key = f"{a.control_id}@{aid}"
                flat_assessments[key] = a
                all_gaps.extend(a.gaps)
                all_evid.extend(a.evidence)

        fw_versions = {fw.id: fw.version for fw in self.catalog.list_frameworks()}
        coverage = self.calculate_coverage(list(flat_assessments.values()))

        snap = ComplianceSnapshot.create(
            assessments=flat_assessments,
            gaps=all_gaps,
            evidence=all_evid,
            exceptions=self.list_exceptions(active_only=True),
            framework_versions=fw_versions,
            catalog_version=self.catalog.catalog_version,
            inventory_version=inventory_version,
            posture_version=posture_version,
            graph_version=graph_version,
            rules_version=self.rule_registry.rules_version,
            summary=coverage,
        )

        with self._lock:
            self._previous_snapshot = snap

        return snap

    def diff(
        self,
        previous: ComplianceSnapshot,
        current: ComplianceSnapshot,
    ) -> ComplianceDiff:
        """Compare two compliance snapshots to identify regressions, resolved gaps, and status changes."""
        regressions: List[str] = []
        status_changed: List[str] = []
        controls_added: List[str] = []
        controls_removed: List[str] = []
        fw_changed: List[str] = []
        evidence_expired: List[str] = []

        # Check framework changes
        if previous.framework_versions != current.framework_versions:
            fw_changed.append(f"Frameworks changed: previous={previous.framework_versions} vs current={current.framework_versions}")

        # Compare assessments
        prev_keys = set(previous.assessments.keys())
        curr_keys = set(current.assessments.keys())

        controls_added = sorted(list(curr_keys - prev_keys))
        controls_removed = sorted(list(prev_keys - curr_keys))

        severity_ranks = {
            ControlState.EVIDENCED: 5,
            ControlState.PARTIALLY_EVIDENCED: 4,
            ControlState.IMPLEMENTED: 3,
            ControlState.PARTIALLY_IMPLEMENTED: 2,
            ControlState.NOT_IMPLEMENTED: 1,
            ControlState.UNKNOWN: 1,
            ControlState.FAILED: 0,
            ControlState.NOT_ASSESSED: 0,
            ControlState.NOT_APPLICABLE: 5,
        }

        for k in sorted(list(prev_keys & curr_keys)):
            pa = previous.assessments[k]
            ca = current.assessments[k]

            if pa.status != ca.status:
                status_changed.append(f"{k}: {pa.status.value} -> {ca.status.value}")
                self._emit_audit("CONTROL_STATUS_CHANGED", {
                    "control_asset": k,
                    "previous_status": pa.status.value,
                    "current_status": ca.status.value,
                })

                # Regression detection (Section 49)
                if severity_ranks.get(ca.status, 0) < severity_ranks.get(pa.status, 0):
                    reg_desc = f"COMPLIANCE_REGRESSION: Control '{k}' degraded from {pa.status.value} to {ca.status.value}."
                    regressions.append(reg_desc)
                    self.metrics.inc_regressions()
                    self._emit_audit("COMPLIANCE_REGRESSION_DETECTED", {
                        "control_asset": k,
                        "previous_status": pa.status.value,
                        "current_status": ca.status.value,
                    })

        # Gaps diff
        prev_gap_ids = {g.gap_id: g for g in previous.gaps}
        curr_gap_ids = {g.gap_id: g for g in current.gaps}

        new_gaps = [g for gid, g in curr_gap_ids.items() if gid not in prev_gap_ids]
        resolved_gaps = [g for gid, g in prev_gap_ids.items() if gid not in curr_gap_ids]

        for rg in resolved_gaps:
            self._emit_audit("COMPLIANCE_GAP_RESOLVED", {
                "gap_id": rg.gap_id,
                "control_id": rg.control_id,
                "asset_id": rg.asset_id,
            })

        # Expired evidence
        prev_evid = {e.id: e for e in previous.evidence}
        curr_evid = {e.id: e for e in current.evidence}
        for eid, e in curr_evid.items():
            if e.is_expired and (eid not in prev_evid or not prev_evid[eid].is_expired):
                evidence_expired.append(f"Evidence '{eid}' for control '{e.control_id}' on asset '{e.asset_id}' expired.")

        is_identical = (
            previous.snapshot_hash == current.snapshot_hash and
            len(status_changed) == 0 and
            len(new_gaps) == 0 and
            len(resolved_gaps) == 0
        )

        return ComplianceDiff(
            is_identical=is_identical,
            control_status_changed=status_changed,
            regressions=regressions,
            new_gaps=new_gaps,
            resolved_gaps=resolved_gaps,
            evidence_expired=evidence_expired,
            controls_added=controls_added,
            controls_removed=controls_removed,
            framework_changed=fw_changed,
            summary={
                "status_changes_count": len(status_changed),
                "regressions_count": len(regressions),
                "new_gaps_count": len(new_gaps),
                "resolved_gaps_count": len(resolved_gaps),
                "expired_evidence_count": len(evidence_expired),
            },
        )

    # -------------------------------------------------------------------------
    # SARIF Export (Section 61)
    # -------------------------------------------------------------------------

    def export_sarif(self, gaps: Optional[List[ComplianceGap]] = None) -> Dict[str, Any]:
        """Export actionable compliance gaps as OASIS SARIF 2.1.0 formatted vulnerability observations."""
        target_gaps = gaps
        if target_gaps is None:
            # Collect open gaps across all assessed assets
            env = self.assess_environment()
            target_gaps = [g for a_list in env.values() for a in a_list for g in a_list]
            target_gaps = [g for a_list in env.values() for a in a_list for g in a.gaps]

        # Deduplicate gaps by gap_id
        dedup_gaps = list({g.gap_id: g for g in target_gaps}.values())

        rules_dict: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []

        for g in dedup_gaps:
            ctrl = self.catalog.get_control(g.control_id)
            rule_id = g.control_id

            if rule_id not in rules_dict:
                rules_dict[rule_id] = {
                    "id": rule_id,
                    "name": ctrl.title if ctrl else g.title,
                    "shortDescription": {"text": ctrl.title if ctrl else g.title},
                    "fullDescription": {"text": ctrl.description if ctrl else g.description},
                    "defaultConfiguration": {
                        "level": "error" if g.severity in (Severity.CRITICAL, Severity.HIGH) else "warning",
                    },
                    "properties": {
                        "framework_id": g.framework_id,
                        "category": ctrl.category if ctrl else "compliance",
                        "tags": ["ai-security", "compliance", ctrl.category if ctrl else "gap"],
                    },
                }

            result_entry = {
                "ruleId": rule_id,
                "level": "error" if g.severity in (Severity.CRITICAL, Severity.HIGH) else "warning",
                "message": {"text": f"{g.title}: {g.description}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"asset://{g.asset_id}"},
                        }
                    }
                ],
                "properties": {
                    "gap_id": g.gap_id,
                    "asset_id": g.asset_id,
                    "missing_evidence": g.missing_evidence,
                    "remediation": g.remediation_guidance,
                    "status": g.status.value,
                },
            }
            results.append(result_entry)

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "LLMFirewall Compliance Engine",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/livesh/LLMFirewall",
                            "rules": list(rules_dict.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }
