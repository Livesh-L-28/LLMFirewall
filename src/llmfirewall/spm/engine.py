"""Core AI Security Posture Management Engine (Phase 35 — AI-SPM)."""

import hashlib
import json
import logging
from pathlib import Path
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from llmfirewall._version import __version__
from llmfirewall.audit import AuditLogger
from llmfirewall.core.models import Action, AuditEvent, Severity
from llmfirewall.graph.engine import KnowledgeGraph, NodeType, RelationshipType
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
)
from llmfirewall.spm.rules import (
    PostureRuleContext,
    PostureRuleRegistry,
    STANDARD_POSTURE_RULES,
)

logger = logging.getLogger("llmfirewall.spm")


class PostureMetrics:
    """Thread-safe bounded telemetry metrics for posture operations without unbounded asset labels."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.posture_evaluations_total = 0
        self.posture_evaluation_failures_total = 0
        self.security_gaps_total = 0
        self.posture_regressions_total = 0
        self.posture_snapshots_total = 0
        self.posture_diff_queries_total = 0

    def record_evaluation(self, gaps_found: int = 0, failed: bool = False) -> None:
        with self._lock:
            self.posture_evaluations_total += 1
            if failed:
                self.posture_evaluation_failures_total += 1
            self.security_gaps_total += gaps_found

    def record_regression(self, count: int = 1) -> None:
        with self._lock:
            self.posture_regressions_total += count

    def record_snapshot(self) -> None:
        with self._lock:
            self.posture_snapshots_total += 1

    def record_diff(self) -> None:
        with self._lock:
            self.posture_diff_queries_total += 1

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "posture_evaluations_total": self.posture_evaluations_total,
                "posture_evaluation_failures_total": self.posture_evaluation_failures_total,
                "security_gaps_total": self.security_gaps_total,
                "posture_regressions_total": self.posture_regressions_total,
                "posture_snapshots_total": self.posture_snapshots_total,
                "posture_diff_queries_total": self.posture_diff_queries_total,
            }

    def get_metrics(self) -> Dict[str, Any]:
        """Convenience alias for to_dict."""
        return self.to_dict()

    def reset(self) -> None:
        with self._lock:
            self.posture_evaluations_total = 0
            self.posture_evaluation_failures_total = 0
            self.security_gaps_total = 0
            self.posture_regressions_total = 0
            self.posture_snapshots_total = 0
            self.posture_diff_queries_total = 0


class PostureEngine:
    """Continuously calculable, evidence-based AI Security Posture Management Engine.
    
    Security & Architectural Invariants:
    1. Evidence-First Design: Every posture state (HEALTHY, ATTENTION_REQUIRED, DEGRADED, CRITICAL)
       is strictly traceable to concrete controls, findings, attack paths, and test coverage evidence.
    2. No Arbitrary Scoring: Exposes factual dimensions rather than synthetic numerical scores.
    3. Multi-Layer Pipeline Integration: Synthesizes Phase 34 (Asset Inventory), Phase 32 (Knowledge Graph),
       Phase 33 (Attack Graph), Phase 31 (Governance Findings), and Phase 30 (Security Tests).
    4. Bounded Traversal & Capacity: Enforces graph traversal depth limits and asset capacity bounds.
    5. Zero Secret Leakage: Sanitizes all auxiliary metadata and never persists raw credentials in reports.
    """

    def __init__(
        self,
        inventory: Optional[Any] = None,
        kg: Optional[KnowledgeGraph] = None,
        attack_graph: Optional[Any] = None,
        governance: Optional[Any] = None,
        rule_registry: Optional[PostureRuleRegistry] = None,
        audit_logger: Optional[AuditLogger] = None,
        metrics: Optional[PostureMetrics] = None,
        max_assets: int = 50_000,
    ) -> None:
        self.inventory = inventory
        self.kg = kg if kg is not None else (inventory.kg if inventory and hasattr(inventory, "kg") else KnowledgeGraph())
        self.attack_graph = attack_graph if attack_graph is not None else (inventory.attack_graph if inventory and hasattr(inventory, "attack_graph") else None)
        self.governance = governance
        self.rule_registry = rule_registry if rule_registry is not None else PostureRuleRegistry()
        self.audit_logger = audit_logger
        self.max_assets = max(1, min(max_assets, 1_000_000))
        self.metrics = metrics if metrics is not None else PostureMetrics()
        self._lock = threading.RLock()

        # Cache of evaluated postures and raw test results
        self._posture_cache: Dict[str, SecurityPosture] = {}
        self._test_results: List[Dict[str, Any]] = []
        self._ingested_findings: List[Dict[str, Any]] = []

    # -------------------------------------------------------------------------
    # Audit & Telemetry
    # -------------------------------------------------------------------------

    def _emit_audit(self, event_type: str, details: Dict[str, Any]) -> None:
        if not self.audit_logger:
            return
        try:
            event = AuditEvent(
                scan_id=f"POSTURE-{details.get('asset_id') or 'event'}",
                action_taken=Action.ALLOW,
                risk_score=0.0,
                max_severity=Severity.LOW,
                metadata={
                    "posture_event": event_type,
                    **details,
                },
            )
            self.audit_logger.emit(event)
        except Exception as exc:
            logger.warning("Failed to emit posture audit event %s: %s", event_type, exc)

    # -------------------------------------------------------------------------
    # Test Results & Findings Ingestion
    # -------------------------------------------------------------------------

    def ingest_test_results(
        self,
        asset_id_or_results: Union[str, List[Dict[str, Any]]],
        test_results: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        """Ingest Phase 30 security test executions to update control effectiveness and test coverage."""
        with self._lock:
            if isinstance(asset_id_or_results, str):
                aid = asset_id_or_results
                results = test_results or []
                for r in results:
                    r["asset_id"] = aid
                self._test_results.extend(results)
            else:
                self._test_results.extend(asset_id_or_results)
            # Invalidate cached postures
            self._posture_cache.clear()

    def ingest_findings(self, findings: List[Any]) -> None:
        """Ingest Phase 31 governance findings to update posture findings."""
        with self._lock:
            for f in findings:
                if hasattr(f, "to_dict"):
                    self._ingested_findings.append(f.to_dict())
                elif isinstance(f, dict):
                    self._ingested_findings.append(f)
            self._posture_cache.clear()

    # -------------------------------------------------------------------------
    # Asset Posture Evaluation
    # -------------------------------------------------------------------------

    def evaluate(self, asset_id: str) -> SecurityPosture:
        """Perform full, evidence-based security posture evaluation for an asset."""
        now = time.time()
        self._emit_audit("POSTURE_EVALUATION_STARTED", {"asset_id": asset_id, "timestamp": now})

        with self._lock:
            # 1. Fetch asset details
            asset = None
            if self.inventory:
                asset = self.inventory.get(asset_id)
            if not asset:
                # Fallback to KnowledgeGraph node
                kg_node = self.kg.get_node(asset_id)
                if kg_node:
                    from llmfirewall.inventory.models import Asset, AssetSource, AssetStatus
                    asset = Asset(
                        id=kg_node.id,
                        type=kg_node.type,
                        name=kg_node.properties.get("name") or kg_node.id,
                        environment=kg_node.properties.get("environment", "unknown"),
                        source=AssetSource.GRAPH,
                        status=AssetStatus.ACTIVE,
                        metadata=kg_node.properties,
                    )

            if not asset:
                # Unknown Asset
                posture = SecurityPosture(
                    asset_id=asset_id,
                    asset_type="unknown",
                    asset_name=asset_id,
                    environment="unknown",
                    state=PostureState.UNKNOWN,
                    state_reason=f"Asset '{asset_id}' is not indexed in Asset Inventory or Knowledge Graph.",
                    evaluated_at=now,
                    unknowns=[f"Asset '{asset_id}' presence and status are completely unrecorded."],
                    evidence=["No discovery records or graph nodes found."],
                )
                self.metrics.record_evaluation(gaps_found=0)
                return posture

            # 2. Extract Security Controls protecting this asset
            controls: Dict[str, ControlPostureRecord] = {}
            for edge in self.kg.store.get_in_edges(asset.id):
                if edge.type in (RelationshipType.PROTECTS.value, "PROTECTED_BY"):
                    src_node = self.kg.get_node(edge.source)
                    if src_node and src_node.type in (NodeType.SECURITY_CONTROL.value, "security_control"):
                        c_id = src_node.id
                        c_name = src_node.properties.get("name") or src_node.id
                        matching_tests = [
                            t for t in self._test_results
                            if t.get("target") == c_id or (bool(t.get("detector")) and str(t.get("detector")) in c_id)
                        ]
                        tested = len(matching_tests) > 0
                        last_t = max([float(t.get("timestamp", now)) for t in matching_tests]) if matching_tests else None
                        
                        # Determine effectiveness
                        eff = ControlEffectiveness.CONFIGURED
                        if tested:
                            all_passed = all(t.get("passed", False) for t in matching_tests)
                            eff = ControlEffectiveness.VALIDATED if all_passed else ControlEffectiveness.FAILED

                        freshness = TestFreshness.UNTESTED
                        if tested and last_t:
                            freshness = TestFreshness.STALE if asset.last_seen > (last_t + 1.0) else TestFreshness.FRESH

                        controls[c_id] = ControlPostureRecord(
                            control_id=c_id,
                            name=c_name,
                            presence=ControlPresence.PRESENT,
                            effectiveness=eff,
                            tested=tested,
                            last_tested=last_t,
                            test_freshness=freshness,
                            evidence=[
                                f"Control '{c_id}' declared in KnowledgeGraph protecting '{asset.id}'.",
                                f"Test execution status: {eff.value} (tested={tested}, freshness={freshness.value}).",
                            ],
                        )

            # Also check direct metadata controls on asset
            ctrl_refs = asset.metadata.get("security_controls", []) or []
            for c_ref in ctrl_refs:
                c_id = c_ref if ":" in c_ref else f"control:{c_ref}"
                if c_id not in controls:
                    controls[c_id] = ControlPostureRecord(
                        control_id=c_id,
                        name=f"Control: {c_ref}",
                        presence=ControlPresence.PRESENT,
                        effectiveness=ControlEffectiveness.CONFIGURED,
                        evidence=["Control referenced in asset configuration metadata."],
                    )

            # 3. Extract Attack Surface
            tools: List[str] = []
            apis: List[str] = []
            memory_stores: List[str] = []
            rag_sources: List[str] = []
            entry_points: List[str] = []

            for edge in self.kg.store.get_out_edges(asset.id):
                tgt = self.kg.get_node(edge.target)
                tgt_type = tgt.type if tgt else ""
                if edge.type in (RelationshipType.CAN_CALL.value, RelationshipType.USES.value, RelationshipType.CAN_ACCESS.value, "RETRIEVES_FROM", "QUERIES"):
                    if tgt_type in (NodeType.TOOL.value, "tool"):
                        tools.append(edge.target)
                    elif tgt_type in ("api", "endpoint"):
                        apis.append(edge.target)
                    elif tgt_type in (NodeType.RAG_SOURCE.value, "rag_source", "vector_store"):
                        rag_sources.append(edge.target)
                    elif "memory" in edge.target.lower() or tgt_type == "memory_store":
                        memory_stores.append(edge.target)

            for edge in self.kg.store.get_in_edges(asset.id):
                src = self.kg.get_node(edge.source)
                src_type = src.type if src else ""
                if src_type in ("api", "endpoint", "user_interface"):
                    entry_points.append(edge.source)

            # Merge with asset metadata
            tools = sorted(list(set(tools + (asset.metadata.get("tools", []) or []))))
            rag_sources = sorted(list(set(rag_sources + ([asset.metadata.get("rag_source")] if asset.metadata.get("rag_source") else []))))
            entry_points = sorted(list(set(entry_points + (asset.metadata.get("entry_points", []) or []))))

            attack_surface = AttackSurfaceRecord(
                tools_count=len(tools),
                tools=tools,
                external_apis_count=len(apis),
                external_apis=apis,
                memory_stores_count=len(memory_stores),
                memory_stores=memory_stores,
                rag_sources_count=len(rag_sources),
                rag_sources=rag_sources,
                entry_points_count=len(entry_points),
                entry_points=entry_points,
            )

            # 4. Extract Multi-Step Attack Paths from AttackGraph
            attack_paths_dict: Dict[str, List[Dict[str, Any]]] = {
                "candidate": [],
                "supported": [],
                "tested": [],
                "observed": [],
                "blocked": [],
            }
            if self.attack_graph:
                paths = self.attack_graph.find_paths(source=asset.id, max_depth=5)
                # Also include paths targeting this asset
                in_paths = self.attack_graph.find_paths(target=asset.id, max_depth=5)
                seen_pids = set()
                for p in paths + in_paths:
                    if p.path_id not in seen_pids:
                        seen_pids.add(p.path_id)
                        p_dict = p.to_dict()
                        st_key = str(p.status.value).lower()
                        if st_key in attack_paths_dict:
                            attack_paths_dict[st_key].append(p_dict)
                        else:
                            attack_paths_dict["candidate"].append(p_dict)

            # 5. Extract Findings (Phase 31)
            findings_dict: Dict[str, List[Dict[str, Any]]] = {
                "open": [],
                "resolved": [],
                "accepted": [],
                "suppressed": [],
            }
            # From ingested findings
            for f in self._ingested_findings:
                if f.get("resource") == asset.id or f.get("target") == asset.id or asset.id in f.get("related_tests", []):
                    st = str(f.get("status", "OPEN")).lower()
                    if st in ("open", "reopened"):
                        findings_dict["open"].append(f)
                    elif st in ("resolved", "mitigated"):
                        findings_dict["resolved"].append(f)
                    elif st in ("accepted", "waived"):
                        findings_dict["accepted"].append(f)
                    else:
                        findings_dict["suppressed"].append(f)

            # From KnowledgeGraph nodes
            for edge in self.kg.store.get_in_edges(asset.id):
                if edge.type in (RelationshipType.AFFECTS.value, RelationshipType.HAS_FINDING.value):
                    f_node = self.kg.get_node(edge.source)
                    if f_node and f_node.type == NodeType.FINDING.value:
                        findings_dict["open"].append({
                            "finding_id": f_node.id,
                            "severity": f_node.properties.get("severity", "MEDIUM"),
                            "category": f_node.properties.get("category", "security"),
                            "description": f_node.properties.get("description", ""),
                        })

            # 6. Test Coverage (Phase 30)
            asset_tests = [t for t in self._test_results if t.get("target") == asset.id or t.get("asset_id") == asset.id]
            passed_cnt = sum(1 for t in asset_tests if t.get("passed", False))
            failed_cnt = sum(1 for t in asset_tests if not t.get("passed", False))
            not_exec = 0
            last_tested_ts = max([float(t.get("timestamp", now)) for t in asset_tests]) if asset_tests else None
            
            # Check test staleness
            is_stale = False
            stale_reason = None
            if last_tested_ts and asset.last_seen > (last_tested_ts + 1.0):
                is_stale = True
                stale_reason = f"Asset observation timestamp ({asset.last_seen}) postdates last test run ({last_tested_ts})."

            test_coverage = TestCoverageRecord(
                total_tests=len(asset_tests),
                passed=passed_cnt,
                failed=failed_cnt,
                not_executed=not_exec,
                last_tested=last_tested_ts,
                is_stale=is_stale,
                stale_reason=stale_reason,
                test_details=asset_tests,
            )

            # 7. Policy Status & Conflicts
            policy_status: Dict[str, Any] = {
                "assigned": None,
                "version": "1.0",
                "active": True,
                "conflicts": [c.to_dict() for c in getattr(asset, "conflicts", [])],
            }
            for edge in self.kg.store.get_out_edges(asset.id):
                if edge.type == RelationshipType.GOVERNED_BY.value:
                    pol = self.kg.get_node(edge.target)
                    if pol:
                        policy_status["assigned"] = pol.id
                        policy_status["version"] = pol.properties.get("version", "1.0")

            # 8. Evaluate Posture Rules & Emitted Gaps
            rule_ctx = PostureRuleContext(
                asset=asset,
                controls=controls,
                findings=findings_dict,
                attack_paths=attack_paths_dict,
                test_coverage=test_coverage,
                attack_surface=attack_surface,
                configuration=asset.metadata,
                policy_status=policy_status,
                drift={
                    "test_stale": is_stale,
                    "asset_conflicts": len(policy_status["conflicts"]),
                },
                kg=self.kg,
            )
            gaps = self.rule_registry.evaluate(rule_ctx)

            # 9. Synthesize Posture State (Evidence-Based Methodology)
            state = PostureState.HEALTHY
            state_reasons: List[str] = []

            # CRITICAL Criteria:
            has_crit_finding = any(str(f.get("severity", "")).lower() == "critical" for f in findings_dict["open"])
            has_crit_path = any(
                p.get("status") in ("SUPPORTED", "TESTED") and p.get("mitigation_status") == "UNMITIGATED"
                for p in attack_paths_dict.get("supported", []) + attack_paths_dict.get("tested", [])
            )
            if has_crit_finding:
                state = PostureState.CRITICAL
                state_reasons.append("Open CRITICAL severity governance finding affecting asset.")
            elif has_crit_path:
                state = PostureState.CRITICAL
                state_reasons.append("Unmitigated supported attack path directly reaches sensitive asset/tool.")

            # DEGRADED Criteria:
            if state != PostureState.CRITICAL:
                has_failed_control = any(c.effectiveness == ControlEffectiveness.FAILED for c in controls.values())
                has_failed_test = test_coverage.failed > 0
                has_high_finding = any(str(f.get("severity", "")).lower() == "high" for f in findings_dict["open"])

                if has_failed_control:
                    state = PostureState.DEGRADED
                    state_reasons.append("Security control empirical validation failed.")
                elif has_failed_test:
                    state = PostureState.DEGRADED
                    state_reasons.append(f"{test_coverage.failed} security test(s) failed against asset.")
                elif has_high_finding:
                    state = PostureState.DEGRADED
                    state_reasons.append("Open HIGH severity governance finding affecting asset.")

            # ATTENTION_REQUIRED Criteria:
            if state not in (PostureState.CRITICAL, PostureState.DEGRADED):
                high_gaps = [g for g in gaps if g.severity in (Severity.HIGH, Severity.MEDIUM)]
                if high_gaps:
                    state = PostureState.ATTENTION_REQUIRED
                    state_reasons.append(f"{len(high_gaps)} security gap(s) identified requiring verification.")
                elif is_stale:
                    state = PostureState.ATTENTION_REQUIRED
                    state_reasons.append("Security test verification is STALE due to architectural modifications.")
                elif policy_status["conflicts"]:
                    state = PostureState.ATTENTION_REQUIRED
                    state_reasons.append("Configuration/policy conflicts detected across discovery sources.")
                elif not controls and getattr(asset, "type", "") in ("agent", "application"):
                    state = PostureState.ATTENTION_REQUIRED
                    state_reasons.append("No active defensive security controls detected protecting asset.")

            # UNKNOWN Criteria:
            if not controls and not asset_tests and not findings_dict["open"] and getattr(asset, "source", "") == "GRAPH":
                state = PostureState.UNKNOWN
                state_reasons = ["Zero empirical test results, controls, or findings available to assess posture."]

            if not state_reasons and state == PostureState.HEALTHY:
                state_reasons.append("Security controls verified present and active; tests passing; zero open high-severity gaps.")

            # 10. Record Unknown Areas
            unknowns: List[str] = []
            if not controls:
                unknowns.append("Defensive controls presence is UNKNOWN.")
            if test_coverage.total_tests == 0:
                unknowns.append("Security test coverage is UNTESTED.")
            if attack_surface.entry_points and not any("firewall" in c for c in controls):
                unknowns.append("External entry point firewall posture is UNKNOWN.")
            for c in controls.values():
                if c.presence == ControlPresence.UNKNOWN:
                    unknowns.append(f"Control '{c.control_id}' presence is UNKNOWN.")

            # Consolidated Evidence
            evidence: List[str] = [
                f"Posture evaluated as {state.value} at {now}.",
                f"Justification: {'; '.join(state_reasons)}",
                f"Controls indexed: {len(controls)} ({sum(1 for c in controls.values() if c.presence == ControlPresence.PRESENT)} present).",
                f"Security tests: {test_coverage.passed}/{test_coverage.total_tests} passed ({test_coverage.failed} failed).",
                f"Candidate/supported attack paths: {len(attack_paths_dict.get('candidate', [])) + len(attack_paths_dict.get('supported', []))}.",
                f"Open governance findings: {len(findings_dict['open'])}.",
            ]

            posture = SecurityPosture(
                asset_id=asset.id,
                asset_type=asset.type,
                asset_name=asset.name,
                environment=asset.environment,
                state=state,
                state_reason="; ".join(state_reasons),
                evaluated_at=now,
                controls=controls,
                findings=findings_dict,
                attack_paths=attack_paths_dict,
                test_coverage=test_coverage,
                attack_surface=attack_surface,
                configuration=asset.metadata,
                policy_status=policy_status,
                drift={
                    "is_test_stale": is_stale,
                    "conflicts": policy_status["conflicts"],
                },
                dimensions={
                    PostureDimension.ASSET_SECURITY.value: {"state": state.value},
                    PostureDimension.TOOL_SECURITY.value: {"tools_count": len(tools)},
                    PostureDimension.TESTING.value: {"pass_ratio": test_coverage.pass_ratio},
                    PostureDimension.GOVERNANCE.value: {"open_findings": len(findings_dict["open"])},
                },
                security_gaps=gaps,
                unknowns=unknowns,
                evidence=evidence,
            )

            self._posture_cache[asset.id] = posture
            self.metrics.record_evaluation(gaps_found=len(gaps))
            self._emit_audit("POSTURE_EVALUATION_COMPLETED", {
                "asset_id": asset.id,
                "state": state.value,
                "gaps_count": len(gaps),
            })
            return posture

    def evaluate_all(self) -> Dict[str, SecurityPosture]:
        """Evaluate security posture across all assets in the active inventory and environment."""
        postures: Dict[str, SecurityPosture] = {}
        assets = []
        if self.inventory:
            assets = self.inventory.list_assets()
        else:
            assets = self.kg.find_nodes()

        for a in assets[: self.max_assets]:
            aid = a.id
            postures[aid] = self.evaluate(aid)

        return postures

    def incremental_evaluate(self, changed_asset_ids: List[str]) -> Dict[str, SecurityPosture]:
        """Dependency-aware evaluation: reevaluates changed assets and their downstream graph dependents."""
        impacted_ids: Set[str] = set()

        for cid in changed_asset_ids:
            impacted_ids.add(cid)
            # Find downstream dependents in KnowledgeGraph
            # E.g. If tool changes -> agent using tool -> app using agent
            for edge in self.kg.store.get_in_edges(cid):
                if edge.type in (RelationshipType.CAN_CALL.value, RelationshipType.USES.value, RelationshipType.DEPENDS_ON.value):
                    impacted_ids.add(edge.source)

        evaluated: Dict[str, SecurityPosture] = {}
        for aid in impacted_ids:
            evaluated[aid] = self.evaluate(aid)

        return evaluated

    # -------------------------------------------------------------------------
    # Environment Posture Summary
    # -------------------------------------------------------------------------

    def summary(self) -> Dict[str, Any]:
        """Calculate evidence-based aggregated posture summary across the environment."""
        postures = self.evaluate_all()
        total_assets = len(postures)

        # State counts
        state_counts = {s.value: 0 for s in PostureState}
        for p in postures.values():
            state_counts[p.state.value] += 1

        # Controls counts
        controls_presence = {"PRESENT": 0, "PARTIALLY_PRESENT": 0, "ABSENT": 0, "UNKNOWN": 0}
        seen_controls = set()
        for p in postures.values():
            for cid, c in p.controls.items():
                if cid not in seen_controls:
                    seen_controls.add(cid)
                    controls_presence[c.presence.value] = controls_presence.get(c.presence.value, 0) + 1

        # Findings
        open_findings_cnt = sum(len(p.findings.get("open", [])) for p in postures.values())

        # Attack Paths
        candidate_paths = sum(len(p.attack_paths.get("candidate", [])) for p in postures.values())
        supported_paths = sum(len(p.attack_paths.get("supported", [])) for p in postures.values())
        tested_paths = sum(len(p.attack_paths.get("tested", [])) for p in postures.values())
        observed_paths = sum(len(p.attack_paths.get("observed", [])) for p in postures.values())

        # Tests
        passed_tests = sum(p.test_coverage.passed for p in postures.values())
        failed_tests = sum(p.test_coverage.failed for p in postures.values())
        not_executed_tests = sum(p.test_coverage.not_executed for p in postures.values())

        # Security Gaps
        all_gaps = [g for p in postures.values() for g in p.security_gaps]
        unique_gaps = {g.gap_id: g for g in all_gaps}.values()
        gaps_by_severity = {
            "CRITICAL": sum(1 for g in unique_gaps if g.severity == Severity.CRITICAL),
            "HIGH": sum(1 for g in unique_gaps if g.severity == Severity.HIGH),
            "MEDIUM": sum(1 for g in unique_gaps if g.severity == Severity.MEDIUM),
            "LOW": sum(1 for g in unique_gaps if g.severity == Severity.LOW),
        }

        # Unknowns
        total_unknowns = sum(len(p.unknowns) for p in postures.values())

        return {
            "assets_count": total_assets,
            "posture_states": state_counts,
            "controls": controls_presence,
            "findings": {
                "open": open_findings_cnt,
            },
            "attack_paths": {
                "candidate": candidate_paths,
                "supported": supported_paths,
                "tested": tested_paths,
                "observed": observed_paths,
            },
            "security_tests": {
                "passed": passed_tests,
                "failed": failed_tests,
                "not_executed": not_executed_tests,
            },
            "security_gaps": {
                "total": len(unique_gaps),
                "by_severity": gaps_by_severity,
            },
            "unknown_areas_count": total_unknowns,
        }

    # -------------------------------------------------------------------------
    # Snapshots & Baseline Comparison (Diff)
    # -------------------------------------------------------------------------

    def snapshot(self, posture_version: str = "1.0") -> PostureSnapshot:
        """Capture a tamper-evident, canonical posture baseline snapshot."""
        with self._lock:
            postures = self.evaluate_all()
            all_gaps = [g for p in postures.values() for g in p.security_gaps]
            unique_gaps = list({g.gap_id: g for g in all_gaps}.values())
            sum_data = self.summary()

            snap = PostureSnapshot.create(
                postures=postures,
                gaps=unique_gaps,
                posture_version=posture_version,
                rules_version=self.rule_registry.rules_version,
                summary=sum_data,
            )
            self.metrics.record_snapshot()
            self._emit_audit("POSTURE_SNAPSHOT_CREATED", {
                "snapshot_hash": snap.snapshot_hash,
                "assets_count": len(postures),
            })
            return snap

    @staticmethod
    def diff(previous: PostureSnapshot, current: PostureSnapshot) -> PostureDiff:
        """Compare two posture snapshots to detect regressions, improvements, and gap deltas."""
        prev_p = previous.postures
        curr_p = current.postures

        posture_improved: List[str] = []
        posture_degraded: List[str] = []
        controls_added: List[str] = []
        controls_removed: List[str] = []
        tests_became_stale: List[str] = []
        regressions: List[str] = []
        attack_surface_changed: List[str] = []
        policy_conflicts: List[str] = []

        # Ranking helper
        state_ranks = {
            PostureState.HEALTHY: 4,
            PostureState.ATTENTION_REQUIRED: 3,
            PostureState.UNKNOWN: 2,
            PostureState.DEGRADED: 1,
            PostureState.CRITICAL: 0,
        }

        common_ids = set(prev_p.keys()).intersection(curr_p.keys())

        for aid in common_ids:
            p_prev = prev_p[aid]
            p_curr = curr_p[aid]

            rank_prev = state_ranks.get(p_prev.state, 2)
            rank_curr = state_ranks.get(p_curr.state, 2)

            if rank_curr > rank_prev:
                posture_improved.append(f"{aid} ({p_prev.state.value} -> {p_curr.state.value})")
            elif rank_curr < rank_prev:
                posture_degraded.append(f"{aid} ({p_prev.state.value} -> {p_curr.state.value})")
                regressions.append(f"Asset '{aid}' posture degraded from {p_prev.state.value} to {p_curr.state.value}.")

            # Controls delta
            prev_ctrls = set(p_prev.controls.keys())
            curr_ctrls = set(p_curr.controls.keys())
            for c in curr_ctrls - prev_ctrls:
                controls_added.append(f"{aid}:{c}")
            for c in prev_ctrls - curr_ctrls:
                controls_removed.append(f"{aid}:{c}")
                regressions.append(f"Control '{c}' removed from asset '{aid}'.")

            # Check if previous control was validated and now unknown
            for c_id in prev_ctrls.intersection(curr_ctrls):
                c_before = p_prev.controls[c_id]
                c_after = p_curr.controls[c_id]
                if c_before.effectiveness == ControlEffectiveness.VALIDATED and c_after.effectiveness in (ControlEffectiveness.UNKNOWN, ControlEffectiveness.FAILED):
                    regressions.append(f"Control '{c_id}' effectiveness regressed from VALIDATED to {c_after.effectiveness.value}.")

            # Stale test delta
            if not p_prev.test_coverage.is_stale and p_curr.test_coverage.is_stale:
                tests_became_stale.append(f"{aid}: {p_curr.test_coverage.stale_reason or 'Modified after testing'}")
                regressions.append(f"Security test coverage for asset '{aid}' became STALE.")

            # Attack surface delta
            if p_curr.attack_surface.tools_count > p_prev.attack_surface.tools_count:
                new_tools = set(p_curr.attack_surface.tools) - set(p_prev.attack_surface.tools)
                attack_surface_changed.append(f"{aid} gained access to new tool(s): {', '.join(new_tools)}")

            # Policy conflicts
            if len(p_curr.policy_status.get("conflicts", [])) > len(p_prev.policy_status.get("conflicts", [])):
                policy_conflicts.append(f"{aid} has new policy conflicts.")
                regressions.append(f"New policy conflicts detected governing '{aid}'.")

        # Security gaps delta
        prev_gaps_map = {g.gap_id: g for g in previous.gaps}
        curr_gaps_map = {g.gap_id: g for g in current.gaps}

        new_gaps = [g for gid, g in curr_gaps_map.items() if gid not in prev_gaps_map]
        resolved_gaps = [g for gid, g in prev_gaps_map.items() if gid not in curr_gaps_map]

        if new_gaps:
            for ng in new_gaps:
                if ng.severity in (Severity.CRITICAL, Severity.HIGH):
                    regressions.append(f"New {ng.severity.value} security gap: {ng.title} ({ng.asset_id}).")

        is_identical = (previous.snapshot_hash == current.snapshot_hash) or not (
            posture_improved or posture_degraded or controls_added or controls_removed
            or tests_became_stale or new_gaps or resolved_gaps or attack_surface_changed or regressions
        )

        return PostureDiff(
            is_identical=is_identical,
            posture_improved=posture_improved,
            posture_degraded=posture_degraded,
            controls_added=controls_added,
            controls_removed=controls_removed,
            tests_became_stale=tests_became_stale,
            new_security_gaps=new_gaps,
            gaps_resolved=resolved_gaps,
            attack_surface_changed=attack_surface_changed,
            policy_conflicts_detected=policy_conflicts,
            regressions=regressions,
            summary={
                "is_identical": is_identical,
                "regressions_count": len(regressions),
                "new_gaps_count": len(new_gaps),
                "resolved_gaps_count": len(resolved_gaps),
                "improved_count": len(posture_improved),
                "degraded_count": len(posture_degraded),
            },
        )

    # -------------------------------------------------------------------------
    # SARIF 2.1.0 Export
    # -------------------------------------------------------------------------

    def export_sarif(self, gaps: Optional[List[SecurityGap]] = None) -> Dict[str, Any]:
        """Export actionable security gaps in OASIS SARIF 2.1.0 format."""
        if gaps is None:
            sum_data = self.summary()
            all_postures = self.evaluate_all()
            all_gaps = [g for p in all_postures.values() for g in p.security_gaps]
            gaps = list({g.gap_id: g for g in all_gaps}.values())

        sarif_results = []
        rules = []
        seen_rules = set()

        for g in gaps:
            sev_str = g.severity.value.lower()
            level = "error" if sev_str in ("critical", "high") else ("warning" if sev_str == "medium" else "note")
            rule_id = f"LLMFIREWALL-SPM-{g.dimension.upper()}"

            if rule_id not in seen_rules:
                seen_rules.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": f"SecurityGap_{g.dimension}",
                    "shortDescription": {"text": g.title},
                    "defaultConfiguration": {"level": level},
                })

            sarif_results.append({
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": f"[{g.severity.value}] {g.title} ({g.asset_id}): {g.description} Guidance: {g.remediation_guidance}",
                },
                "properties": {
                    "gap_id": g.gap_id,
                    "asset_id": g.asset_id,
                    "dimension": g.dimension,
                    "severity": g.severity.value,
                    "evidence": g.evidence,
                    "status": g.status.value,
                    "related_control": g.related_control,
                    "related_attack_path": g.related_attack_path,
                },
            })

        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "LLMFirewall AI-SPM",
                            "version": __version__,
                            "informationUri": "https://github.com/livesh/LLMFirewall",
                            "rules": rules,
                        }
                    },
                    "results": sarif_results,
                }
            ],
        }
