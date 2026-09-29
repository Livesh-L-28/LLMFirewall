# Posture Engine

## 1. Responsibilities

The [PostureEngine](file:///Users/livesh/LLMFirewall/src/llmfirewall/spm/engine.py) orchestrates evidence collection, control verification, security test aggregation, gap identification, baseline snapshotting, and regression analysis.

```text
PostureEngine
├── evaluate(asset_id)
├── evaluate_all()
├── incremental_evaluate(changed_asset_ids)
├── summary()
├── snapshot(posture_version)
├── diff(previous, current)
└── export_sarif(gaps)
```

---

## 2. Evidence-Based Evaluation

When evaluating an asset (`posture.evaluate(asset_id)`), the engine performs an 8-step evaluation pipeline:

1. **Asset Identity & Metadata Retrieval**:
   Retrieves asset record from Phase 34 [AssetInventory](file:///Users/livesh/LLMFirewall/src/llmfirewall/inventory/engine.py) or Phase 32 [KnowledgeGraph](file:///Users/livesh/LLMFirewall/src/llmfirewall/graph/engine.py). If absent, gracefully emits `PostureState.UNKNOWN`.
2. **Defensive Control Mapping**:
   Queries incoming `PROTECTS` or `PROTECTED_BY` edges in the KnowledgeGraph to discover protecting security controls (e.g., prompt injection detectors, PII scrubbers, tool authorization gates).
3. **Attack Surface Synthesis**:
   Traverses outgoing graph relationships (`CAN_CALL`, `USES`, `CAN_ACCESS`) to catalog accessible tools, external APIs, persistent memory stores, RAG document sources, and entry points.
4. **Security Test Coverage Integration**:
   Aggregates empirical security tests executed against this asset or its protecting controls. Determines test status (`passed`, `failed`, `not_executed`) and evaluates freshness:
   $$\text{TestFreshness} = \begin{cases} \text{STALE} & \text{if } \text{asset.last\_seen} > (\text{test.timestamp} + 1.0) \\ \text{FRESH} & \text{otherwise} \end{cases}$$
5. **Attack Path Exposure Analysis**:
   Integrates Phase 33 [AttackGraph](file:///Users/livesh/LLMFirewall/src/llmfirewall/attack_graph/engine.py) to identify candidate, supported, tested, observed, and blocked attack paths without treating candidate paths as confirmed exploits.
6. **Governance & Policy Status**:
   Extracts assigned policies, active versions, and inspects for conflicting policies.
7. **Declarative Rule Execution**:
   Executes all registered rules in the [PostureRuleRegistry](file:///Users/livesh/LLMFirewall/src/llmfirewall/spm/rules.py) against the asset context to produce structured [SecurityGap](file:///Users/livesh/LLMFirewall/src/llmfirewall/spm/models.py) objects.
8. **State Synthesis & Deterministic Fingerprint**:
   Determines the overall posture state (`HEALTHY`, `ATTENTION_REQUIRED`, `DEGRADED`, `CRITICAL`, `UNKNOWN`) and computes a canonical SHA-256 fingerprint for change tracking.

---

## 3. Incremental Evaluation

Re-evaluating thousands of assets on minor changes causes unnecessary computational overhead. The Posture Engine uses the Knowledge Graph's dependency topology to re-evaluate only modified assets and their direct downstream dependents:

```python
# Invalidate a modified tool
reevaluated = engine.incremental_evaluate(["tool:database"])
# Downstream agents that call tool:database are automatically reevaluated
```

### Benchmark Scaling:
* At 1,000 assets: **0.158 ms**
* At 10,000 assets: **0.158 ms**
* At 50,000 assets: **0.189 ms**

---

## 4. Aggregated Environment Summary

```python
summary = engine.summary()
```

Returns factual environment metrics:
* `assets_count`: Total indexed assets.
* `posture_states`: State distribution (`HEALTHY`, `ATTENTION_REQUIRED`, `DEGRADED`, `CRITICAL`, `UNKNOWN`).
* `controls`: Distinct control presence (`PRESENT`, `PARTIALLY_PRESENT`, `UNKNOWN`, `ABSENT`).
* `findings`: Open governance findings.
* `attack_paths`: Candidate, supported, tested, observed path counts.
* `security_tests`: Passed, failed, not executed test counts.
* `security_gaps`: Total gaps and counts partitioned by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
* `unknown_areas_count`: Count of unobserved or untested properties.

---

## 5. Audit Logging & Bounded Telemetry

Every posture evaluation, regression, and snapshot creation emits an immutable audit event:
* `POSTURE_EVALUATION_STARTED`
* `POSTURE_EVALUATION_COMPLETED`
* `POSTURE_SNAPSHOT_CREATED`
* `POSTURE_REGRESSION_DETECTED`
* `SECURITY_GAP_CREATED`

Telemetry counters adhere to strict bounded cardinality (no unbounded asset IDs as metric tags):
* `posture_evaluations_total`
* `posture_evaluation_failures_total`
* `security_gaps_total`
* `posture_regressions_total`
* `posture_snapshots_total`
* `posture_diff_queries_total`
