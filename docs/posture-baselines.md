# Posture Baselines, Snapshots & Regression Detection

## 1. Overview

AI-SPM enables teams to establish reproducible security posture baselines, track posture evolution over time, and immediately detect **security regressions** between releases.

```text
Baseline Snapshot (v1.0)
          │
          ├── Tool Authorization = VALIDATED
          └── Prompt Injection Defense = VALIDATED
                    │
           [ Architectural Change ]
                    │
Current Snapshot (v2.0)
          │
          ├── Tool Authorization = UNKNOWN
          └── Prompt Injection Defense = VALIDATED
                    │
                    ↓
         POSTURE_REGRESSION DETECTED
```

---

## 2. Posture Snapshots

A [PostureSnapshot](file:///Users/livesh/LLMFirewall/src/llmfirewall/spm/models.py) captures an immutable, tamper-evident record of the entire security posture:

```python
snapshot = engine.snapshot(posture_version="1.0")
```

The snapshot computes a canonical SHA-256 digest (`snapshot_hash`) across sorted asset fingerprints, gap IDs, schema versions, and rule versions:

```json
{
  "schema_version": "1.0.0",
  "posture_version": "1.0",
  "inventory_version": "1.0",
  "graph_version": "1.0",
  "rules_version": "1.0.0",
  "created_at": 1790600833.018,
  "snapshot_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "summary": {},
  "postures": {},
  "gaps": []
}
```

---

## 3. Posture Diff & Drift Detection

Comparing two snapshots detects regressions, improvements, and architectural drift:

```python
diff = PostureEngine.diff(snap_before, snap_after)
```

The [PostureDiff](file:///Users/livesh/LLMFirewall/src/llmfirewall/spm/models.py) reports:
* `is_identical`: Boolean indicating whether posture changed.
* `posture_improved`: Assets whose posture state upgraded (e.g. `ATTENTION_REQUIRED` -> `HEALTHY`).
* `posture_degraded`: Assets whose posture state degraded (e.g. `HEALTHY` -> `DEGRADED`).
* `controls_added`: Defensive controls added to assets.
* `controls_removed`: Defensive controls decommissioned.
* `tests_became_stale`: Tests whose verification became stale due to asset modifications.
* `new_security_gaps`: Newly identified security gaps.
* `gaps_resolved`: Previously open gaps verified resolved.
* `attack_surface_changed`: Assets gaining access to new tools, external APIs, or memory buffers.
* `policy_conflicts_detected`: Newly introduced contradictory policy rules.
* `regressions`: Explicit evidentiary statements describing security regressions.

---

## 4. CLI Usage

```bash
# Capture baseline before release
llmfirewall posture snapshot --output baseline-v1.json

# Capture snapshot after staging deployment
llmfirewall posture snapshot --output release-v2.json

# Detect regressions
llmfirewall posture diff --before baseline-v1.json --after release-v2.json
```

Example CLI Output:

```text
AI Security Posture Diff
========================
Identical Baseline: NO

Security Regressions Detected:
  ✖ Asset 'agent:support' posture degraded from HEALTHY to ATTENTION_REQUIRED.
  ✖ Control 'control:tool_authorization' removed from asset 'agent:support'.

Controls Removed:
  - agent:support:control:tool_authorization

New Security Gaps:
  ! [HIGH] Tool Authorization Not Configured or Verified (agent:support)

Attack Surface Changes:
  * agent:support gained access to new tool(s): tool:database_delete
```
