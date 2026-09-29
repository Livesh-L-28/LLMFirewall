# Security Baselines & Integrity Verification

## 1. What is a Security Baseline?

A `SecurityBaseline` is an immutable, cryptographically anchored snapshot of verified security state at a known point in time. It records:
- Baseline ID & version
- Creation timestamp & creator
- Test suite configuration & parameters
- Policy version & hash
- Model identity & weights hash
- Dependency inventory hash
- Firewall configuration hash
- List of verified findings & active waivers
- SHA-256 integrity digest

---

## 2. Cryptographic Tamper Resistance

Baselines never trust mutable file system attributes or filenames. Every `SecurityBaseline` contains an `integrity_hash` computed across canonical JSON representations of its parameters.

When loaded, `baseline.verify_integrity()` recalculates the canonical digest:
- If any finding, configuration hash, or model identity was tampered with, `verify_integrity()` returns `False`.
- The Governance Engine immediately blocks release with reason code `TAMPERING_DETECTED`.

---

## 3. Baseline Comparison & Drift Categories

When comparing a current evaluation with a baseline (`baseline.compare_findings(current)`), outcomes are categorized as:
- `NEW`: Finding observed now that was not in the baseline (triggers regression warning/block).
- `RESOLVED`: Finding present in baseline that is now eliminated.
- `UNCHANGED`: Finding active in both baseline and current evaluation.
- `CHANGED`: Finding whose severity was modified (e.g. escalated from MEDIUM to HIGH).
- `MISSING`: Expected baseline findings that are missing from report.

---

## 4. CLI Commands

### Create a Baseline
```bash
llmfirewall baseline create --output baseline.json --id BASE-2026.09 --results security-results.json
```

### Compare Against Baseline
```bash
llmfirewall baseline compare --current security-results.json --baseline baseline.json
```
