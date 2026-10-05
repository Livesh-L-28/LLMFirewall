# Detection Engine Architecture & Extension Guide (Phase 44)

## 1. Overview & Detection Lifecycle

LLMFirewall Core v1.1.0 introduces a modular, staged detection pipeline designed for microsecond-scale execution, deterministic evaluation, and flexible extensibility.

The end-to-end detection lifecycle is strictly decoupled: **Detectors detect**, **Risk engines score**, and **Policy engines decide**.

```
Input Text
   │
   ▼
[Stage 1: Normalization & Token Heuristics]
   │  • NFKC canonicalization & control/zero-width character stripping
   │  • Lightweight structural token signals (roles, delimiters, encodings)
   ▼
[Stage 2: Execution Planning & Pre-Filter Index]
   │  • Candidate selection via direction and trigger hints
   │  • Deterministic ordering by cost class (CHEAP → NORMAL → EXPENSIVE)
   ▼
[Stage 3: Staged Detector Execution & Failure Isolation]
   │  • Isolated detector invocation
   │  • Fail-safe error capture into FindingCollection.errors (or fail_fast)
   ▼
[Stage 4: Confidence Calibration]
   │  • Bounded deterministic confidence validation (0.0 <= conf <= 1.0)
   ▼
[Stage 5: Finding Aggregation & Deduplication]
   │  • Deterministic SHA-256 fingerprinting
   │  • Span overlap normalization
   ▼
FindingCollection
   │
   ▼
Risk Engine → Policy Engine → Enforcement Decision
```

---

## 2. Detector Contracts: Classical Inheritance & Structural Typing

LLMFirewall supports two complementary ways to define custom detectors:

### 2.1 Classical Inheritance (`Detector`)
Inherits from `llmfirewall.detectors.base.Detector` (which inherits from `BaseDetector`):
```python
from llmfirewall import Detector, DetectorMetadata, Finding, ThreatType, Severity

class MyDetector(Detector):
    @property
    def metadata(self) -> DetectorMetadata:
        return DetectorMetadata(
            name="my_detector",
            description="Custom detector via classical inheritance",
            supported_threats=[ThreatType.CUSTOM],
            cost="cheap",
            trigger_hints=["custom_token"],
        )

    def detect(self, text: str, context=None):
        if "custom_token" in text.lower():
            return [
                Finding(
                    detector_name=self.name,
                    threat_type=ThreatType.CUSTOM,
                    description="Matched custom_token",
                    severity=Severity.HIGH,
                )
            ]
        return []
```

### 2.2 Structural Typing (`DetectorProtocol`)
Allows third-party libraries and users to define detectors without subclassing any framework class:
```python
from typing import Any, Dict, List, Optional
from llmfirewall import DetectorMetadata, DetectorProtocol, Finding, ThreatType, Severity

class VendorDetector:
    """Satisfies DetectorProtocol without framework inheritance."""
    @property
    def name(self) -> str:
        return "vendor_detector"

    @property
    def metadata(self) -> DetectorMetadata:
        return DetectorMetadata(
            name=self.name,
            description="Vendor detector",
            supported_threats=[ThreatType.CUSTOM],
        )

    def detect(self, text: str, context: Optional[Dict[str, Any]] = None) -> List[Finding]:
        # Implementation...
        return []

# Runtime check
assert isinstance(VendorDetector(), DetectorProtocol)
```

---

## 3. Metadata, Cost Model, and Pre-Filtering

Every detector declares a `DetectorMetadata` record. In v1.1.0, two optional fields facilitate intelligent candidate scheduling:
- `cost`: Declares estimated computation cost (`DetectorCost.CHEAP`, `NORMAL`, `EXPENSIVE`). Cheaper detectors run earlier in the pipeline.
- `trigger_hints`: List of substring hints. When hints are declared, `DetectorPreFilter` schedules the detector only if at least one hint is present in the normalized input. Detectors without hints are **always** scheduled.

> **Critical Rule**: The pre-filter NEVER produces final security decisions. It only optimizes execution order and skips provably irrelevant detectors when explicit trigger hints are not matched.

---

## 4. Token Heuristics

Lightweight token heuristics (`TokenHeuristics`) extract deterministic structural signals prior to detector execution:
- `char_count` and `token_count_approx`
- `non_ascii_ratio` and `control_char_count`
- `delimiter_density` (density of `<>{}[|]``\#@`)
- Structural flags: `has_role_markers`, `has_instruction_markers`, `has_code_blocks`, `has_hex_or_base64_tokens`
- `suspicious_token_count`: Composite structural signal passed to detectors via `context["heuristics"]`.

---

## 5. Finding Identity, Aggregation, and Deduplication

1. **Deterministic Fingerprinting**: Each finding is assigned a reproducible fingerprint derived from detector name, threat type, category/rule ID, character offsets, and description.
2. **Exact Duplicate Elimination**: Identical findings emitted by multiple passes or rules are collapsed into a single canonical finding.
3. **Span Overlap Normalization**: If two findings from the same detector span identical text regions, the finding with higher severity or confidence is preserved.
4. **Confidence Calibration**: Findings are verified to ensure confidence is bounded within `[0.0, 1.0]`, with boundary checks on span offsets.

---

## 6. Failure Isolation and Security Boundaries

- By default (`fail_fast=False`), unhandled exceptions raised by any detector are caught, logged, and isolated into `FindingCollection.errors`. Execution of remaining detectors proceeds without interruption.
- When `fail_fast=True`, detector exceptions immediately halt execution by raising `LLMFirewallError`.
- Raw sensitive text is protected: `matched_text` is omitted or redacted according to privacy settings, avoiding sensitive credential leakage in downstream logs or exceptions.

---

## 7. Configuration Reference

```yaml
detectors:
  fail_fast: false          # Halt on first detector error if true
  enable_prefilter: true    # Enable candidate pre-filtering based on trigger hints
  enable_heuristics: true   # Compute token heuristics and context enrichment
  prompt_injection:
    enabled: true
  pii:
    enabled: true
  secrets:
    enabled: true
```
