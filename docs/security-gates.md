# Security Gates Specification & Configuration

## 1. Security Gate Architecture

A `SecurityGate` is an atomic evaluative check that enforces one security control over evidence records.

Supported `GateType` values:
- `test`: Verifies security test suite results, minimum pass rates, and required test cases.
- `policy`: Validates policy versions and detects unexplained policy drift.
- `model`: Verifies cryptographic hash, provider, and integrity of model artifacts.
- `dependency`: Enforces dependency supply-chain integrity.
- `configuration`: Validates firewall configuration hashes.
- `drift`: Analyzes snapshot drift and regressions against past runs.
- `provenance`: Enforces document provenance and trust boundaries for RAG.
- `agent`: Detects capability expansion and unauthorized agent operations.
- `custom`: Supports organization-specific declarative checks.

---

## 2. Declarative Gate Configuration

```yaml
gates:
  - id: core-security
    type: test
    name: Core LLM Security Tests
    required: true
    minimum_pass_rate: 0.95
    required_tests:
      - PI-001
      - TOOL-001
    block_on:
      - critical
    max_allowed_severity: high

  - id: model-integrity
    type: model
    name: Model Weights & Provenance
    required: true
    block_on:
      - critical
      - high
```

---

## 3. Evaluation Semantics

- **Required Tests**: If any test ID in `required_tests` did not run, the gate fails with `MISSING_REQUIRED_TEST`.
- **Pass Rate**: If the suite pass rate falls below `minimum_pass_rate`, the gate fails with `PASS_RATE_BELOW_THRESHOLD`.
- **Severity Enforcement**: Findings with severities listed in `block_on` produce `BLOCK`. Findings above `max_allowed_severity` produce `FAIL`. Findings listed in `review_on` produce `REVIEW`.

---

## 4. CLI Execution

```bash
llmfirewall gate --policy governance.yaml --ci
```

Exit Codes:
- `0`: Release permitted (decision is `PASS` or authorized override applied).
- `1`: Release prohibited (decision is `FAIL`, `BLOCK`, or non-overridden `REVIEW` in CI).
- `2`: CLI usage or input error.
- `3`: System or runtime error.
