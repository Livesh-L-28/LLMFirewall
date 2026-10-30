# Policy Precedence Security Benchmark Report

- **Category:** `policy_precedence`
- **Total Evaluated Cases:** 4
- **Passed:** 4
- **Failed:** 0

## Evaluation Cases

| ID | Subcategory | Severity | Expected | Actual | Findings | Latency | Outcome |
|---|---|---|---|---|---|---|---|
| `POL-001` | block_beats_redact_injection_pii | CRITICAL | `BLOCK` | `BLOCK` | `pii,prompt_injection` | 0.31ms | **PASS** |
| `POL-002` | block_beats_redact_secret_pii | CRITICAL | `BLOCK` | `BLOCK` | `secret_leakage_in_output` | 0.12ms | **PASS** |
| `POL-003` | pure_redaction_pii | MEDIUM | `REDACT` | `REDACT` | `pii` | 0.22ms | **PASS** |
| `POL-004` | clean_pass_through | INFORMATIONAL | `ALLOW` | `ALLOW` | `none` | 0.17ms | **PASS** |
