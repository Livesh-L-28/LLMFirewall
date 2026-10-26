# Malformed Oversized Security Benchmark Report

- **Category:** `malformed_oversized`
- **Total Evaluated Cases:** 5
- **Passed:** 5
- **Failed:** 0

## Evaluation Cases

| ID | Subcategory | Severity | Expected | Actual | Findings | Latency | Outcome |
|---|---|---|---|---|---|---|---|
| `MAL-001` | empty_payload | INFORMATIONAL | `ALLOW` | `ALLOW` | `none` | 0.10ms | **PASS** |
| `MAL-002` | whitespace_padding | INFORMATIONAL | `ALLOW` | `ALLOW` | `none` | 0.05ms | **PASS** |
| `MAL-003` | control_characters_null | LOW | `ALLOW` | `ALLOW` | `none` | 0.15ms | **PASS** |
| `MAL-004` | large_payload_benign | INFORMATIONAL | `ALLOW` | `ALLOW` | `none` | 0.25ms | **PASS** |
| `MAL-005` | large_payload_trailing_injection | CRITICAL | `BLOCK` | `BLOCK` | `prompt_injection` | 0.34ms | **PASS** |
