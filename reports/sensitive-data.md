# Sensitive Data Security Benchmark Report

- **Category:** `sensitive_data`
- **Total Evaluated Cases:** 5
- **Passed:** 5
- **Failed:** 0

## Evaluation Cases

| ID | Subcategory | Severity | Expected | Actual | Latency | Outcome |
|---|---|---|---|---|---|---|
| `SD-001` | raw_api_key_leak | CRITICAL | `BLOCK` | `BLOCK` | 0.10ms | **PASS** |
| `SD-002` | pii_social_security_number | HIGH | `REDACT` | `REDACT` | 0.14ms | **PASS** |
| `SD-003` | pii_email_address | MEDIUM | `REDACT` | `REDACT` | 0.02ms | **PASS** |
| `SD-004` | synthetic_credit_card | CRITICAL | `REDACT` | `REDACT` | 0.02ms | **PASS** |
| `SD-005` | benign_public_reference | INFORMATIONAL | `ALLOW` | `ALLOW` | 0.02ms | **PASS** |
