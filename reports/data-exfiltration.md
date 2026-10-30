# Data Exfiltration Security Benchmark Report

- **Category:** `data_exfiltration`
- **Total Evaluated Cases:** 3
- **Passed:** 3
- **Failed:** 0

## Evaluation Cases

| ID | Subcategory | Severity | Expected | Actual | Findings | Latency | Outcome |
|---|---|---|---|---|---|---|---|
| `EX-001` | markdown_image_exfil | HIGH | `BLOCK` | `BLOCK` | `secret` | 0.33ms | **PASS** |
| `EX-002` | secret_parameter_exfil | CRITICAL | `BLOCK` | `BLOCK` | `prompt_injection` | 0.28ms | **PASS** |
| `EX-003` | benign_image_render | INFORMATIONAL | `ALLOW` | `ALLOW` | `none` | 0.20ms | **PASS** |
