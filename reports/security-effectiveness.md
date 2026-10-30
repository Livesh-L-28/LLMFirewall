# LLMFirewall Security Effectiveness Report

- **Dataset Version:** `2.0.0`
- **Total Test Cases:** 64
- **Passed Cases:** 64 / 64
- **Policy Decision Accuracy:** `100.00%`

## Core Effectiveness Metrics

| Metric | Value | Target | Evaluation Status |
|---|---|---|---|
| **Precision** | `100.00%` | >= 95.0% | PASS |
| **Recall** | `100.00%` | >= 95.0% | PASS |
| **F1 Score** | `100.00%` | >= 95.0% | PASS |
| **False Positive Rate (FPR)** | `0.00%` | <= 5.0% | PASS |
| **False Negative Rate (FNR)** | `0.00%` | <= 5.0% | PASS |

## Binary Confusion Matrix

| Condition | Actual Attack | Actual Benign |
|---|---|---|
| **Predicted Attack (Blocked/Redacted/Warned)** | `36` (TP) | `0` (FP) |
| **Predicted Benign (Allowed)** | `0` (FN) | `28` (TN) |

## Policy Outcomes Matrix (Expected vs Actual)

| Expected Action | actual: allow | actual: block | actual: redact | actual: warn | actual: review |
|---|---|---|---|---|---|
| **ALLOW** | 28 | 0 | 0 | 0 | 0 |
| **BLOCK** | 0 | 31 | 0 | 0 | 0 |
| **REDACT** | 0 | 0 | 4 | 0 | 0 |
| **WARN** | 0 | 0 | 0 | 0 | 0 |
| **REVIEW** | 0 | 0 | 0 | 0 | 1 |

## Breakdown by Threat Category

| Category | Cases | Accuracy | Precision | Recall | F1 Score | P50 Latency | P95 Latency | Findings Match |
|---|---|---|---|---|---|---|---|---|
| `agent_attacks` | 3 | 100.0% | 100.0% | 100.0% | 100.0% | 0.17ms | 1.61ms | 100.0% |
| `benign` | 8 | 100.0% | 100.0% | 100.0% | 100.0% | 0.20ms | 0.44ms | 100.0% |
| `data_exfiltration` | 3 | 100.0% | 100.0% | 100.0% | 100.0% | 0.28ms | 0.32ms | 100.0% |
| `jailbreak` | 7 | 100.0% | 100.0% | 100.0% | 100.0% | 0.23ms | 0.29ms | 42.9% |
| `malformed_oversized` | 5 | 100.0% | 100.0% | 100.0% | 100.0% | 0.15ms | 0.32ms | 100.0% |
| `memory_poisoning` | 3 | 100.0% | 100.0% | 100.0% | 100.0% | 0.09ms | 0.11ms | 100.0% |
| `multi_turn` | 2 | 100.0% | 100.0% | 100.0% | 100.0% | 0.55ms | 0.57ms | 100.0% |
| `policy_precedence` | 4 | 100.0% | 100.0% | 100.0% | 100.0% | 0.19ms | 0.29ms | 100.0% |
| `prompt_injection` | 11 | 100.0% | 100.0% | 100.0% | 100.0% | 0.22ms | 0.23ms | 100.0% |
| `rag_poisoning` | 3 | 100.0% | 100.0% | 100.0% | 100.0% | 0.09ms | 0.11ms | 100.0% |
| `sensitive_data` | 5 | 100.0% | 100.0% | 100.0% | 100.0% | 0.02ms | 0.12ms | 100.0% |
| `tool_abuse` | 5 | 100.0% | 100.0% | 100.0% | 100.0% | 0.11ms | 0.16ms | 100.0% |
| `unicode_evasion` | 5 | 100.0% | 100.0% | 100.0% | 100.0% | 0.23ms | 0.27ms | 100.0% |
