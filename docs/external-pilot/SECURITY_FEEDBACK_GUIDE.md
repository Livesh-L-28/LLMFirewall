# Security Feedback Collection & Triage Standard Operating Procedure

## 1. Overview & Responsible Disclosure

Security feedback from independent developers and evaluators is critical to the hardening of `llmfirewall-core`.

To protect downstream users and avoid disclosing zero-day exploitation vectors prematurely, this document establishes the protocol for capturing, classifying, and triaging security findings across 9 distinct categories.

> [!CAUTION] Responsible Disclosure Notice
> If you discover a critical prompt injection bypass, remote code execution vector, or credential leakage vulnerability that could affect active production deployments, **do not open a public GitHub issue**. Instead, report it privately via email to the maintainers or use GitHub Private Vulnerability Reporting.

---

## 2. Nine Report Classifications

Every report submitted by an evaluator is categorized into one of nine distinct threat and quality domains:

| Category | Description | Primary Impact | Severity Default |
| :--- | :--- | :--- | :--- |
| **1. False Positive (FP)** | Legitimate, benign application prompt falsely blocked (`Action.BLOCK`). | User friction / broken workflow | High or Medium |
| **2. False Negative (FN)** | Adversarial prompt injection or jailbreak evaded detection (`Action.ALLOW`). | Security perimeter compromise | Critical or High |
| **3. Prompt Injection Bypass** | Novel obfuscation (ciphers, base64, homoglyphs) bypassing static heuristics. | Security model evasion | High |
| **4. PII Detection Failure** | Sensitive PII (email, SSN, phone, card) failed to redact or corrupted text. | Privacy regulation compliance | High or Medium |
| **5. Tool Security Failure** | SSRF against private IP/cloud metadata or shell command permitted by tool checker. | Host / network infrastructure risk | Critical |
| **6. Streaming Leakage** | Hostile token or credential split across chunk boundaries evaded detection. | Real-time output compromise | High |
| **7. Multi-Tenant Isolation** | Context bleeding, cross-tenant cache hit, or noisy-neighbor rate exhaustion. | Confidentiality / Availability | High |
| **8. Performance Regression** | Scan latency spike (> 10ms) or unbounded memory leak in worker processes. | Production SLA degradation | Medium or Low |
| **9. Installation Failure** | Package fails to install on supported Python version (3.9–3.12) or OS. | Developer onboarding blocker | High |

---

## 3. Mandatory Reporting Schema

For every issue logged, evaluators must capture the following 8 fields:

1. **Reproduction Steps**: Self-contained Python script or curl command reproducing the defect without external proprietary dependencies.
2. **Package Version**: Exact distribution and version (e.g. `llmfirewall-core==1.4.0`).
3. **Environment**: Operating system, architecture (x86_64/arm64), and exact Python version (`python --version`).
4. **Expected Behavior**: What decision (`Action.ALLOW`, `Action.BLOCK`, `Action.REDACT`) or HTTP status was expected.
5. **Actual Behavior**: The exact outcome returned by `fw.scan()` or raised exception.
6. **Severity**: Self-assessed severity (`Critical`, `High`, `Medium`, `Low`, `Enhancement`).
7. **Security Impact**: Threat explanation (e.g. "Allows unauthorized SSRF to AWS metadata 169.254.169.254").
8. **Evidence**: Relevant logs, decision traces (`fw.trace_decision()`), or timing measurements.

---

## 4. Triage & Remediation Workflow

```
Report Received ──► [ Intake Privacy Check ] ──► (Contains real secrets? Redact immediately)
                           │
                           ▼
               [ Clean Environment Reproduction ]
                           │
                           ├── (Not reproducible? Request clarification / close)
                           │
                           ▼
               [ Root Cause Classification & Severity ]
                           │
                           ▼
               [ Author Regression Test ] ──► (tests/regression/)
                           │
                           ▼
               [ Fix Implementation & Review ]
                           │
                           ▼
               [ Verify Against Protected Hashes & CI ]
```

### Invariant: Never Weaken Security Controls
- When fixing false positives, **never remove or disable core threat detection rules** globally.
- Remediation must be achieved through refined token boundary heuristics, context-aware rule scoping, or granular policy configuration.
- All fixes must verify that Holdout datasets v1–v4 and `tests/test_secrets.py` remain bit-for-bit identical.
