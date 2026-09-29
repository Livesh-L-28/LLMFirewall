# AI Security Posture Management (AI-SPM)

## 1. Overview

**Phase 35 — AI Security Posture Management (AI-SPM)** provides a continuously calculable, evidence-based view of the security posture of AI systems.

While earlier phases answer:
* **Phase 34 (Asset Inventory)**: *What AI assets exist?*
* **Phase 32 (Knowledge Graph)**: *How are they connected?*
* **Phase 33 (Attack Graph)**: *How could they be attacked?*

**Phase 35 (AI-SPM)** answers:
```text
HOW WELL IS IT PROTECTED?
WHAT SECURITY CONTROLS EXIST?
WHAT IS MISCONFIGURED?
WHAT HAS NOT BEEN TESTED?
WHAT SECURITY GAPS EXIST?
WHAT CHANGED?
```

The unified defensive architecture becomes:

```text
       Asset Inventory (Phase 34)
                  ↓
       Knowledge Graph (Phase 32)
                  ↓
       Attack Graph (Phase 33)
                  ↓
       Security Posture Engine (Phase 35)
                  ↓
       AI-SPM
```

---

## 2. Core Architectural Principles

1. **No Arbitrary Numerical Scores**: Simplistic security scores (e.g., `73/100`) are fundamentally avoided. Every posture conclusion is backed by explicit, verifiable audit evidence.
2. **Explicit Posture States**:
   * `HEALTHY`: Mandatory defensive controls present and validated; security tests passing; no open HIGH or CRITICAL findings; no unmitigated attack paths.
   * `ATTENTION_REQUIRED`: Non-critical gaps exist (e.g. unverified authorization, unexecuted tests, unknown rate limiting or logging).
   * `DEGRADED`: A security control failed validation, an empirical security test failed, or an open HIGH severity finding exists.
   * `CRITICAL`: An open CRITICAL severity finding exists, an unmitigated attack path reaches sensitive data/tools, or perimeter control is ABSENT.
   * `UNKNOWN`: Insufficient observations or evidence available to assess security posture.
3. **Unknown as a First-Class State**: If evidence is missing, posture reports `UNKNOWN` or `NOT_TESTED`. Unknown is never silently converted into `SECURE` or `VULNERABLE`.
4. **Control Presence vs. Effectiveness**: Configured does not equal effective:
   * **Presence**: `PRESENT`, `PARTIALLY_PRESENT`, `ABSENT`, `UNKNOWN`.
   * **Effectiveness**: `CONFIGURED`, `TESTED`, `VALIDATED`, `FAILED`, `UNKNOWN`.
5. **Zero Secret Infiltration**: Credentials, API keys, private tokens, and passwords are recursively redacted from posture records, snapshots, and reports.
6. **Defensive Non-Goals**: AI-SPM does not perform automatic vulnerability exploitation, active network scanning, automatic production remediation, or arbitrary firewall blocking.

---

## 3. The 15 Posture Dimensions

AI-SPM categorizes security posture into 15 standardized dimensions:

| Dimension | Description |
|---|---|
| `asset_security` | Asset classification, provenance integrity, inventory tracking |
| `model_security` | Foundation model versions, change detection, deployment security |
| `agent_security` | Autonomous agent capabilities, instructions, isolation, memory |
| `tool_security` | Tool identity, agent permissions, invocation authorization |
| `prompt_security` | Prompt injection detection, jailbreak guardrails, system prompt protection |
| `rag_security` | Retrieval document validation, tenant access control, poisoning defenses |
| `memory_security` | Persistent memory retention, buffer isolation, memory poisoning defenses |
| `data_security` | Sensitive data access, PII protection, exfiltration controls |
| `dependency_security` | AI libraries, supply chain integrity, vulnerability tracking |
| `configuration_security` | TLS, authentication, rate limiting, logging, timeout controls |
| `access_control` | RBAC, tool call authorization, perimeter authentication |
| `monitoring` | Observability sinks, audit logging, telemetry tracking |
| `testing` | Empirical security test coverage (Phase 30), test freshness |
| `governance` | Policy-as-Code assignment, version tracking, policy conflict detection |
| `attack_surface` | Factual exposure of tools, external APIs, memory, and RAG sources |

---

## 4. Posture Pipeline Integration

The Posture Engine synthesizes factual evidence across all LLMFirewall subsystems:

```text
                        LLMFirewall
                             │
                             ↓
                      ASSET INVENTORY
                             │
                             ↓
                   SECURITY KNOWLEDGE GRAPH
                             │
               ┌─────────────┴─────────────┐
               ↓                           ↓
         ATTACK GRAPH                 GOVERNANCE
               │                           │
               ↓                           ↓
         ATTACK PATHS                  POLICIES
               │                       BASELINES
               │                       FINDINGS
               └─────────────┬─────────────┘
                             ↓
                    AI-SPM POSTURE ENGINE
                             │
         ┌───────────────────┼───────────────────┐
         ↓                   ↓                   ↓
      Controls            Testing            Configuration
         │                   │                   │
         └───────────────────┼───────────────────┘
                             ↓
                    SECURITY GAPS
                             │
                             ↓
                    POSTURE SNAPSHOT
                             │
                             ↓
                      POSTURE DIFF
                             │
                             ↓
                   SECURITY REGRESSION
```

---

## 5. CLI Commands

AI-SPM provides standard CLI commands:

```bash
# Aggregated posture summary across all assets
llmfirewall posture summary

# Output summary as structured JSON
llmfirewall posture summary --json

# Detailed posture for a specific asset
llmfirewall posture agent:customer-support

# Capture a baseline snapshot
llmfirewall posture snapshot --output baseline.json

# Compare current posture against baseline
llmfirewall posture diff --before baseline.json --after current.json

# Export actionable security gaps in SARIF 2.1.0 format
llmfirewall posture export --format sarif --output gaps.sarif
```
