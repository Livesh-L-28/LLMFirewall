# Security Operations & Incident Response Runbook

## 1. Overview

This runbook defines standard operating procedures for Security Operations Centers (SOC), Application Security Engineers, and Site Reliability Engineers (SRE) managing production incidents involving LLMFirewall-Core.

---

## 2. Severity Classification Matrix

| Severity | Definition | Target MTTA | Target MTTR | Examples |
| :--- | :--- | :--- | :--- | :--- |
| **SEV-1 (Critical)** | Active security bypass with exfiltration of PII/credentials or full platform outage. | < 15 min | < 2 hours | Successful jailbreak leaking system prompt + API keys; Redis outage with `FAIL_CLOSED` policy blocking all traffic. |
| **SEV-2 (High)** | Elevated attack volume, widespread false-positive blocks, or degraded security infrastructure. | < 30 min | < 4 hours | Sustained prompt injection flood (> 1,000 req/sec); false positive rate > 5% on benign traffic. |
| **SEV-3 (Medium)** | Individual rule misclassification or single-tenant rate-limit exhaustion. | < 2 hours | < 1 business day | Single benign query falsely flagged as SQL injection; single customer tenant throttled. |
| **SEV-4 (Low)** | Telemetry / metric anomalies with zero user-facing impact. | < 1 business day | < 1 sprint | OpenTelemetry collector reporting transient dropped metric packets. |

---

## 3. Incident Playbooks

### Playbook 1: Sustained Prompt Injection / Jailbreak Attack

**Trigger**: Alert `LLMFirewall_HighThreatVolume` triggers (> 500 blocks/min).

1. **Triage & Context Isolation**:
   - Inspect Grafana dashboard / OpenTelemetry traces for `action="BLOCK"`.
   - Identify the source dimension: `tenant_id`, IP range, or API key hash.
2. **Containment**:
   - If isolated to a single tenant or user: Apply emergency rate limit via `DistributedRateLimiter`:
     ```python
     limiter.set_emergency_quota(key=attacker_tenant_id, limit=0, duration=3600)
     ```
   - If distributed botnet: Update API gateway / Cloudflare WAF to drop requests at edge.
3. **Investigation**:
   - Inspect `SafeAuditEvent` logs. Examine matched `rule_ids` (e.g. `EXT_RULE_SYSTEM_OVERRIDE`).
   - Do NOT attempt to log raw prompt payloads into Slack or Jira. Use rule IDs and threat scores for correlation.
4. **Post-Incident**:
   - Add new adversarial patterns to regression test suite `tests/regression/`.

---

### Playbook 2: Elevated False-Positive Spike

**Trigger**: Alert `LLMFirewall_FalsePositiveSpike` triggers (User reports or sudden spike in `BLOCK` on known benign workflows).

1. **Verify Impact**:
   - Identify which rule ID is triggering the blocks via `llmfirewall_threats_detected_total{rule_id="..."}`.
2. **Execute Hot-Rollback**:
   - If caused by a newly deployed policy, execute atomic zero-downtime rollback:
     ```bash
     llmfirewall policy rollback --policy-id tenant_finance --reason "FP spike in rule PII_FIN_04"
     ```
   - Or programmatically via `PolicyGovernanceManager.rollback_policy()`.
3. **Verify Restoration**:
   - Confirm scan pass rate returns to baseline (> 99.8%).

---

### Playbook 3: External Infrastructure Outage (Redis / Vault Down)

**Trigger**: Alert `LLMFirewall_RedisUnreachable` or `CircuitBreaker_Open`.

1. **Assess Failure Policy**:
   - Check `LLMFIREWALL_FAILURE_POLICY` environment variable.
   - If set to `FAIL_OPEN`: Confirm `InMemoryRateLimiter` and local cached secrets took over. Applications remain operational.
   - If set to `FAIL_CLOSED`: Evaluate if risk profile allows temporary toggle to `FAIL_OPEN` during outage.
2. **Remediate Dependency**:
   - Restart Redis pods or Vault unseal operations in Kubernetes.
3. **Recovery Verification**:
   - Verify `CircuitBreaker` transitions from `OPEN` to `HALF_OPEN` and then `CLOSED`.
