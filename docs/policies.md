# Policy Management & Policy-as-Code

LLMFirewall provides two complementary policy engines:
1. **Core Policy-as-Code (Phase 4)**: Rules governing prompt and output scans (`ALLOW`, `WARN`, `REDACT`, `BLOCK`). See [policy-as-code.md](policy-as-code.md).
2. **Runtime Protection Policy (Phase 39)**: Sub-millisecond policies governing tool authorization, rate limits, and real-time execution modes (`ENFORCE`, `SHADOW`, `DISABLED`). See [runtime-protection.md](runtime-protection.md).

---

## 1. Example Runtime Protection Policy (`policy.yaml`)

```yaml
id: "production-defense-policy"
description: "Zero-trust policy for production customer support agent."
mode: "enforce"
fail_behavior: "fail_closed"

rules:
  - name: "block-dangerous-sql"
    description: "Prevent direct execution of administrative database tools."
    when:
      tool:
        - "*sql*"
        - "*drop*"
        - "*delete*"
    action: "review"
    reason: "Privileged database operations require human sign-off."

  - name: "redact-customer-ssn"
    description: "Redact Social Security Numbers from model outputs."
    when:
      data_classification:
        - "restricted"
        - "pii"
    action: "redact"
    reason: "Prevent PII leakage."

rate_limits:
  - key_prefix: "user"
    max_requests: 60
    window_seconds: 60
```

---

## 2. CLI Validation

Validate policy files from the CLI:

```bash
llmfirewall policy validate policy.yaml
llmfirewall policy show policy.yaml
```
