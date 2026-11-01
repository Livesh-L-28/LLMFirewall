# LLMFirewall-Core Configuration & Policy-as-Code Guide

Author, customize, and enforce declarative security policies using JSON and YAML.

---

## 1. Overview: Deterministic Action Precedence

LLMFirewall evaluates all policy rules deterministically using strict action precedence:

$$\text{BLOCK} > \text{REDACT} > \text{WARN} > \text{ALLOW}$$

- If any active rule resolves to **`Action.BLOCK`**, the request is immediately rejected.
- If no rule blocks, but a rule matches **`Action.REDACT`**, sensitive text is sanitized.
- If warnings are recorded without blocks or redactions, `Action.WARN` is emitted with audit telemetry.
- If no rules trigger, the request defaults to `Action.ALLOW`.

---

## 2. Built-in Policy Presets (v1.4.0)

LLMFirewall-Core includes three built-in JSON policy presets located in `src/llmfirewall/policies/`:

| Preset Name | Target Use Case | Default PII Action | Default Injection Action | Risk Threshold |
|:---|:---|:---:|:---:|:---:|
| **`default`** | Production standard | `Action.REDACT` | `Action.BLOCK` | $\ge 0.85$ Block |
| **`privacy`** | Strict compliance / GDPR | `Action.REDACT` (zero retention) | `Action.BLOCK` | $\ge 0.70$ Block |
| **`strict`** | High-security enterprise | `Action.BLOCK` | `Action.BLOCK` | $\ge 0.50$ Block |

### Initializing with a Preset

```python
from llmfirewall import Firewall

# Initialize with strict enterprise preset:
fw_strict = Firewall(policy="strict")

# Initialize with privacy-first preset:
fw_privacy = Firewall(policy="privacy")
```

---

## 3. Authoring Custom Declarative Policies

Custom policies can be defined in JSON or YAML:

```json
{
  "name": "enterprise_custom_policy",
  "version": "1.0",
  "default_action": "ALLOW",
  "risk_thresholds": {
    "block": 0.85,
    "warn": 0.50
  },
  "rules": [
    {
      "id": "block_injections",
      "name": "Block Prompt Injections",
      "threat_type": "prompt_injection",
      "action": "BLOCK",
      "priority": 100
    },
    {
      "id": "redact_pii_emails",
      "name": "Redact Email Addresses",
      "threat_type": "pii",
      "action": "REDACT",
      "priority": 90
    }
  ]
}
```

### Loading a Policy File in Python

```python
from llmfirewall import Firewall
from llmfirewall.policy import Policy

# Load declarative policy from disk:
policy = Policy.from_file("policies/custom_policy.json")

# Instantiate firewall with policy:
fw = Firewall(policy=policy)
```

---

## 4. Validating Policies via CLI

Validate your policy files for rule contradictions, invalid threat types, or cycle defects:

```bash
llmfirewall policy validate policies/default.json
```
*Expected Output:*
```text
Policy 'policies/default.json' is valid.
Rules: 4 | Precedence: BLOCK > REDACT > WARN > ALLOW
```
