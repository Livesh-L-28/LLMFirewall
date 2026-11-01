# Enterprise Policy Governance, Versioning & Rollback

## 1. Overview

In multi-tenant and regulated enterprise environments, security policies cannot be treated as ad-hoc configuration files. A faulty or tampered policy can disable critical PII redactions or introduce catastrophic false positives that break production LLM pipelines.

`PolicyGovernanceManager` provides end-to-end lifecycle governance for Policy-as-Code definitions:
- Cryptographic SHA-256 integrity checks preventing file tampering.
- Explicit approval state machine (`DRAFT` → `VALIDATED` → `APPROVED` → `ACTIVATED`).
- Atomic, zero-downtime rollback to known-good policy revisions.
- Immutable baseline floor enforcement preventing tenant policies from weakening corporate security controls.

---

## 2. Policy Lifecycle State Machine

```
   ┌─────────┐      Validation       ┌───────────┐      Approval       ┌──────────┐
   │  DRAFT  ├──────────────────────►│ VALIDATED ├────────────────────►│ APPROVED │
   └─────────┘                       └───────────┘                     └────┬─────┘
                                                                            │
                                                                   Activate │
                                                                            ▼
   ┌─────────────┐      Atomic Rollback      ┌───────────┐             ┌───────────┐
   │   RETIRED   │◄──────────────────────────┤ROLLED_BACK│◄────────────┤ ACTIVATED │
   └─────────────┘                           └───────────┘             └───────────┘
```

---

## 3. Cryptographic Verification & Approval Workflow

```python
from llmfirewall.enterprise import (
    PolicyGovernanceManager,
    PolicyLifecycleState,
    PolicyIntegrityError,
)

# 1. Initialize governance manager with an immutable enterprise baseline policy
gov_mgr = PolicyGovernanceManager(
    baseline_policy_path="policies/corporate_baseline.yaml"
)

# 2. Stage a candidate policy document
gov_record = gov_mgr.stage_policy(
    policy_id="tenant_finance_v2",
    content=raw_policy_yaml_bytes,
    author="appsec-lead@corp.internal",
)

print(f"Policy SHA-256: {gov_record.content_hash}")
print(f"Current State: {gov_record.state}") # DRAFT

# 3. Validate against syntax and schema
gov_mgr.validate_policy("tenant_finance_v2") # Transitions to VALIDATED

# 4. Enforce mandatory AppSec approval
gov_mgr.approve_policy(
    policy_id="tenant_finance_v2",
    approved_by="ciso-delegate@corp.internal",
    approval_token="SEC-SIGN-918237"
) # Transitions to APPROVED

# 5. Hot-activate into runtime engine
gov_mgr.activate_policy("tenant_finance_v2") # Transitions to ACTIVATED
```

---

## 4. Atomic Zero-Downtime Rollback

If a newly activated policy causes unexpected application errors or false positives, administrators can roll back atomically to the previous revision in a single synchronous call:

```python
# Atomic instant rollback
reverted_record = gov_mgr.rollback_policy(
    policy_id="tenant_finance_v2",
    reason="Elevated false-positive rate observed on financial ticker analysis",
    operator="sre-oncall@corp.internal"
)

print(f"Reverted to revision: {reverted_record.version}")
```
The governance manager swaps the active in-memory reference pointer under a lock, ensuring zero dropped requests during rollback.

---

## 5. Non-Negotiable Baseline Floor Protection

Enterprise platforms frequently allow individual product teams to customize scanning rules. However, tenant customizations **must never disable corporate baseline protections**:
- If a tenant policy attempts to disable credential scrubbing or SQL injection detection, `PolicyGovernanceManager` rejects the policy during the `VALIDATE` step.
- The effective policy evaluated by the engine is the strict union of `Baseline Policy` ⊕ `Tenant Customizations`.
