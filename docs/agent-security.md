# Phase 29: Agent Capability Security & Action Control

`LLMFirewall` Phase 29 provides capability-based authorization, least-privilege action controls, delegation depth enforcement, action budgets, approval gates, loop detection, and runtime session revocation for autonomous and tool-using AI agents.

---

## The Core Security Invariant

```text
LLM DECISION  ≠  AUTHORIZATION
TOOL RESULT   ≠  CAPABILITY GRANT
RAG CONTENT   ≠  CAPABILITY GRANT
MODEL OUTPUT  ≠  AUTHORIZATION
USER TEXT     ≠  POLICY CHANGE
```

An LLM or autonomous agent may *request* an action. The firewall decides whether that action is authorized based on deterministic cryptographic capabilities, resource scoping, active budgets, delegation grants, and approval gates.

---

## Architecture

```text
                    USER / AGENT
                         │
                         ↓
                    MODEL OUTPUT
                         │
                         ↓
               ActionRequest(agent_id, capability, resource, arguments)
                         │
                         ↓
            ┌───────────────────────────┐
            │   Capability Engine       │
            │   ├── 1. Kill-Switch / Revocation Check
            │   ├── 2. Explicit Deny Check
            │   ├── 3. Capability Grant Match
            │   ├── 4. Resource Scope / Path / URL Guard
            │   ├── 5. Delegation Depth & Escalation Guard
            │   ├── 6. Action Depth & Loop Detector
            │   ├── 7. Action Budget & Rate Limiter
            │   └── 8. Human Approval Gate
            └────────────┬──────────────┘
                         │
         ┌───────────────┼───────────────┐
         ↓               ↓               ↓
       ALLOW      REQUIRE_APPROVAL     DENY / BUDGET_EXCEEDED
         │               │
         │         ApprovalProvider
         │               │
         └───────┬───────┘
                 ↓
          Tool Security (Phase 22)
                 ↓
          Tool Execution
                 ↓
          Tool Result Guard (Phase 26 / 27)
                 ↓
          Next Agent Step
```

---

## Core Components

### 1. Capability & CapabilityGrant

Capabilities represent granular, normalized operations with stable dot-notation identifiers (`filesystem.read`, `filesystem.write`, `network.request`, `shell.execute`, `database.read`).

```python
from llmfirewall import Capability, CapabilityGrant, ActionClassification, CapabilityRiskClass

cap = Capability(
    name="filesystem.read",
    action=ActionClassification.READ,
    resource="./reports/*",
    risk_class=CapabilityRiskClass.LOW,
)

grant = CapabilityGrant(
    capability="filesystem.read",
    resources=["./reports/*"],
    max_uses=50,
)
```

### 2. ActionRequest & ActionDecision

Agents formulate normalized `ActionRequest` objects. Sensitive secrets are scrubbed before evaluation:

```python
from llmfirewall import ActionRequest, ActionDecisionStatus

req = ActionRequest(
    agent_id="research_agent",
    capability="filesystem.read",
    tool="read_file",
    resource="./reports/summary.txt",
    session_id="session_42",
)

decision = firewall.authorize_action(req)
if decision.is_allowed:
    # Execute tool safely
    pass
```

### 3. Action Budgets & Atomic Reservations

Action budgets enforce limits across total actions, per-capability calls, runtime, and tokens without race conditions:

```python
from llmfirewall import ActionBudget

budget = ActionBudget(
    max_actions=100,
    capability_budgets={"network.request": 10, "shell.execute": 0},
    max_runtime_seconds=300,
)
```

The `BudgetManager` provides atomic `check_and_reserve()` and `release_reservation()` semantics to protect concurrent multi-agent executions.

### 4. Delegation & Escalation Protection

When an agent delegates to a subagent:
* **Subset Constraint**: `child_capabilities ⊆ parent_capabilities` unless explicitly authorized.
* **Depth Limit**: Prevents infinite or runaway subagent chains (`max_depth = 2`).

```python
from llmfirewall import DelegationGrant

delegation = DelegationGrant(
    parent_agent_id="orchestrator",
    child_agent_id="worker",
    allowed_capabilities=["filesystem.read"],
    max_depth=2,
    current_depth=1,
)
```

### 5. Approval Gates & Replay Protection

Sensitive actions (`shell.execute`, `database.delete`) can require human or system approval:

```python
from llmfirewall import MemoryApprovalProvider

approvals = MemoryApprovalProvider()
# Approve action for specific action_id or (session_id, capability, resource)
approvals.approve_action("action_123", approved_by="security_admin")
```

Approvals feature:
* **Strict Non-Interactive Rejection**: If approval is required and no provider is present, the action is denied (`ActionDecisionStatus.DENY`).
* **TTL Expiration**: Expired approvals cannot authorize actions.
* **Replay Protection**: An approval granted for `record=123` cannot authorize `record=456`.

### 6. Emergency Kill-Switch & Session Revocation

Security teams can revoke an agent session in real time without terminating the host process:

```python
firewall.revoke_session("session_42")
# All future actions for session_42 will immediately evaluate to DENY
```

### 7. Action Depth & Loop Protection

Tracks recursive invocation depth and identifies repetitive execution cycles:
```python
# Cycles like A -> B -> A -> B trigger agent_loop_detected and are denied
```

---

## Configuration Example

```yaml
capabilities:
  enabled: true
  default_grants:
    - capability: "filesystem.read"
      resources: ["./reports/*", "./data/*"]
    - capability: "network.request"
      resources: ["https://api.github.com/*"]
  explicit_deny:
    - "shell.execute"
    - "filesystem.delete"
  approval_required:
    - "database.write"
    - "email.send"
  max_action_depth: 10
  default_budget:
    max_actions: 50
    max_runtime_seconds: 600
    capability_budgets:
      network.request: 10
```

---

## CLI Commands

```bash
# List standard system capabilities and classifications
llmfirewall agent capabilities

# Evaluate policy against a capability and resource
llmfirewall agent policy-check filesystem.read --resource ./reports/doc.txt --grant filesystem.read

# Verify explicit deny enforcement
llmfirewall agent policy-check shell.execute --grant shell.execute
```

---

## Threat Model & Mitigations

| Threat | Attack Vector | LLMFirewall Mitigation |
| :--- | :--- | :--- |
| **Privilege Escalation** | Agent attempts to invoke ungranted tools or escalate capabilities dynamically | Deterministic capability matching against static `CapabilityGrant` set; default-deny. |
| **Delegation Escalation** | Parent agent delegates to subagent which requests elevated capabilities | Invariant `child_capabilities ⊆ parent_capabilities` verified on every delegated request. |
| **Path / Resource Escape** | Relative path traversal (`./reports/../../etc/passwd`) | Path normalization and Phase 22 path security integration. |
| **SSRF Escape** | Agent requests `network.request` with private IP (`169.254.169.254`) | Hostname and URL validation delegating to Phase 22 SSRF engine. |
| **Runaway Loops & DoS** | Prompt injection forces tool infinite loop | Action budgets, rate limiting, action depth tracking, and repeated-action loop detection. |
| **Approval Replay** | Reusing a previously granted approval token on a new resource | Nonce, action ID, resource, and session binding with TTL expiration. |
| **Compromised Agent Run** | Agent exhibits anomalous or hostile behavior | Real-time session revocation (`firewall.revoke_session`) and emergency deny rules. |

---

## Limitations & Non-Goals

1. **OS Sandboxing**: `LLMFirewall` is an application-level guardrail. It does not replace container or hypervisor isolation (e.g. Docker, Firecracker).
2. **Network Filtering**: Requires network egress proxies or firewall rules for defense against DNS rebinding.
3. **IAM Replacement**: Application agent capabilities complement, but do not replace, database row-level security or cloud IAM.
