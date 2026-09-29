# Capability-Based Security Specification

This document details the capability model, taxonomy, scoping rules, and security enforcement algorithms implemented in `LLMFirewall` Phase 29.

---

## 1. Capability Taxonomy

All capabilities adhere to a hierarchical dot-notation naming convention (`<domain>.<operation>`):

| Capability Identifier | Classification | Default Risk | Description |
| :--- | :--- | :--- | :--- |
| `filesystem.read` | `READ` | `LOW` | Read files within authorized directory paths |
| `filesystem.write` | `WRITE` | `MEDIUM` | Write or modify files within authorized directories |
| `filesystem.delete` | `DELETE` | `HIGH` | Delete files within authorized paths |
| `database.read` | `READ` | `LOW` | Execute read-only database queries |
| `database.write` | `WRITE` | `MEDIUM` | Insert or update database records |
| `database.delete` | `DELETE` | `HIGH` | Delete database rows or drop collections |
| `network.request` | `COMMUNICATE` | `MEDIUM` | Outbound HTTP/HTTPS requests to permitted domains |
| `email.send` | `COMMUNICATE` | `HIGH` | Dispatch outbound email communications |
| `shell.execute` | `EXECUTE` | `CRITICAL` | Execute system processes or terminal commands |
| `cloud.deploy` | `DEPLOY` | `HIGH` | Trigger infrastructure deployments |
| `admin.configure` | `ADMIN` | `CRITICAL` | Modify runtime policies or security parameters |

---

## 2. Resource Scoping Rules

Capability grants optionally declare resource patterns:

```yaml
capabilities:
  - capability: filesystem.read
    resources:
      - "./data/*"
      - "./reports/*.pdf"
```

### Path Normalization
Before evaluating resource patterns, paths undergo:
1. Normalization of directory separators and removal of relative segments (`..`, `.`).
2. Resolution to absolute paths when evaluated against sandbox directories.
3. Matching against explicit glob patterns using `fnmatch`.
4. Traversal rejection: Any path attempting to escape root bounds via traversal is blocked.

### Network Scoping
For `network.request`, resource strings represent allowed URL prefixes or domain wildcards:
```yaml
- capability: network.request
  resources:
    - "https://api.github.com/*"
    - "https://*.stripe.com/*"
```
Private IP ranges, AWS/GCP metadata endpoints (`169.254.169.254`), and loopback interfaces (`127.0.0.1`) are denied by default.

---

## 3. Delegation Invariants

Delegation allows an autonomous agent to spawn or delegate tasks to specialized subagents.

### The Subset Invariant
$$\text{Capabilities}(\text{Child}) \subseteq \text{Capabilities}(\text{Parent})$$

A parent agent cannot delegate capabilities it does not possess. Any attempt by a child agent to request capabilities outside the intersection of its own grant and the delegation token is denied with `ActionDecisionStatus.DENY`.

### Depth Bound
Recursive delegation chains are strictly bounded:
$$\text{CurrentDepth} \le \text{MaxDepth}$$
Exceeding `max_depth` results in automatic delegation rejection.

---

## 4. Approval Gates & Cryptographic Anti-Replay

Actions classified as high-risk or explicitly marked in policy as `approval: required` cannot execute until a valid `ApprovalRequest` is verified.

### Anti-Replay Verification
An approval token or record is valid **if and only if**:
1. `approved == True`
2. `expires_at > current_timestamp`
3. If bound to `action_id`, `record.action_id == request.action_id`
4. If bound to `(session_id, capability, resource)`, all three fields match exactly.

Once verified and consumed for an execution, the approval token cannot be used again for a different action or modified resource arguments.

---

## 5. Action Budgets & Concurrency

To defend against financial DoS, API exhaustion, or infinite agent loops:

1. **Global Action Limit**: Maximum allowed actions per session (`max_actions`).
2. **Per-Capability Limit**: Granular quotas per capability (e.g. `filesystem.write: 5`).
3. **Runtime Limit**: Cumulative wall-clock execution time (`max_runtime_seconds`).
4. **Token Quota**: Cumulative prompt/completion tokens consumed (`max_tokens`).

### Atomic Reservation Protocol
```text
Thread / Worker
       │
       ├──> BudgetManager.check_and_reserve(action_count=1)
       │    ├── Validates remaining capacity under Lock
       │    └── Decrements remaining quota atomically
       │
    [Execution Phase]
       │
       ├── If Success: Reservation committed
       └── If Failure / Rejected: BudgetManager.release_reservation()
```

---

## 6. Security Event Telemetry

Every authorization evaluation emits an auditable event with correlation IDs:

* `agent_id`
* `session_id`
* `action_id`
* `parent_action_id`
* `capability`
* `decision`
* `risk_class`
* `timestamp`

Sensitive argument values and API secrets are never logged in audit records.
