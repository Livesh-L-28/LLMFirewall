# Phase 3 Verification Report: LLMFirewall Cross-Step Agent Security

**Date**: October 26, 2026  
**Repository**: `Livesh-L-28/LLMFirewall`  
**Distribution**: `llmfirewall-core`  
**Version**: `1.2.0`  
**Preserved File Verification**:  
- `tests/test_secrets.py` SHA-256: `d5ca47fd85349bf4ef6d7944ab9a9f131aa27877b58bb90b31532203d7420e41` (PASSED / VERIFIED)  
**Total Test Suite Results**: **845 passed**, 1 skipped (0 failures)

---

## 1. Executive Summary

Phase 3 extends LLMFirewall's agent and tool security architecture with a stateful, cross-step execution and authorization enforcer (`src/llmfirewall/workflow/`). Rather than evaluating agent interactions as disconnected, stateless events, Phase 3 correlates threat signals across multi-turn reasoning cycles while enforcing strict immutable tenant isolation, deterministic pre-execution tool gating, and zero-retention cryptographic tracking.

---

## 2. Baseline Architecture & Gaps Identified

Prior to Phase 3, the codebase provided:
- Single-turn prompt scanning (`fw.scan()`, `fw.scan_prompt()`).
- Single-invocation tool parameter checks (`fw.check_tool_call()`).
- Basic runtime decorators (`@fw.protect`, `@fw.protect_tool`).
- Document ingestion scanning (`DocumentIngestionScanner`).

### Gaps Addressed in Phase 3
1. **Isolated Tool Inspection**: An attack payload introduced in retrieved RAG context or prompt injection had no deterministic mechanism to taint downstream tool authorizations.
2. **Mutable / Missing Tenancy Invariants**: Single-turn checks accepted optional tenant IDs, but did not guarantee that a multi-step session could not be hijacked mid-flight across tenant boundaries.
3. **Absence of Lifecycle Management**: No explicit tracking of workflow states (`INITIALIZING`, `ACTIVE`, `CANCELLED`, `TIMED_OUT`, `BLOCKED`, `COMPLETED`), timeouts, or execution quotas.
4. **Permissive Failure Risk**: No formal fail-closed contract for backing persistence during multi-step execution.

---

## 3. Threat Model & Formal Identity Taxonomy

Phase 3 introduces a formal taxonomy distinguishing eight concepts to eliminate confused-deputy and cross-tenant risks:

| Identity Concept | Source & Authority | Trust Level | Validation Mechanism | Lifecycle |
| :--- | :--- | :--- | :--- | :--- |
| **Request Identity** (`request_id`) | Client header or UUID | Untrusted if client | Format and length validation | Single request |
| **Agent / Workflow Identity** (`agent_id`, `workflow_id`) | Application orchestrator | **Authoritative** | Bound at workflow creation; validated via `ctx.assert_agent()` | Bound to workflow session |
| **Tenant Identity** (`tenant_id`) | Authenticated session token | **Authoritative & Immutable** | Bound at workflow creation; verified via `ctx.assert_tenant()` | Bound to workflow session |
| **Tool Identity** (`tool_name`) | Agent tool call declaration | Untrusted | Validated against allowlists and denylists | Per-invocation |
| **Security Context** (`WorkflowSecurityContext`) | LLMFirewall engine | Internal state | Memory LRU with pluggable persistence | Bound by TTL & idle timeout |
| **Policy Authorization** (`ScopedPermission`) | Security policy configuration | **Authoritative** | Scoped actions and resource glob pattern matching | Static per workflow session |
| **Threat Observations** (`ThreatObservation`) | Detectors, RAG, tool scanners | Internal findings | Monotonic taint escalation (`CLEAN` -> `ELEVATED` -> `TAINTED` -> `CRITICAL`) | Bounded FIFO window (50 items) |
| **Workflow Execution State** (`WorkflowStatus`) | CrossStepEnforcer engine | Internal state | Lifecycle state machine transitions | Updated per step boundary |

---

## 4. Architectural Implementation & Deliverables

### A. Core Workflow Package (`src/llmfirewall/workflow/`)
1. **`models.py`**:
   - `WorkflowSecurityContext`: Stateful envelope with immutable tenant binding, monotonic threat state escalation, step and tool counters, TTL/idle timeout checks, and `safe_dict()`.
   - `ScopedPermission`: Granular tool permissions with `allowed_actions`, `denied_actions`, `allowed_resources`, `denied_resources`, `max_invocations`, and `requires_clean_workflow`.
   - `ThreatObservation`: Audit record storing boundary, threat type, severity, and confidence without retaining raw secret strings.
   - `WorkflowStepRecord`: Bounded execution record storing SHA-256 digest (`content_hash`) and argument type signature summary (`tool_arguments_summary`).
   - Exception hierarchy: `WorkflowSecurityError`, `CrossTenantViolationError`, `IdentityTamperingError`, `WorkflowExpiredError`, `WorkflowCancelledError`, `WorkflowLimitExceededError`, `ToolAuthorizationError`.
2. **`context.py` (`WorkflowContextManager`)**:
   - Bounded in-memory LRU tracking (`max_in_memory=1000`).
   - Thread-safe concurrency control via `threading.RLock`.
   - Pluggable backing store integration with `BasePersistenceAdapter`.
   - Fail-closed storage error handling: disk corruption or database errors raise `WorkflowSecurityError` and deny execution.
3. **`enforcer.py` (`CrossStepEnforcer`)**:
   - `enforce_prompt()`: Input scan; escalates workflow taint on injection findings; terminates on block.
   - `enforce_rag()`: Retrieval scan; quarantines malicious chunks and taints workflow if poisoned.
   - `enforce_tool_call()`: Immediate pre-execution authorization check. Evaluates quotas, allowlists, scoped permissions, built-in parameter safety (traversal, command injection, SSRF), and taint restrictions (`DANGEROUS_TOOLS_ON_TAINT`). A denied tool raises `ToolAuthorizationError` and **never executes**.
   - `enforce_tool_result()`: Post-execution tool output scan; taints workflow if credentials or injections leak from external services.

### B. Core Orchestrator Integration
- **`Firewall` (`src/llmfirewall/firewall.py`)**:
  - Properties `fw.workflow_manager` and `fw.cross_step_enforcer`.
  - Helper methods: `fw.create_workflow()`, `fw.get_workflow()`, `fw.workflow()`.
  - Updated `fw.check_tool_call()` and `fw.check_tool_result()` to seamlessly route through cross-step enforcer when `workflow_id` is supplied while preserving 100% backward compatibility when omitted.
  - Updated `@fw.protect_tool` in `src/llmfirewall/protection/sdk.py` to enforce pre-execution authorization gating.

### C. Multi-Step Example Application (`examples/cross_step_agent/`)
- `application.py`: Implementation of an Enterprise Support & IT Operations Agent demonstrating:
  - Benign workflow execution.
  - Poisoned RAG documentation blocking subsequent privileged service restarts.
  - Scoped resource restrictions preventing restart of protected services (`payment_processor`).
  - Cross-tenant violation rejection.
- `test_application.py`: Automated integration test suite verifying end-to-end operation.
- `README.md`: Architecture guide and run instructions.

---

## 5. Multi-Step Threat Scenario Verification

All 9 mandatory multi-step threat scenarios and edge cases were implemented in `tests/test_cross_step_security.py` and passed with 100% determinism:

| Scenario | Objective | Tested Conditions | Expected & Observed Outcome | Verdict |
| :--- | :--- | :--- | :--- | :--- |
| **Scenario 1** | Benign prompt followed by malicious tool request | User asks benign query; agent attempts path traversal `../../../../etc/shadow` | `ToolAuthorizationError` raised; underlying function never executed; logged as `Action.BLOCK` | **PASS** |
| **Scenario 2** | Indirect prompt injection in retrieved content | Benign prompt; retrieved RAG chunk contains instruction override | Chunk quarantined; workflow threat state escalated to `TAINTED`; dangerous tool `database_delete` denied | **PASS** |
| **Scenario 3** | Unsafe tool result influences subsequent action | Safe prompt and HTTP query; API returns leaked GitHub token | Output flagged; workflow escalates to `CRITICAL`; subsequent `send_email` blocked | **PASS** |
| **Scenario 4** | Mid-workflow identity tampering | Attacker attempts to switch `tenant_id` or escalate `agent_id` | `CrossTenantViolationError` and `IdentityTamperingError` raised immediately; zero cross-tenant leakage | **PASS** |
| **Scenario 5** | Replay of stale or expired authorization context | Workflow exceeds TTL or inactivity idle timeout | `WorkflowExpiredError` raised immediately; status set to `TIMED_OUT` | **PASS** |
| **Scenario 6** | Conflicting tool permissions | Tool with scoped actions (`read` only) and paths (`/data/public/*` only) | Permitted read succeeds; `delete` action or `/etc/*` path raises `ToolAuthorizationError` | **PASS** |
| **Scenario 7** | Workflow cancellation during execution | Operator triggers Emergency Stop via `cancel_workflow` | Workflow status set to `CANCELLED`; subsequent tool request raises `WorkflowCancelledError` | **PASS** |
| **Scenario 8** | Storage failure fails closed | Backing persistence store raises disk I/O error | Workflow creation and retrieval fail closed with `WorkflowSecurityError`; no permissive bypass | **PASS** |
| **Scenario 9** | High-concurrency tenant isolation | 8 concurrent threads executing independent workflows across distinct tenants | Zero race conditions, zero cross-tenant contamination, 100% isolation verified | **PASS** |
| **Decorator** | Pre-execution tool gating invariant | `@fw.protect_tool` wrapping real Python function with call counter | Allowed call runs; denied call raises `ToolAuthorizationError`; call counter confirms tool never ran | **PASS** |
| **Limits** | Workflow step and tool execution limits | Workflow with `max_tool_calls=2` invoked 3 times | 3rd invocation raises `WorkflowLimitExceededError`; workflow marked `BLOCKED` | **PASS** |
| **Zero-Retention**| Telemetry and context privacy | Workflow containing secret tokens serialized via `safe_dict()` | Zero raw prompts or secret strings present; only SHA-256 content hashes and parameter type signatures retained | **PASS** |

---

## 6. Backward Compatibility & Test Invariants

1. **Test Invariant**:
   `tests/test_secrets.py` SHA-256 checksum:
   ```bash
   shasum -a 256 tests/test_secrets.py
   # d5ca47fd85349bf4ef6d7944ab9a9f131aa27877b58bb90b31532203d7420e41  tests/test_secrets.py
   ```
2. **Backward Compatibility**:
   - All existing single-turn calls (`fw.scan()`, `fw.check_tool_call(call)`, `@fw.protect`) function identically without modification.
   - All 829 baseline tests continue to pass.
   - New capabilities are strictly additive.

---

## 7. Execution Proof & Static Checks

```bash
# 1. Run cross-step security suite
pytest tests/test_cross_step_security.py -v
# ============================== 12 passed in 0.19s ==============================

# 2. Run example application tests
pytest examples/cross_step_agent/test_application.py -v
# ============================== 4 passed in 0.36s ===============================

# 3. Run full test suite
pytest -q
# ============================ 845 passed, 1 skipped in 5.48s ====================

# 4. Lint and static formatting
ruff check .
# All checks passed!
```

---

## 8. Conclusion

Phase 3 is complete and fully verified. LLMFirewall now provides end-to-end cross-step security correlation, preventing multi-turn jailbreaks, indirect RAG injections from affecting privileged tools, and cross-tenant authorization escapes.

*Phase 3 is complete. Halting execution per instructions (Phases 4–6 not started, version unchanged at v1.2.0, zero pushes, zero publishes).*
