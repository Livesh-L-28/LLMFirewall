# Multi-Step AI Agent Security with LLMFirewall (Phase 3)

This directory provides an end-to-end runnable example of an Enterprise IT Support & Operations Agent protected by **LLMFirewall Cross-Step Agent Security**.

---

## 1. Trust Boundaries & Protection Flow

```text
1. User Request (Input) ──────► [BOUNDARY 1: Input Prompt Scan]
                                  fw.cross_step_enforcer.enforce_prompt()
                                        │ (Taint escalated if adversarial)
                                        ▼
2. RAG Knowledge Ingestion ───► [BOUNDARY 2: Retrieved Context Quarantine]
                                  fw.cross_step_enforcer.enforce_rag()
                                        │ (Quarantines injections; taints workflow)
                                        ▼
3. Agent Reason / Tool Call ──► [BOUNDARY 3: Pre-Execution Authorization]
                                  fw.check_tool_call() / @fw.protect_tool
                                        │ (Gated by tenant, taint state, and scoped permissions)
                                        ▼
                                  [Tool Executes ONLY If Authorized]
                                        │
                                        ▼
4. Tool Result ───────────────► [BOUNDARY 4: Tool Result Scan]
                                  fw.check_tool_result()
                                        │ (Taints workflow if sensitive data or secrets leak)
                                        ▼
5. Final Sanitized Output ────► Sanitized Response to User
```

---

## 2. Key Security Guarantees Demonstrated

1. **Deterministic Pre-Execution Tool Denial**:
   A tool invocation denied by scoped permissions or taint gating *never* executes. The underlying Python function is never called.
2. **Cross-Step Taint Propagation**:
   When indirect prompt injection is detected in retrieved documentation or an external API returns leaked credentials, the workflow state escalates to `TAINTED` or `CRITICAL`. Privileged tools (e.g. `restart_service`, `shell_exec`, `database_delete`) are automatically blocked for all subsequent steps in that session.
3. **Strict Immutable Tenancy**:
   `tenant_id` is bound authoritatively at workflow creation. Steps specifying an mismatched tenant are immediately aborted with `CrossTenantViolationError`.
4. **Zero-Retention Telemetry**:
   Workflow context records SHA-256 digests (`content_hash`) and argument parameter type signatures (`tool_arguments_summary`) instead of storing raw user prompts or unredacted passwords.

---

## 3. Running the Example Tests

```bash
pytest examples/cross_step_agent/test_application.py -v
```
