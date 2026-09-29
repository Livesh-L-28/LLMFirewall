# LLMFirewall Phase 32: AI Security Knowledge Graph

This directory demonstrates the **AI Security Knowledge Graph** architecture representing relationships between AI applications, models, agents, tools, prompts, policies, security controls, security tests, and findings.

---

## Architecture

The example implements the following topology:

```text
Application (app:customer_portal)
    ↓ [USES]
Agent (agent:support_copilot)
 ┌──┴────────────────────────┐
 ↓ [USES]                    ↓ [CAN_CALL]
Model (model:gpt-4o)       Tools:
                             • tool:web_search
                             • tool:customer_db
                                 │
                                 └── [PROTECTED_BY] → control:sql_sanitizer
                                 └── [HAS_FINDING]  → finding:db_auth_missing
```

Plus security governance and assurance overlays:
- **Policy**: `policy:enterprise_ai_guardrails` governs `app:customer_portal` and `agent:support_copilot`.
- **Security Control**: `control:prompt_shield` protects `agent:support_copilot` and mitigates `threat:indirect_injection`.
- **Security Test**: `test:pi_regression_suite` evaluates `control:prompt_shield` with verified passing status.
- **Finding**: `finding:db_auth_missing` affects `tool:customer_db` and is mitigated by `control:sql_sanitizer`.

---

## Key Capabilities Demonstrated

1. **Local, Lightweight Graph**: Runs 100% in-process without requiring Neo4j, Redis, or external cloud services.
2. **Deterministic Entity IDs**: Stable namespaced identities (`agent:support_copilot`, `model:gpt-4o`, `tool:customer_db`).
3. **Bounded Path Traversal**: Cycle-safe BFS discovery (e.g. tracing lineage from application to sensitive databases).
4. **Security Impact Analysis**: Discovers all governing policies, protecting controls, evaluating tests, and active findings.
5. **Cascading Blast Radius**: Computes cascading exposure when a foundational model or upstream dependency is modified.
6. **Evidence-Based Control Coverage**: Distinguishes `configured`, `tested`, `passing`, and `failing` controls based on verifiable test links.
7. **Canonical Cryptographic Hashing**: Computes SHA-256 digests over normalized topology for tamper detection and release gating.

---

## Running the Example

Execute the Python demonstration:

```bash
python3 examples/security_graph/application.py
```

Inspect the exported knowledge graph using the LLMFirewall CLI:

```bash
# List all nodes
llmfirewall graph nodes --graph examples/security_graph/sample_graph.json

# Trace directed path from application to database
llmfirewall graph path app:customer_portal tool:customer_db --graph examples/security_graph/sample_graph.json

# Analyze security impact on the agent
llmfirewall graph impact agent:support_copilot --graph examples/security_graph/sample_graph.json

# Analyze cascading blast radius of the model
llmfirewall graph impact model:gpt-4o --mode blast --graph examples/security_graph/sample_graph.json

# Inspect evidence-based control coverage
llmfirewall graph impact agent:support_copilot --mode coverage --graph examples/security_graph/sample_graph.json
```
