# Agent & Tool Security 2.0 (Phase 47)

LLMFirewall v1.1.0 delivers a defense-in-depth architecture for securing Autonomous Agents and Tool Execution. It unifies stateful capabilities, action budget management, replay protection, typed parameter constraints, multi-step action chains, approval gates, and tool-result provenance & trust classification.

---

## 1. Architectural Pipeline

```
Agent Action Request / Tool Invocation
   │
   ▼
[ 1. Tool Identity & Allowlist / Denylist Check ]
   │
   ▼
[ 2. Tool Definition & Registry Authorization ]
   │
   ▼
[ 3. Replay Protection & Deduplication Guard ]
   │
   ▼
[ 4. Stateful Capability & Role Authorization ] (Least Privilege & Resource Scopes)
   │
   ▼
[ 5. Action-Chain & Lineage Tracking ] (Preventing Escalation Across Steps)
   │
   ▼
[ 6. Typed Parameter & Schema Validation ] (Enum, Range, Type, Structure)
   │
   ▼
[ 7. Destination, SSRF, File Path, Command & SQL Inspection ]
   │
   ▼
[ 8. Sensitive Argument Scanning ] (PII, Secrets, Injection via Detector Engine)
   │
   ▼
[ 9. Risk Scoring & Policy-as-Code Evaluation ]
   │
   ▼
[ 10. Human/Policy Approval Gates & Budget Enforcement ]
   │
   ▼
Tool Execution
   │
   ▼
[ 11. Tool Result Output Inspection ]
   │
   ▼
[ 12. Result Trust Classification & Provenance Tagging ] (TRUSTED, UNTRUSTED, SANITIZED, QUARANTINED)
   │
   ▼
Safe Result or Quarantined Isolation
```

---

## 2. Key Components

### 2.1 Typed Parameter Constraints & Schema Validation
Tool parameters are evaluated against lightweight JSON Schema specifications:
- **Type verification**: `string`, `integer`, `number`, `boolean`, `array`, `object` (with strict boolean vs int disambiguation).
- **Enum constraints**: Disallowing unauthorized enumerations.
- **Range limits**: Numeric `minimum` / `maximum` enforcement.
- **String length limits**: `minLength` / `maxLength` enforcement.

### 2.2 Replay Protection
Prevents automated duplicate execution of sensitive side-effect actions (such as funds transfer or delete commands):
```python
engine = ToolSecurityEngine(enable_replay_protection=True)
```

### 2.3 Stateful Capability Authorization & Action Chains
Links tools with fine-grained granular capabilities (`filesystem.read`, `database.write`, etc.) and enforces glob-based resource scoping:
- Action chains track root actions, parent actions, and call depth.
- Prevents capability escalation across multi-agent delegation or sub-agent handoffs.
- Integrates with `BudgetManager` to enforce quotas per capability or session.

### 2.4 Tool-Result Provenance & Trust Classification
External tool results are classified under `ResultTrustLevel`:
- `TRUSTED`: Internal, authenticated, and verified deterministic outputs.
- `UNTRUSTED`: External API or public web responses.
- `SANITIZED`: Data that was modified by redaction (e.g. PII masking).
- `QUARANTINED`: Data carrying detected indirect prompt injections or malicious payloads.

---

## 3. Usage Example

```python
from llmfirewall import (
    Firewall,
    ToolRegistry,
    ToolSecurityEngine,
    ToolCall,
    ToolResult,
    ResultTrustLevel,
    Action,
)

# Initialize registry and tools
registry = ToolRegistry()
registry.register_tool(
    name="query_database",
    schema={
        "type": "object",
        "required": ["query", "limit"],
        "properties": {
            "query": {"type": "string", "minLength": 5},
            "limit": {"type": "integer", "minimum": 1, "maximum": 50},
        },
    },
)

fw = Firewall(tool_registry=registry)

# Evaluate tool invocation
call_decision = fw.check_tool_call(
    "query_database",
    arguments={"query": "SELECT id, name FROM users", "limit": 10},
)
if call_decision.is_allowed:
    # Execute tool safely
    raw_output = "User Alice: alice@example.com"
    
    # Evaluate result
    result_decision = fw.check_tool_result(
        "query_database",
        raw_output,
    )
    print("Decision:", result_decision.action)
    print("Sanitized Output:", result_decision.sanitized_output)
```
