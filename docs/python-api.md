# Python API Reference

LLMFirewall provides a unified public API from the root `llmfirewall` package.

---

## 1. Primary Entrypoints

### `Firewall`
The master orchestrator connecting all detection, risk, inventory, graph, compliance, incident, and runtime protection engines.

```python
from llmfirewall import Firewall

fw = Firewall()
```

#### Key Methods:
- `fw.scan(text, **kwargs) -> ScanResult`: Direct prompt/output inspection.
- `fw.check(prompt_or_output, direction="input") -> ScanResult`: Full policy pipeline execution.
- `fw.inspect(prompt=..., tool=..., tool_args=..., output=...) -> RuntimeDecision`: Real-time sub-millisecond evaluation (<1ms).
- `@fw.protect(agent_id=..., raise_on_block=True)`: Decorator guarding agent functions.
- `fw.protect_tool(tool_fn, tool_name=...)`: Wrapper guarding sensitive tools.
- `fw.risk.prioritize(asset_id=...)`: Multi-factor risk analysis.
- `fw.incidents.record_event(...)`: Event ingestion and incident detection.
- `fw.compliance.assess(asset_id=...)`: Evidence-backed compliance mapping.

---

### `Scanner`
Lightweight, standalone text scanner for rapid, zero-overhead threat checking.

```python
from llmfirewall import Scanner

scanner = Scanner()
result = scanner.scan("Explain quantum mechanics")
print(result.is_allowed) # True
```

---

## 2. Core Models & Enums

### `PolicyDecision`
- `Action.ALLOW`: Traffic allowed without alteration.
- `Action.WARN`: Traffic permitted with audit warning.
- `Action.REDACT`: Sensitive tokens or PII replaced with redaction placeholders.
- `Action.BLOCK`: Execution rejected by security policy.

### `SecurityBlockError`
Exception raised by `@fw.protect` or `fw.protect_tool` when an operation is blocked by runtime security policy.

```python
from llmfirewall import SecurityBlockError

try:
    guarded_agent("Drop database")
except SecurityBlockError as err:
    print(f"Blocked: {err.reason}")
```

---

## 3. Subsystem Accessors

Access specialized subsystems through properties on the `Firewall` instance:

```python
fw = Firewall()

# Asset Inventory
fw.inventory.register(...)
fw.inventory.list_assets()

# Security Knowledge Graph
fw.knowledge_graph.add_node(...)
fw.knowledge_graph.find_path(...)

# Attack Graph Engine
fw.attack_graph.find_paths(...)

# AI-SPM Posture Engine
fw.posture.evaluate(...)

# Compliance Engine
fw.compliance.assess(...)

# Risk Prioritization Engine
fw.risk.prioritize(...)

# Incident Response Engine
fw.incidents.list_incidents(...)
fw.incidents.get_timeline(inc_id)
```
