# AI Security Knowledge Graph (Phase 32)

The **AI Security Knowledge Graph** provides a lightweight, local, and extensible graph-based security model for representing relationships across the entire AI software development lifecycle: applications, models, agents, tools, prompts, policies, security controls, RAG sources, documents, dependencies, findings, threats, attack techniques, security tests, baselines, releases, and incidents.

---

## 1. Architectural Principles

### Zero External Graph Database Mandate
LLMFirewall does **NOT** require Neo4j, Redis Graph, PostgreSQL, or cloud database infrastructure. The core graph engine runs:
- Completely local and in-process.
- In-memory by default (`InMemoryGraphStore`) with sub-microsecond point lookups.
- Optionally backed by standard zero-dependency local SQLite (`SQLiteGraphStore`).

```text
                  KnowledgeGraph
                        │
         ┌──────────────┴──────────────┐
         ↓                             ↓
InMemoryGraphStore             SQLiteGraphStore
  (Default, thread-safe)         (Local file persistence)
```

### Deterministic Node Identity
Node identifiers are deterministic, human-readable, and stable across rediscovery (e.g. `agent:support_assistant`, `model:gpt-4o`, `tool:web_search`, `finding:SEC-01`, `control:prompt_shield`), rather than ephemeral random UUIDs.

### Zero Secret Infiltration
Node properties, relationship metadata, and snapshots strictly enforce secret sanitization. Keys matching credential patterns (`api_key`, `token`, `password`, `secret`, `private_key`) are immediately rejected.

---

## 2. Graph Taxonomy

### Node Types
The graph standardizes on a taxonomy of AI security entities:

| Node Type | Description | Example Identity |
| :--- | :--- | :--- |
| `application` | Top-level AI software service or system | `app:customer_portal` |
| `agent` | Autonomous or semi-autonomous AI agent | `agent:triage_bot` |
| `model` | Underlying foundation or fine-tuned model | `model:gpt-4o` |
| `tool` | Tool or function accessible by agents | `tool:database_query` |
| `prompt` | System prompt or versioned template | `prompt:system_v2` |
| `policy` | Security policy document | `policy:enterprise_guardrails` |
| `security_control` | Defensive guardrail or detection module | `control:prompt_shield` |
| `rag_source` | Vector store or knowledge base | `rag:compliance_kb` |
| `document` | Knowledge document or chunk reference | `doc:iso27001_sec5` |
| `dependency` | Python package or AI library | `dep:langchain_core` |
| `finding` | Security defect or vulnerability finding | `finding:sec_tool_01` |
| `threat` | Threat vector or category | `threat:indirect_injection` |
| `attack_technique` | MITRE ATLAS or adversarial technique | `technique:aml_t0051` |
| `security_test` | Automated security or red-team test | `test:pi_regression_01` |
| `baseline` | Cryptographically anchored security baseline | `baseline:v2.4_release` |
| `release` | Software release or deployment milestone | `release:2026.09.1` |
| `incident` | Production security event or breach | `incident:inc_987` |
| `capability` | Granular agent capability permission | `capability:network_egress` |
| `configuration` | Security or runtime configuration | `config:firewall_prod` |

### Relationship Types
Directed edges represent structural, governance, control, and testing relationships:

```text
USES            : Asset relies on another asset (App -> Agent, Agent -> Model)
CAN_CALL        : Agent possesses permission to invoke a tool (Agent -> Tool)
CAN_ACCESS      : Agent possesses capability access (Agent -> Capability)
GOVERNED_BY     : Asset is subject to policy constraints (Agent -> Policy)
GOVERNS         : Policy enforces rules on an asset (Policy -> Agent)
PROTECTED_BY    : Asset is defended by a security control (Agent -> Control)
PROTECTS        : Security control defends an asset (Control -> Agent)
DEPENDS_ON      : Asset depends on supply-chain package (App -> Dependency)
CONTAINS        : Container contains elements (Release -> Model, RAG -> Document)
GENERATED_FROM  : Response provenance origin (Response -> Document)
TESTED_BY       : Control or model evaluated by test (Control -> Test)
TESTS           : Test evaluates control or asset (Test -> Control)
HAS_FINDING     : Asset exhibits an active security finding (Agent -> Finding)
AFFECTS         : Finding impairs an asset (Finding -> Tool)
MITIGATED_BY    : Finding resolved or mitigated by control (Finding -> Control)
MITIGATES       : Control neutralizes a threat (Control -> Threat)
DETECTS         : Test identifies a threat (Test -> Threat)
PRODUCES        : Test generates a finding (Test -> Finding)
BLOCKED_BY      : Release blocked by security gate (Release -> Gate)
PRECEDES        : Directed workflow sequence (NodeA -> NodeB)
```

---

## 3. Query Engine & Graph Analysis

### Shortest Path & Bounded Traversal
Finds the shortest directed connection between two nodes with strict cycle protection:

```python
path = graph.find_path("app:customer_portal", "tool:customer_db", max_depth=4)
# Returns GraphPath(nodes=['app:customer_portal', 'agent:support_copilot', 'tool:customer_db'], length=2)
```

Cycle protection guarantees termination even when circular references (`Agent -> Tool -> Policy -> Agent`) exist.

### Security Impact Analysis
Discovers all related security context around an asset up to a configurable depth:

```python
impact = graph.security_impact("agent:support_copilot", max_depth=2)
# Access associated:
# impact.controls: List of protecting security control IDs
# impact.policies: List of governing policy IDs
# impact.findings: List of active security finding IDs
# impact.tests:    List of evaluating test IDs
# impact.threats:  List of targeting threat IDs
```

### Cascading Blast Radius
Measures downstream reachability when an asset (e.g. foundational model or tool) is compromised or updated:

```python
blast = graph.blast_radius("model:gpt-4o", max_depth=3)
# Returns BlastRadiusResult:
# blast.impacted_applications
# blast.impacted_agents
# blast.impacted_tools
# blast.impacted_policies
# blast.associated_findings
# blast.total_impacted_nodes
```

### Evidence-Based Control Coverage (No Fake Coverage)
Evaluates whether security controls protecting an asset are verified by automated tests:

```python
coverage = graph.control_coverage("agent:support_copilot")
# Categorizes each control as:
# ControlStatus.PASSING     (Automated test evaluated and passed)
# ControlStatus.FAILING     (Automated test failed)
# ControlStatus.TESTED      (Tested without explicit pass/fail property)
# ControlStatus.CONFIGURED  (Registered control without test evidence)
# ControlStatus.UNKNOWN     (Unverified status)
```

---

## 4. Snapshots, Diff & Cryptographic Hash

### Canonical Graph Hashing
Graph snapshots compute a deterministic SHA-256 digest over canonicalized nodes and directed edges:
- Insertion order invariant: graphs populated in reverse or scrambled order yield identical digests.
- Ephemeral timestamp invariant: ignores creation clock drift.

```python
snap = graph.snapshot()
print(snap.graph_hash)  # Deterministic SHA-256 digest
```

### Graph Diff & Security Diff
Compares two graph snapshots to extract structural changes and security-relevant evolutions:

```python
# Structural diff
diff = graph.diff(snap_previous, snap_current)
# diff.nodes_added, diff.nodes_removed, diff.nodes_changed
# diff.relationships_added, diff.relationships_removed

# Curated security-relevant diff
sec_diff = graph.security_diff(snap_previous, snap_current)
# sec_diff.new_tool_access   (New tools granted to agents)
# sec_diff.new_capabilities  (New agent capabilities introduced)
# sec_diff.model_changes     (Model swaps or version changes)
# sec_diff.new_dependencies  (New supply-chain packages)
# sec_diff.new_policies      (New governing policies)
# sec_diff.new_findings      (New vulnerabilities attached)
# sec_diff.removed_controls  (Security controls deleted)
# sec_diff.has_security_impact (True if any critical change occurred)
```

---

## 5. Command-Line Interface (CLI)

The CLI provides commands for graph inspection, queries, and CI/CD integration:

```bash
# List graph nodes (with optional type filtering)
llmfirewall graph nodes --type agent

# List directed relationships
llmfirewall graph relationships --type CAN_CALL

# Inspect details and adjacent connections of a node
llmfirewall graph show agent:support_copilot

# Trace directed path between two entities
llmfirewall graph path app:customer_portal tool:customer_db

# Run security impact analysis
llmfirewall graph impact agent:support_copilot

# Run cascading blast radius analysis
llmfirewall graph impact model:gpt-4o --mode blast

# Run control coverage assessment
llmfirewall graph impact agent:support_copilot --mode coverage

# Machine-readable JSON output for CI/CD pipelines
llmfirewall graph impact agent:support_copilot --json

# Export and import graphs
llmfirewall graph export --output security_graph.json
llmfirewall graph import security_graph.json
```

---

## 6. Threat Model & Graph Security

| Threat | Risk Description | Mitigation |
| :--- | :--- | :--- |
| **Graph Poisoning** | Malicious injection of fake controls to bypass governance checks | Evidence-based coverage requires verifiable test linkage (`TESTS` edge + passing test result). |
| **Graph Tampering** | Unauthorized mutation of exported graph JSON files | Cryptographic canonical SHA-256 graph digest detects modification. |
| **Relationship Injection** | Rogue edges granting undeclared tool access to agents | Validation enforces existing source/target endpoints and registered types; `security_diff` alerts on `new_tool_access`. |
| **Traversal DoS** | Deep cyclic or dense graphs causing infinite recursion or stack exhaustion | Breadth-First and Depth-First searches strictly enforce `max_depth` (default 8) and cycle tracking. |
| **Oversized Import DoS** | Massive JSON files intended to consume server memory | Hard 50MB file size limit and configurable `max_nodes` / `max_relationships` bounds. |
| **Sensitive Data Leakage** | Storing raw private keys, passwords, or PII in graph properties | Automatic property validator rejects credential keys (`api_key`, `password`, `secret`, `token`, `credential`). |
| **Stale Graph Data** | Outdated representation masking new vulnerabilities | Snapshots include `timestamp` and `graph_version`; integration with Phase 28 drift detection flags discrepancies. |
| **False Relationships** | Inaccurate claims that a control or test applies to an asset | Strict relationship validation ensures endpoints exist and match expected types. |

---

## 7. Performance Benchmarks

Measured on standard hardware (macOS, Python 3.12):

| Scale | Node Rate | Edge Rate | Lookup Latency | Path Search (d=4) | Impact Query | Blast Radius | Snapshot & Hash | Memory (RSS) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1,000 Nodes** | 56,000/sec | 52,000/sec | 0.41 µs | 0.017 ms | 0.017 ms | 0.031 ms | 3.43 ms | +12.1 MB |
| **10,000 Nodes** | 45,000/sec | 40,000/sec | 0.51 µs | 0.019 ms | 0.019 ms | 0.041 ms | 82.10 ms | +116.3 MB |
| **50,000 Nodes** | 42,000/sec | 40,000/sec | 0.61 µs | 0.019 ms | 0.021 ms | 0.045 ms | 216.69 ms | +508.7 MB |

---

## 8. Extensibility & Customization

Custom node and relationship types can be registered dynamically at runtime without modifying LLMFirewall source code:

```python
from llmfirewall.graph import KnowledgeGraph

graph = KnowledgeGraph()
graph.register_node_type("custom_sensor")
graph.register_relationship_type("TRANSMITS_TO")

node = graph.add_node("sensor:01", node_type="custom_sensor")
```

Custom persistent backends can be created by subclassing `GraphStore` and implementing the required CRUD and neighbor retrieval methods.
