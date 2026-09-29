# Attack Path Analysis (Phase 33)

**Attack Path Analysis** enables LLMFirewall to trace, evaluate, and test multi-step traversal chains through an AI architecture leading to potential compromise.

---

## 1. Traversal Engine & Algorithmic Bounds

The traversal engine uses a bounded Breadth-First Search (BFS) over the `KnowledgeGraph`, evaluating applicable `AttackRule` sets at each hop.

To prevent algorithmic complexity and path-explosion denial-of-service, all traversals enforce strict bounds:

```python
paths = attack_graph.find_paths(
    source="app:chat",
    target="tool:customer_db",
    max_depth=5,              # Maximum hop count (clamped 1-20)
    max_paths=100,            # Maximum paths returned (clamped 1-1000)
    max_nodes_visited=5000,   # Resource traversal cap (clamped 10-50000)
    timeout=10.0,             # Wall-clock timeout in seconds (clamped 0.1-60.0)
)
```

### Cycle Handling
Real-world AI architectures frequently contain cycles:
```text
Agent A  ──[CALLS]──>  Agent B  ──[CALLS]──>  Agent A
Agent    ──[CAN_CALL]─> Tool     ──[RETURNS]──> Agent
```
The traversal queue maintains a `visited_node_ids` set for each active candidate branch. A node cannot be revisited within the same path sequence, completely eliminating infinite loops.

### Deterministic Path Deduplication
Identical multi-step paths discovered through redundant graph traversals are deduplicated using a SHA-256 fingerprint over normalized hop sequences:

```python
combined = f"{source}::{'->'.join(step_keys)}::{target}"
path_id = f"PATH-{sha256(combined)[:12].upper()}"
```

---

## 2. Multi-Step Test Corroboration (Phase 30 Integration)

When automated security test results or red-team suites from Phase 30 are ingested:

```python
test_results = [
    {"technique": "T-PI-01", "target": "agent:lead", "passed": True, "test_id": "TEST-PI-01"},
    {"technique": "T-TA-04", "target": "tool:sql", "passed": True, "test_id": "TEST-TA-02"},
]

tested_paths = attack_graph.ingest_test_results(test_results)
```

### Strict Test Rule
> **A multi-step path is ONLY upgraded to `TESTED` if automated tests demonstrate every single hop in the chain.**

If Step A is tested but Step B is untested, the path remains `CANDIDATE`. LLMFirewall never infers successful compromise of unverified downstream steps.

---

## 3. Production Runtime Telemetry (Observability Integration)

When runtime telemetry events or SIEM alerts confirm a sequence of adversarial events in production:

```python
events = [
    {"event_type": "PROMPT_INJECTION_DETECTED", "technique": "T-PI-01", "timestamp": time.time()},
    {"event_type": "UNAUTHORIZED_TOOL_INVOKED", "technique": "T-TA-04", "timestamp": time.time() + 1},
]

observed_paths = attack_graph.ingest_runtime_events(events)
```

Paths matching the observed sequence transition to `OBSERVED`, preserving exact event IDs and timestamps as verified `AttackEvidence`.

---

## 4. Snapshots & Architectural Drift Diffs

Attack Graph snapshots provide a tamper-evident audit record of the attack surface at a specific point in time:

```python
# Baseline snapshot
snap_v1 = attack_graph.snapshot(graph_version="1.0")

# Architecture changes (e.g. new tool added to agent)
kg.add_node("tool:admin_shell", "tool")
kg.add_relationship("agent:bot", "CAN_CALL", "tool:admin_shell")

# New snapshot & diff
snap_v2 = attack_graph.snapshot(graph_version="1.1")
diff = AttackGraph.diff(snap_v1, snap_v2)

print(f"New Attack Paths: {diff.paths_added}")
print(f"Resolved Paths: {diff.paths_removed}")
print(f"Changed Paths: {diff.paths_changed}")
```

---

## 5. CLI Query Commands

### List All Candidate Attack Paths
```bash
llmfirewall attack paths
```

### Output in JSON Format
```bash
llmfirewall attack paths --format json
```

### Output in SARIF 2.1.0 (for CI/CD Release Gates)
```bash
llmfirewall attack paths --format sarif
```

### Target Query Between Two Assets
```bash
llmfirewall attack path --source agent:support --target tool:crm_db
```
