# AI Asset Inventory & Discovery

## 1. Overview

**Phase 34 — AI Asset Inventory & Discovery** establishes an authoritative, continuously refreshable asset discovery and inventory layer for **LLMFirewall**.

As AI architectures evolve rapidly from single prompts into compound multi-agent systems, organizations face critical visibility gaps:
- *What AI assets actually exist across configuration, code, dependencies, and runtime?*
- *Where did each asset come from, and what is its provenance?*
- *What models, tools, RAG document stores, or APIs is each agent connected to?*
- *Who or what can access these assets?*
- *What security controls and policies apply to them?*
- *What components are unknown, stale, or drifting from baseline?*

Rather than maintaining a disconnected external asset database, LLMFirewall implements a unified pipeline:

```text
                        LLMFirewall
                             │
                             ↓
                   ASSET DISCOVERY
                             │
         ┌───────────────────┼───────────────────┐
         ↓                   ↓                   ↓
     Configuration       Dependencies        Runtime / Code
         │                   │                   │
         └───────────────────┼───────────────────┘
                             ↓
                      NORMALIZATION
                             │
                             ↓
                    ASSET INVENTORY
                             │
             ┌───────────────┼───────────────┐
             ↓               ↓               ↓
           Assets         Provenance        Status
             │
             ↓
                 KNOWLEDGE GRAPH (Phase 32)
                      │
             ┌────────┴────────┐
             ↓                 ↓
       ATTACK GRAPH        GOVERNANCE (Phase 31)
       (Phase 33)              │
             │                 ↓
             ↓             Baselines
      Attack Paths         Findings
      Threat Models            │
             │                 │
             └────────┬────────┘
                      ↓
               SECURITY POSTURE
                   (Phase 35)
```

---

## 2. Core Architectural Principles

1. **No Disconnected Database**: The inventory discovers and normalizes assets; the Phase 32 [KnowledgeGraph](file:///Users/livesh/LLMFirewall/src/llmfirewall/graph/engine.py) models their graph relationships; and the Phase 33 [AttackGraph](file:///Users/livesh/LLMFirewall/src/llmfirewall/graph/attack.py) analyzes multi-step attack paths.
2. **Deterministic Identity**: Asset IDs are stable and domain-prefixed (e.g., `agent:customer-support`, `model:gpt-4o`, `package:pydantic:2.13.5`), preventing asset duplication on successive discovery cycles.
3. **Deterministic Fingerprints**: Every asset computes a canonical SHA-256 fingerprint over its identity, type, version, environment, and sorted metadata to reliably detect meaningful architectural changes.
4. **Zero Secret Infiltration**: Credentials, API keys, passwords, and private tokens are recursively sanitized before ingestion or persistence.
5. **Multi-Source Provenance**: When multiple discovery sources identify the same asset (e.g. Config + Runtime), metadata is safely merged while preserving historical source provenance.
6. **Conflict Transparency**: Differences between configured and observed attributes (such as version mismatches) are recorded explicitly as `AssetConflict` entries rather than silently discarded.
7. **Fault Isolation**: If one discovery provider fails, the overall discovery process does not crash; it reports `DiscoveryStatus.PARTIAL` and registers all assets discovered by healthy providers.
8. **Defensive Non-Goals**: Discovery is strictly passive and defensive. It **never** scans arbitrary internet ports, executes discovered code, exploits targets, or queries remote databases without permission.

---

## 3. Normalized Asset Model

Every asset in the inventory conforms to the normalized [Asset](file:///Users/livesh/LLMFirewall/src/llmfirewall/inventory/models.py) schema:

| Field | Type | Description |
|---|---|---|
| `id` | `str` | Stable canonical identifier (e.g., `agent:support`, `model:gpt-4o`). |
| `type` | `str` | Classification type from `AssetType` (23 standard types or custom). |
| `name` | `str` | Human-readable name. |
| `version` | `Optional[str]` | Version or release tag. |
| `environment` | `str` | Operational environment (`development`, `testing`, `staging`, `production`, `unknown`). |
| `source` | `AssetSource` | Primary source (`CONFIGURATION`, `RUNTIME`, `CODE`, `DEPENDENCY_MANIFEST`, etc.). |
| `status` | `AssetStatus` | Lifecycle status (`ACTIVE`, `INACTIVE`, `STALE`, `REMOVED`, `UNKNOWN`). |
| `metadata` | `Dict[str, Any]` | Sanitized attributes (max 64KB, credentials redacted). |
| `first_seen` | `float` | Epoch timestamp of initial discovery. |
| `last_seen` | `float` | Epoch timestamp of most recent observation. |
| `tags` | `List[str]` | User-assigned classification tags (`ai`, `critical`, `external`). |
| `owner` | `Optional[str]` | Team or service owner identifier. |
| `confidence` | `DiscoveryConfidence` | Reliability of source (`HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`). |
| `provenance` | `List[AssetProvenance]` | Audit trail of all discovery sources confirming this asset. |
| `conflicts` | `List[AssetConflict]` | Discrepancies observed across different sources. |
| `fingerprint` | `str` | 64-character SHA-256 fingerprint for change detection. |

---

## 4. Lifecycle & Freshness Tracking

Assets progress through controlled lifecycle states:

```text
[NEW DISCOVERY] ──────> ACTIVE
                          │
            threshold     │  re-observed
             elapsed      ↓  in runtime
                        STALE ────────> ACTIVE
                          │
                   explicit removal
                     provenance
                          ↓
                       REMOVED
```

- **ACTIVE**: Observed within the freshness threshold (default 7 days).
- **STALE**: Not re-observed within the freshness threshold. Stale assets remain in inventory and graph for governance visibility but are flagged during diffs.
- **REMOVED**: Decommissioned or confirmed removed by an authoritative source.
- **Revitalization**: An asset previously marked `STALE` or `REMOVED` automatically transitions back to `ACTIVE` upon fresh observation.

---

## 5. Security Exposure & Attack Surface Integration

The inventory integrates directly with Phase 32 ([KnowledgeGraph](file:///Users/livesh/LLMFirewall/src/llmfirewall/graph/engine.py)) and Phase 33 ([AttackGraph](file:///Users/livesh/LLMFirewall/src/llmfirewall/graph/attack.py)) via:

```python
exposure = inventory.attack_surface("agent:customer-support")
```

The resulting [AssetExposure](file:///Users/livesh/LLMFirewall/src/llmfirewall/inventory/models.py) document provides an objective, multi-dimensional view:
- **Ingress Channels**: Network endpoints, user chat, API routes.
- **Accessible Tools**: Tools the agent is authorized to call (`CAN_CALL`).
- **Granted Capabilities**: Explicit capabilities (`filesystem:read`, `sql:execute`).
- **Protecting Controls**: Defenses active on the asset (`PromptInjectionDetector`, `SecretDetector`, `RBAC`).
- **Candidate Attack Paths**: Multi-step graph paths discovered by Phase 33 threat modeling rules.
- **Associated Findings**: Governance findings and vulnerability detections affecting the asset.

---

## 6. Snapshots & Architectural Diffing

Inventories can be exported to tamper-evident baseline snapshots:

```python
# Create baseline snapshot with SHA-256 integrity hash
snapshot = inventory.snapshot()
```

When comparing two snapshots:

```python
diff = AssetInventory.diff(baseline_snapshot, current_snapshot)
```

The diff detects:
- `assets_added`: New components introduced since the baseline.
- `assets_removed`: Decommissioned components.
- `assets_changed`: Components with modified fingerprints or lifecycle states.
- `relationships_changed`: Topological changes in the knowledge graph.
- `configurations_changed`: Parameter modifications on existing assets.

---

## 7. Command-Line Interface (CLI)

### Discover Assets
```bash
# Live discovery across configuration, dependencies, and environment
llmfirewall inventory discover

# Output as machine-readable JSON
llmfirewall inventory discover --format json
```

### List Inventory Assets
```bash
# List all discovered assets
llmfirewall inventory list

# Filter by type or environment
llmfirewall inventory list --type agent
llmfirewall inventory list --environment production

# Export as JSON
llmfirewall inventory list --format json
```

### Inspect Asset & Attack Surface
```bash
# View comprehensive details, provenance, and security exposure
llmfirewall inventory show agent:customer-support

# View as JSON
llmfirewall inventory show agent:customer-support --format json
```

### Export & Diff Baselines
```bash
# Export snapshot to file
llmfirewall inventory export baseline.json

# Compare baseline against current inventory
llmfirewall inventory diff --before baseline.json --after current.json
```

---

## 8. Performance Benchmarks

Measured on macOS (Apple Silicon, Python 3.12):

| Asset Count | Registration Throughput | Deduplication & Merge | Point Lookup Throughput | Snapshot Time | Diff Time | Memory Overhead |
|---|---|---|---|---|---|---|
| **1,000** | 25,776 assets/sec | 18,557 merges/sec | 1,203,247 lookups/sec | 0.73 ms | 0.94 ms | 11.9 MB |
| **10,000** | 23,954 assets/sec | 13,822 merges/sec | 1,305,198 lookups/sec | 11.39 ms | 19.90 ms | 108.0 MB |
| **50,000** | 20,872 assets/sec | 14,560 merges/sec | 1,230,642 lookups/sec | 74.86 ms | 151.68 ms | 243.4 MB |
