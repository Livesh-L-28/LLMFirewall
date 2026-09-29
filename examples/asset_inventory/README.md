# AI Asset Inventory & Continuous Discovery Example (Phase 34)

This example demonstrates how **LLMFirewall** maintains an authoritative, continuously refreshable inventory of AI components, tracks multi-source provenance, detects architectural drift, and feeds the Security Knowledge Graph and Attack Graph.

---

## Architecture

```text
Customer Support AI
        │
 ┌──────┼────────┐
 ↓      ↓        ↓
Agent  Model    RAG
 │      │        │
 ├──Tool│        └──Vector Store
 └──API │
        └──Provider
```

---

## Running the Example

Run the demonstration script:

```bash
python3 examples/asset_inventory/application.py
```

Or run via the LLMFirewall CLI:

```bash
# Discover live assets in the active workspace
llmfirewall inventory discover

# List all discovered assets
llmfirewall inventory list

# View the exported demo inventory
llmfirewall inventory list --inventory examples/asset_inventory/inventory_export.json

# Inspect security exposure for the support agent
llmfirewall inventory show agent:support_agent --inventory examples/asset_inventory/inventory_export.json
```

---

## Key Scenarios Demonstrated

1. **Multi-Source Discovery**:
   Discovers AI components from static configuration, runtime telemetry, dependency manifests, and static code.
2. **Deterministic Fingerprinting & Normalization**:
   Calculates 64-character SHA-256 fingerprints over normalized attributes for reliable change detection.
3. **Multi-Source Provenance Merging**:
   Combines configuration declarations and runtime observations without data loss, tracking every source in an auditable trail.
4. **Conflict & Drift Tracking**:
   Explicitly captures version and configuration discrepancies (e.g. Configured 1.0.0 vs Runtime Observed 1.1.0).
5. **Knowledge Graph & Attack Surface Integration**:
   Automatically populates the Phase 32 Security Knowledge Graph with nodes and inferred edges, feeding Phase 33 multi-step attack path evaluation.
6. **Baseline Snapshots & Diffing**:
   Generates tamper-evident baseline snapshots with cryptographic digests and computes architectural diffs (`assets_added`, `assets_removed`, `assets_changed`).
