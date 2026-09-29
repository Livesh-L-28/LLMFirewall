# AI Asset Inventory Schema Specification

## 1. Schema Overview

LLMFirewall defines versioned, deterministic schemas for asset inventory, discovery reporting, baseline snapshots, drift diffs, and security exposure views.

Schema Version: `1.0.0`

---

## 2. Controlled Taxonomies

### 2.1 AssetType
Extensible string taxonomy of AI components:

```text
application          Autonomous AI app or service orchestrator
agent                Autonomous or semi-autonomous LLM agent
model                Foundational, fine-tuned, or local language model
model_provider       Model provider or hosting infrastructure (OpenAI, Bedrock, etc.)
tool                 Function, tool, or plugin callable by an agent
api                  External or internal REST / GraphQL / gRPC interface
prompt               System prompt or standalone prompt instruction
prompt_template      Parameterized prompt template
rag_source           Retrieval-Augmented Generation pipeline or source
document_store       Storage layer containing unindexed reference documents
document             Individual ingested source document or corpus
memory_store         Session or long-term conversational memory backend
vector_store         Vector database or embedding index
database             Relational or NoSQL database
dependency           Direct or indirect supply-chain library
package              Installed Python or language distribution
container            Container image or deployment artifact
configuration        Security or operational configuration document
policy               Security or governance Policy-as-Code document
security_control     Defensive detector, guardrail, or authorization filter
capability           Explicit granted permission or capability flag
integration          Third-party SaaS or webhook integration
endpoint             Network ingress or egress URI
custom               Extensible custom entity type
```

### 2.2 AssetStatus
```text
ACTIVE      Observed and operational within freshness threshold
INACTIVE    Configured but not currently handling traffic
STALE       Unobserved beyond freshness threshold; pending investigation
REMOVED     Confirmed decommissioned or removed from system
UNKNOWN     Operational state cannot be reliably determined
```

### 2.3 AssetSource
```text
CONFIGURATION        Declared in LLMFirewall or application config
RUNTIME              Observed dynamically in telemetry events
CODE                 Extracted via static source code AST inspection
DEPENDENCY_MANIFEST  Identified in pyproject.toml, requirements, or package metadata
DOCKER               Identified in Dockerfile or container image metadata
ENVIRONMENT          Identified from non-sensitive environment configuration
API                  Discovered via service catalog or API endpoint
PLUGIN               Provided by an integrated extension or plugin
USER_REGISTERED      Explicitly registered by an administrator
GRAPH                Derived from knowledge graph relationship analysis
```

### 2.4 DiscoveryConfidence
```text
HIGH       Direct configuration, lockfile, or authoritative runtime observation
MEDIUM     Conservative static code inspection or heuristic mapping
LOW        Inferred or unverified indirect relationship
UNKNOWN    Confidence level undetermined
```

---

## 3. Schema Definitions

### 3.1 Asset JSON Schema
```json
{
  "id": "agent:customer-support",
  "type": "agent",
  "name": "Customer Support Agent",
  "version": "1.2.0",
  "environment": "production",
  "source": "CONFIGURATION",
  "status": "ACTIVE",
  "metadata": {
    "model": "gpt-4o",
    "tools": ["database_tool", "web_search"],
    "timeout_seconds": 30
  },
  "first_seen": 1790595970.0,
  "last_seen": 1790595975.0,
  "tags": ["ai", "production", "support"],
  "owner": "support-engineering",
  "confidence": "HIGH",
  "provenance": [
    {
      "source": "CONFIGURATION",
      "provider_name": "config_discovery",
      "reference": "config.yaml",
      "observed_at": 1790595970.0,
      "details": {"line": 42}
    }
  ],
  "conflicts": [],
  "fingerprint": "c04c073f10f1bca120fdbaabf08aee3c849e1eccca55b3e44bf39591986b7b5e"
}
```

### 3.2 DiscoveryResult JSON Schema
```json
{
  "status": "COMPLETE",
  "provider_results": {
    "config_discovery": {
      "status": "success",
      "assets_found": 5,
      "duration_ms": 0.42
    },
    "dependency_discovery": {
      "status": "success",
      "assets_found": 12,
      "duration_ms": 45.1
    }
  },
  "assets_discovered": 17,
  "assets_added": 17,
  "assets_changed": 0,
  "assets_removed": 0,
  "warnings": [],
  "duration_ms": 45.52,
  "timestamp": 1790595975.0
}
```

### 3.3 InventorySnapshot JSON Schema
```json
{
  "schema_version": "1.0.0",
  "inventory_version": "1.0",
  "created_at": 1790595975.0,
  "assets_count": 2,
  "assets": [
    {
      "id": "agent:customer-support",
      "type": "agent",
      "name": "Customer Support Agent",
      "fingerprint": "..."
    }
  ],
  "sources": ["CONFIGURATION", "DEPENDENCY_MANIFEST"],
  "graph_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "snapshot_hash": "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0"
}
```

### 3.4 InventoryDiff JSON Schema
```json
{
  "is_identical": false,
  "assets_added": ["tool:analytics_api"],
  "assets_removed": ["model:legacy-v1"],
  "assets_changed": ["agent:customer-support"],
  "relationships_changed": ["knowledge_graph_topology_updated"],
  "sources_changed": ["API"],
  "configurations_changed": ["agent:customer-support"]
}
```

### 3.5 AssetExposure JSON Schema
```json
{
  "asset_id": "agent:customer-support",
  "asset_type": "agent",
  "environment": "production",
  "sources": ["CONFIGURATION"],
  "entry_points": ["api:chat_v1"],
  "tools": ["tool:database_tool"],
  "capabilities": ["sql:read"],
  "security_controls": ["security_control:control:prompt_injection_detector"],
  "attack_paths": [],
  "findings": [],
  "assumptions": ["Tool accepts agent-generated arguments without independent validation."],
  "last_seen": 1790595975.0
}
```

---

## 4. Resource Limits & Hardening Rules

| Constraint | Limit | Description |
|---|---|---|
| `max_asset_id_length` | 256 bytes | Prevents storage exhaustion and log injection. |
| `max_metadata_size` | 64 KB | Serialized metadata threshold per asset. |
| `max_import_size` | 10 MB | Maximum file size for inventory JSON/YAML import. |
| `max_inventory_capacity` | 50,000 assets | Default memory capacity safeguard against DoS. |
| Traversal validation | Strict | Rejects `../` and `..\` directory traversal sequences in IDs. |
| Secret scrubbing | Recursive | Replaces API keys, tokens, and passwords with `[REDACTED_CREDENTIAL]`. |
