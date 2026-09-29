# AI Threat Modeling (Phase 33)

LLMFirewall provides automated, evidence-backed **AI Threat Modeling** directly derived from the AI Security Knowledge Graph and Attack Graph analysis.

---

## 1. Overview

Traditional threat modeling for AI systems is frequently manual, disconnected from actual runtime architectures, and either produces speculative claims or misses multi-hop agent-to-tool attack chains.

LLMFirewall solves this by automatically assembling a comprehensive, auditable `ThreatModel` from real component topologies:

```text
Threat Model: Customer Support Agent
====================================
Model ID: TM-88F4A19B | Version: 1.0

Entry Points:
  - Chat API (CHAT_INPUT) -> target: app:customer_portal
  - Document Ingestion (DOCUMENT_INGESTION) -> target: rag:faq_store

Assets:
  - agent:support_bot
  - app:customer_portal
  - capability:database_read
  - rag:faq_store
  - tool:crm_query

Trust Boundaries:
  - user → app:customer_portal (untrusted -> trusted_input)
  - agent:support_bot → tool:crm_query (agent_reasoning -> external_side_effects)

Candidate Attack Paths (2):
  1. app:customer_portal → agent:support_bot → tool:crm_query [SUPPORTED] (Mitigation: UNMITIGATED)
  2. rag:faq_store → agent:support_bot [CANDIDATE] (Mitigation: MITIGATED)

Controls:
  - control:prompt_injection_detector
  - control:rag_scanner

Unverified Assumptions:
  - CRM tool accepts agent-generated parameters without independent server-side validation.

SECURITY GAPS: 1 unmitigated attack path(s) detected!
```

---

## 2. In-Scope AI Asset Classes

LLMFirewall threat models automatically identify and scope all connected Phase 32 assets without manual duplication:

| Asset Class | Description | Example Identity |
| :--- | :--- | :--- |
| `Application` | High-level service or web interface | `app:web_portal` |
| `Agent` | Autonomous or worker AI agent | `agent:triage_bot` |
| `Model` | Foundation model or weights | `model:gpt-4o` |
| `Tool` | Function or side-effect integration | `tool:sql_exec` |
| `Capability` | Authorized permission boundary | `capability:payment_refund` |
| `RAG Source` | Retrieval knowledge base or index | `rag:enterprise_docs` |
| `Document` | Ingested file or knowledge chunk | `doc:customer_contract` |
| `Memory` | Agent persistent or scratch memory | `memory:user_profile` |
| `Dependency` | Upstream package or library | `dep:langchain_community` |
| `Security Control` | Active detector, sanitizer, or gate | `control:prompt_shield` |

---

## 3. Trust Boundaries

Trust boundaries mark demarcation lines where security context, privilege, or trust assumptions change:

1. **User / External API → Application Ingress**: Untrusted data enters the perimeter.
2. **Application → Agent Reasoning Context**: User payload enters prompt template.
3. **Agent → Tool Invocation Boundary**: Unchecked LLM reasoning attempts external side-effects.
4. **Tool → Sensitive Storage / Enterprise API**: Direct command or query against protected data stores.
5. **Agent A → Agent B (Multi-Agent)**: Inter-agent messaging crossing privilege compartments.

---

## 4. Entry Points

Ingress vectors are identified automatically or declared explicitly:

- `HTTP_API`: Public or internal REST/gRPC endpoints.
- `CHAT_INPUT`: Direct user conversational interfaces.
- `FILE_UPLOAD`: User-submitted documents, PDFs, images.
- `DOCUMENT_INGESTION`: Automated pipelines fetching external web pages or s3 objects.
- `TOOL_INPUT`: Webhook callbacks or external tool response payloads.
- `MCP_INPUT`: Model Context Protocol tool or resource inputs.
- `AGENT_MESSAGE`: Messages received from peer agents in multi-agent workflows.

---

## 5. Security Gaps to Governance Findings

When an attack path has no applicable, passing security control (`mitigation_status == UNMITIGATED`), LLMFirewall classifies it as a **Security Gap**.

Security Gaps are converted into `GovernanceFinding` objects:
- **Category**: `ATTACK_SURFACE_SECURITY_GAP`
- **Severity**: `HIGH`
- **Resource**: Target asset ID
- **Lifecycle Tracking**: Tracked across CI runs, subject to release gate thresholds and security baselines.

---

## 6. CLI Usage

### Generate System Threat Model
```bash
llmfirewall threat-model
```

### Scope Threat Model to Specific Asset
```bash
llmfirewall threat-model --asset agent:customer_support
```

### Export Machine-Readable Threat Model (JSON / YAML)
```bash
llmfirewall threat-model export --output threat_model.json --format json
llmfirewall threat-model export --output threat_model.yaml --format yaml
```

---

## 7. Python API

```python
from llmfirewall import Firewall, FirewallConfig

fw = Firewall(config=FirewallConfig())
fw.build_security_graph()

# Generate threat model
tm = fw.generate_threat_model(asset_id="agent:support")

print(f"Total Attack Paths: {len(tm.attack_paths)}")
print(f"Security Gaps: {tm.security_gaps_count}")

# Export JSON
json_doc = tm.to_json(indent=2)
```
