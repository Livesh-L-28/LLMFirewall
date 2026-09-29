# Discovery Providers Reference

## 1. Architecture & Provider Interface

Every discovery source in LLMFirewall implements the abstract [DiscoveryProvider](file:///Users/livesh/LLMFirewall/src/llmfirewall/inventory/providers/base.py) interface:

```python
class DiscoveryProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Unique provider identifier (e.g. 'config_discovery')."""
        pass

    @property
    @abstractmethod
    def source_type(self) -> AssetSource:
        """Classification source enum (e.g. AssetSource.CONFIGURATION)."""
        pass

    @abstractmethod
    def discover(self) -> List[Asset]:
        """Perform discovery and return normalized Asset instances."""
        pass
```

### Fault Isolation & Resilience
The [DiscoveryEngine](file:///Users/livesh/LLMFirewall/src/llmfirewall/inventory/engine.py) orchestrates registered providers within isolated execution blocks. If an individual provider encounters network issues, file permission errors, or unhandled exceptions:
- The error is captured in `provider_results[provider.name]["error"]`.
- A warning is recorded in `warnings`.
- The overall discovery cycle completes with `DiscoveryStatus.PARTIAL`.
- Successfully discovered assets from healthy providers are retained and registered.

---

## 2. Built-in Discovery Providers

### 2.1 ConfigDiscoveryProvider
- **Source**: `AssetSource.CONFIGURATION`
- **Confidence**: `DiscoveryConfidence.HIGH`
- **Module**: `llmfirewall.inventory.providers.config`
- **Scope**:
  - Inspects active `FirewallConfig`, discovering the orchestrator application asset (`application:firewall`).
  - Discovers active security policies (`policy:<policy_name>`).
  - Discovers active detectors and guardrails (`security_control:control:<detector_name>`).
  - Discovers registered agent tools and granted capabilities.
  - Safely reads raw configuration models, agents, databases, and vector stores without connecting to remote systems.

### 2.2 EnvironmentDiscoveryProvider
- **Source**: `AssetSource.ENVIRONMENT`
- **Confidence**: `DiscoveryConfidence.HIGH`
- **Module**: `llmfirewall.inventory.providers.env`
- **Scope**:
  - Scans environment variables for known AI provider markers (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `COHERE_API_KEY`, `AWS_BEDROCK_REGION`, `OLLAMA_HOST`, etc.).
  - Extracts model provider assets (e.g. `provider:openai`, `provider:anthropic`).
  - **CRITICAL SECURITY GUARANTEE**: Never stores or exposes the secret values. Registers only `{"configured": True}`.

### 2.3 DependencyDiscoveryProvider
- **Source**: `AssetSource.DEPENDENCY_MANIFEST`
- **Confidence**: `DiscoveryConfidence.HIGH`
- **Module**: `llmfirewall.inventory.providers.dependencies`
- **Scope**:
  - Uses offline `importlib.metadata` to inspect installed Python packages without executing package code.
  - Recognizes AI ecosystem packages (`openai`, `anthropic`, `transformers`, `torch`, `langchain`, `fastapi`, `pydantic`, `uvicorn`, etc.).
  - Captures package names and installed versions.

### 2.4 CodeDiscoveryProvider
- **Source**: `AssetSource.CODE`
- **Confidence**: `DiscoveryConfidence.MEDIUM`
- **Module**: `llmfirewall.inventory.providers.code`
- **Scope**:
  - Performs static, conservative AST inspection of Python source files without executing code.
  - Identifies client SDK instantiations (`OpenAI(...)`, `Anthropic(...)`, `AutoModelForCausalLM.from_pretrained(...)`, `FastAPI(...)`).
  - Extracts model identifier strings from call arguments when statically resolvable.
  - Gracefully ignores syntax errors or unsupported constructs.

### 2.5 ImportDiscoveryProvider
- **Source**: `AssetSource.USER_REGISTERED`
- **Confidence**: `DiscoveryConfidence.HIGH`
- **Module**: `llmfirewall.inventory.providers.import_provider`
- **Scope**:
  - Imports pre-computed inventory files in JSON or YAML format.
  - **Security Constraints**:
    - Rejects files larger than 10MB to prevent memory exhaustion attacks.
    - Employs safe parsing (`json.loads`, `yaml.safe_load`).
    - Validates schema against the normalized `Asset` model.

### 2.6 RuntimeDiscoveryProvider
- **Source**: `AssetSource.RUNTIME`
- **Confidence**: `DiscoveryConfidence.HIGH`
- **Module**: `llmfirewall.inventory.providers.runtime`
- **Scope**:
  - Ingests structured telemetry events emitted during request evaluation (`agent_invocation`, `tool_execution`, `model_request`, `rag_access`).
  - Updates `last_seen` timestamps on active assets.
  - Discovers dynamic agents, tools, and endpoints invoked at runtime without capturing sensitive prompt payloads.

### 2.7 ManualDiscoveryProvider
- **Source**: `AssetSource.USER_REGISTERED`
- **Confidence**: `DiscoveryConfidence.HIGH`
- **Module**: `llmfirewall.inventory.providers.manual`
- **Scope**:
  - Tracks assets registered directly via `inventory.register(asset)`.

---

## 3. Implementing a Custom Discovery Provider

To add a domain-specific discovery source (e.g. Kubernetes, AWS ECS, or internal service catalog):

```python
from typing import List
import time
from llmfirewall import (
    Asset,
    AssetProvenance,
    AssetSource,
    AssetStatus,
    AssetType,
    DiscoveryConfidence,
    DiscoveryProvider,
)

class CloudCatalogDiscoveryProvider(DiscoveryProvider):
    @property
    def name(self) -> str:
        return "cloud_catalog_discovery"

    @property
    def source_type(self) -> AssetSource:
        return AssetSource.API

    def discover(self) -> List[Asset]:
        assets: List[Asset] = []
        now = time.time()

        # Query catalog safely without secret retrieval
        services = [
            {"id": "doc-retriever", "type": "rag_source", "name": "Documentation RAG"}
        ]

        for s in services:
            prov = AssetProvenance(
                source=self.source_type,
                provider_name=self.name,
                reference="cloud_catalog:services",
                observed_at=now,
            )
            assets.append(
                Asset.create(
                    asset_id=f"rag_source:{s['id']}",
                    asset_type=AssetType.RAG_SOURCE.value,
                    name=s["name"],
                    source=self.source_type,
                    status=AssetStatus.ACTIVE,
                    confidence=DiscoveryConfidence.HIGH,
                    provenance=[prov],
                )
            )

        return assets
```

Register the custom provider with the firewall inventory:

```python
from llmfirewall import Firewall

fw = Firewall()
fw.inventory.discovery_engine.register_provider(CloudCatalogDiscoveryProvider())
result = fw.inventory.discover()
```
