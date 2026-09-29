# Declarative Control Packs & Framework Versioning

LLMFirewall allows compliance frameworks and controls to be defined declaratively in **YAML** or **JSON** control packs.

---

## 1. Declarative Control Pack Schema

A control pack specifies a framework definition and its constituent controls:

```yaml
framework:
  id: company-ai-security
  name: Acme Enterprise AI Security Framework
  version: "1.2.0"
  description: Internal AI compliance baselines for autonomous agents and LLMs.
  source: Acme Information Security

controls:
  - id: AC-01
    title: Agent Tool Authorization & Least Privilege
    category: access_control
    domain: Access Control
    description: All tool executions by autonomous agents must require RBAC authorization.

    requirements:
      - agent tool calls require authorization policies
      - unauthorized tool invocation attempts must be blocked and audited

    evidence:
      - authorization_policy
      - authorization_test
      - production_configuration

    applicability:
      asset_types:
        - agent
        - tool
      environments:
        - production
        - staging

  - id: PS-01
    title: Prompt Injection & Jailbreak Defense
    category: prompt_security
    domain: Prompt Security
    description: Model inputs and prompt templates must be filtered for jailbreak patterns.

    requirements:
      - prompt injection detector active
      - automated jailbreak test suite passing

    evidence:
      - security_control
      - security_test
```

---

## 2. Framework Versioning

Every framework pack must specify:
- `framework.version`: The semantic version of the framework (e.g. `1.2.0`).
- `catalog.catalog_version`: The catalog schema version (e.g. `1.0.0`).

### Immutability & Multi-Version Coexistence
When a framework evolves from `v1.0.0` to `v2.0.0`:
- LLMFirewall keeps framework versions strictly segregated in catalog indexes.
- Historical snapshots continue to point to the exact framework version under which they were assessed.
- Updating a framework does not corrupt or overwrite past compliance baselines.

---

## 3. Strict Safety & Validation Invariants

1. **5MB Maximum Pack Size**: Packs larger than 5MB are rejected to prevent memory exhaustion attacks.
2. **Safe YAML Parsing**: Control packs are parsed strictly using `yaml.safe_load`.
3. **Duplicate Control ID Rejection**: Any duplicate control IDs within the same pack raise a validation error.
4. **Secret Scrubbing**: Any credential strings (e.g. `sk-`, `ghp_`, API keys) embedded in pack metadata are automatically redacted upon loading.
5. **Checksum Calculation**: Every framework pack computes an authoritative SHA-256 digest of its canonical controls.

---

## 4. CLI & Programmatic Loading

### Programmatic
```python
from llmfirewall.compliance import ControlCatalog

catalog = ControlCatalog()
fw = catalog.load_pack_from_file("path/to/custom_pack.yaml")
print(f"Loaded {len(fw.controls)} controls with checksum {fw.checksum}")
```

### Exporting Control Packs
```python
catalog.export_pack_to_file("company-ai-security", "exported_pack.yaml", format_type="yaml")
```
