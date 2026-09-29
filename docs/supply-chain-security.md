# AI Supply-Chain Security

LLMFirewall Phase 28 introduces unified AI supply-chain protection, tracking the lineage and verifying the integrity of models, dependencies, configurations, and prompt assets.

---

## Architecture

```text
                  AI APPLICATION
                       │
        ┌──────────────┼──────────────┐
        ↓              ↓              ↓
   Dependencies      Models       Config/Policy
        │              │              │
        ↓              ↓              ↓
    Inventory       Verify        Integrity
        │              │              │
        └──────────────┼──────────────┘
                       ↓
                 Policy Engine
                       │
                Security Decision
                       │
          ┌────────────┼────────────┐
          ↓            ↓            ↓
        ALLOW         WARN        BLOCK
```

---

## Core Invariants

1. `UNVERIFIED MODEL ≠ TRUSTED MODEL`
2. `UNKNOWN INTEGRITY ≠ VALID INTEGRITY`
3. `MODEL METADATA ≠ SECURITY AUTHORITY`
4. `DEPENDENCY INVENTORY ≠ VULNERABILITY VERIFICATION`
5. `POLICY CONFIGURATION ≠ SECRET VALUES`

---

## 1. Offline Dependency Inventory & Scanning

LLMFirewall inspects the installed Python environment via standard `importlib.metadata` without requiring outbound internet calls:

```python
from llmfirewall import DependencyScanner

scanner = DependencyScanner(
    blocked_packages=["malicious-lib"],
    allowed_packages=None
)

# Discover installed packages offline
deps = scanner.scan_environment()
findings = scanner.evaluate_dependencies(deps)
```

### CLI Command

```bash
llmfirewall supply-chain scan --offline
llmfirewall supply-chain dependencies --format table
```

---

## 2. CycloneDX & Normalized SBOM Export

Generate machine-readable software bills of materials (SBOM) without exposing secrets:

```bash
llmfirewall supply-chain sbom --format cyclonedx --output sbom.json
```

---

## 3. Configuration & Policy Drift Detection

Deterministic, secret-safe hashing detects unexpected tampering with hyperparameters, policies, or system prompts:

```python
from llmfirewall import Firewall, hash_configuration

fw = Firewall()

# Capture baseline
base_cfg = hash_configuration({"temperature": 0.7, "top_p": 0.9}, config_type="inference_params")
fw.integrity_manager.set_baseline_config(base_cfg)

# Check drift at runtime
drift = fw.integrity_manager.check_config_drift({"temperature": 1.9, "top_p": 0.9}, config_type="inference_params")
if drift:
    print(f"Drift detected: {drift.description}")
```

---

## 4. AI Security Snapshot

Produce a deterministic cryptographic fingerprint of your complete AI deployment state:

```python
snapshot = fw.create_security_snapshot(application_version="1.0.0")
print("Fingerprint:", snapshot.snapshot_hash)
```

Compare snapshots between staging and production:

```bash
llmfirewall supply-chain diff snapshot_baseline.json snapshot_candidate.json
```

---

## 5. Threat Model

| Threat | Description | Mitigation |
|---|---|---|
| **Model Tampering** | Bit-level manipulation of weights | Streaming SHA-256 / SHA-512 verification with constant-time equality check |
| **Model Substitution** | Swapping an approved model with a backdoored artifact | Manifest validation and hash pinning |
| **Dependency Confusion** | Installing untrusted packages from unvetted indices | Offline dependency inventory and source origin classification |
| **Configuration Drift** | Unauthorized runtime hyperparameter adjustments | Deterministic, secret-redacted configuration hashing |
| **Prompt Template Tampering** | Modifying system guardrails in production | Cryptographic prompt asset digest tracking |

---

## 6. Limitations

- **No OS Sandbox**: LLMFirewall does not run sandboxed kernel processes.
- **No Inherent Malware Analysis**: Binary virus scanning is out of scope.
- **Offline Intelligence Scope**: Vulnerability intelligence requires a designated provider or local database.
