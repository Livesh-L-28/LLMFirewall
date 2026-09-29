# LLMFirewall Release Manifest

**Release Version:** `1.0.0rc1`  
**Status:** Release Candidate  
**Target Release:** `v1.0.0 Production`  
**License:** Apache-2.0  
**Supported Python Versions:** `>=3.9` (Tested on 3.9, 3.10, 3.11, 3.12)  

---

## 1. Package Artifacts

| Artifact Name | Format | Integrity Hash (SHA-256) |
|---|---|---|
| `llmfirewall-1.0.0rc1-py3-none-any.whl` | Wheel | Generated at build time |
| `llmfirewall-1.0.0rc1.tar.gz` | Source Distribution | Generated at build time |

---

## 2. Core Architectural Subsystems Included

1. **Core Detection & Policies (Phases 1–10)**:
   - Detectors: Prompt Injection, Jailbreak, Credentials/Secrets, PII (Email, Phone, SSN, Credit Cards).
   - Scanners: `Scanner` standalone class, `Firewall.scan()`, `Firewall.check()`.
   - Policy-as-Code: Deterministic action precedence (`BLOCK` > `REDACT` > `WARN` > `ALLOW`).
2. **Agent & Capability Defense (Phases 11–20)**:
   - Capability budget enforcement, tool argument validation, SSRF checks, path traversal sandboxing.
   - Model artifact integrity verification and safe serialization guards.
3. **Continuous Testing & Evaluation (Phases 21–30)**:
   - Red team simulation fuzzer, SARIF 2.1.0 exports, automated security evaluation runner.
4. **Governance, Knowledge Graph, AI-SPM & Release (Phases 31–40)**:
   - AI Asset Inventory (`inventory`), Security Knowledge Graph (`graph`).
   - Attack Path Analysis (`attack`), Threat Modeling (`threat-model`).
   - AI-SPM Posture Management (`posture`), Compliance Mapping (`compliance`).
   - Risk & Prioritization Engine (`risk`), Incident Response (`incidents`).
   - Runtime Protection Engine (`protect` / `< 1ms` overhead).

---

## 3. CLI Subcommand Manifest (11 Primary Tools)

```text
llmfirewall scan
llmfirewall policy
llmfirewall protect
llmfirewall test
llmfirewall inventory
llmfirewall graph
llmfirewall attack
llmfirewall posture
llmfirewall compliance
llmfirewall risk
llmfirewall incidents
```

---

## 4. Benchmark & Validation Program (Phase 41)

- Reproducible Benchmark Corpus: `benchmarks/dataset/` across 8 threat categories.
- Performance Profile: Sub-millisecond runtime protection overhead (`< 1ms`).
- Safety Defaults: `FAIL_CLOSED`, `dry_run=True` containment hooks, zero raw secrets logged or displayed.
