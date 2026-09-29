# LLMFirewall Security Model & Threat Boundary

This document defines the formal threat model, security controls, architectural boundaries, data handling policies, and known limitations of **LLMFirewall v1.0.0**.

---

## 1. Threat Model

LLMFirewall operates at the application layer to guard LLM pipelines, autonomous agents, and RAG systems. It addresses four primary adversary archetypes:

1. **Malicious External Users**: Attackers attempting direct prompt injection, jailbreaks, persona manipulation, or prompt extraction to subvert application intent.
2. **Untrusted Third-Party Content (RAG & Web)**: Indirect prompt injections embedded in retrieved documents, websites, database records, or PDFs intended to hijack model context during inference.
3. **Overprivileged or Compromised Agents**: Autonomous multi-agent loops attempting unauthorized tool calls, destructive file/database operations, SSRF attempts, or excessive resource consumption.
4. **Supply Chain & Model Tampering**: Malicious weight serialization formats (e.g. `pickle` exploits), tampered configurations, or known vulnerabilities in third-party libraries.

---

## 2. Supported Security Controls

LLMFirewall implements defense-in-depth across the following layers:

| Layer | Security Controls | Module |
|:---|:---|:---|
| **Input Inspection** | Normalization, regex/heuristic pattern matching, jailbreak detectors, system prompt extraction guards. | `llmfirewall.detectors.prompt_injection` |
| **Data Protection** | Regex and checksum validation for PII (emails, phone numbers, IPs, credit cards); high-entropy secret detection (API keys, private tokens). | `llmfirewall.detectors.pii`, `llmfirewall.detectors.secrets` |
| **Output Guardrails** | Outgoing model response inspection and automatic character-span redaction before returning to clients. | `llmfirewall.policy.redactor` |
| **Tool Sandboxing** | Schema argument bounds checking, SSRF prevention (IP range, cloud metadata blocking), SQL injection heuristic analysis, domain allowlists. | `llmfirewall.tools` |
| **Agent Capability Control** | Action budgets, capability grants, privilege delegation rules, human approval provider gates. | `llmfirewall.capabilities` |
| **RAG Security** | Document ingestion sanitization, strict untrusted context tagging, quarantine store for infected records. | `llmfirewall.rag` |
| **Runtime Protection** | Sub-millisecond rate limiting, session loop guards, fail-safe modes (`FAIL_CLOSED`, `FAIL_OPEN`). | `llmfirewall.protection`, `llmfirewall.runtime` |
| **Supply Chain Verification** | Streaming SHA-256 model hashing, unsafe serialization detection (`pickle` blocking), dependency auditing. | `llmfirewall.supply_chain` |
| **Observability & Audit** | Zero-leakage structured telemetry, SHA-256 event hashing, incident correlation engine. | `llmfirewall.observability`, `llmfirewall.incidents` |

---

## 3. Policy Enforcement & Precedence

Policy evaluation is deterministic. When multiple detectors emit findings for a single request, actions resolve according to strict precedence:

$$\text{BLOCK} > \text{REDACT} > \text{WARN} > \text{ALLOW}$$

- If any rule triggers `BLOCK`, the transaction is immediately rejected (`SecurityBlockError` or HTTP 403).
- If rules trigger `REDACT`, sensitive tokens are masked while allowing benign surrounding content.
- If rules trigger `WARN`, execution proceeds and an audit alert is recorded.
- Requests trigger `ALLOW` only if no higher-priority security rule matched.

---

## 4. Data Handling & Zero-Retention Privacy

LLMFirewall is engineered with a strict **privacy-first data handling invariant**:

1. **In-Process Execution**: Scanning runs entirely within your host process. Prompts and outputs are never transmitted to external third-party inspection APIs or hosted LLM proxies.
2. **Zero Plaintext Secret Storage**: When secrets, tokens, or credentials are discovered, their raw plaintext values are scrubbed immediately. Audit logs record only synthetic identifiers, sanitized lengths, or one-way hashes (`hash_content`).
3. **Isolated Telemetry**: Telemetry metrics export only counters and latency distributions. Raw prompt bodies and customer personal data are never attached as metric labels or event attributes.
4. **Ephemeral Redaction**: Redaction masks sensitive spans in memory during the execution pipeline without caching unredacted copies.

---

## 5. Security Evaluation & Benchmark Scope

LLMFirewall was evaluated against the project's internal 40-case security benchmark corpus and regression test suites.

> [!IMPORTANT]
> **Evaluation Scope Notice:**
> The reported detection metrics correspond specifically to the project's 40-case benchmark corpus and automated test suites. Passing these benchmarks demonstrates that the deterministic heuristic engines and policies function as specified against known reference patterns. It should not be interpreted as universal or infallible security protection against all conceivable adversarial attacks.

---

## 6. Known Limitations

Security practitioners must consider the following technical boundaries:

1. **Heuristic & Rule-Based Detection**: LLMFirewall uses high-performance deterministic heuristics, regex patterns, and entropy scoring to maintain sub-millisecond execution. Highly novel, obfuscated, or adversarial jailbreaks (e.g. complex linguistic ciphers, multi-turn stateful gaslighting) may evade static heuristics.
2. **Defense-in-Depth Required**: LLMFirewall is not a substitute for identity and access management (IAM), network firewalls, rate limiters at the API gateway layer, or model-level safety alignments. It should be deployed as one layer in a defense-in-depth posture.
3. **Language Coverage**: Built-in prompt injection and PII patterns are optimized primarily for English text; multilingual coverage varies depending on character sets and regex structures.
4. **Semantic Understanding**: Deterministic pattern matching does not perform deep semantic or philosophical reasoning on prompt intent.
5. **Multi-Modal Limitations**: Inspection is performed on text and structured arguments; raw image, audio, or video binaries are not inspected directly by the core text engine.

---

## 7. Responsible Disclosure

We welcome vulnerability reports from security researchers and practitioners. For instructions on reporting security findings privately, please see [SECURITY.md](../SECURITY.md).
