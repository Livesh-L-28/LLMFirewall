# LLMFirewall-Core — Operational Boundaries & Security Limitations

Transparent disclosure of the security model, architectural boundaries, and known limitations of LLMFirewall-Core.

---

## 1. Security Philosophy & Universal Disclaimer

> [!WARNING]
> **Universal Security Disclaimer**: No automated guardrail system can guarantee 100% prevention of all prompt injection attacks, zero-day jailbreaks, or adaptive social engineering attempts.
>
> High benchmark scores on synthetic datasets reflect baseline heuristic effectiveness, not absolute immunity. Security must be implemented using **defense-in-depth**: combine input scanning, output verification, least-privilege tool execution, network egress filtering, and human oversight for sensitive operations.

---

## 2. Threat Vector Boundaries & Limitations

### 2.1 Prompt Injection & Adversarial Evasions
- **Heuristic Detection Engine**: LLMFirewall evaluates inputs using deterministic multi-pass heuristics, regex pattern matching, and Unicode normalizers (NFKC, Cyrillic homoglyph mappings, zero-width space stripping, leetspeak decoding).
- **Known Limitations**:
  - **Indirect / Semantic Evasions**: Prompts using complex multi-paragraph narrative framing, passive voice, fictional roleplay, or novel multilingual phrasing without explicit override keywords may not trigger static rules.
  - **Context-Dependent Injections**: Content that is benign in one application (e.g. creative writing about hacking) may be classified as suspicious, or vice-versa.
  - **Multi-turn Distributed Payloads**: Attackers splitting instructions across multiple conversational turns require explicit state tracking via [`MultiTurnSecurityState`](../src/llmfirewall/detectors/prompt_injection/context.py) or session-based wrappers.

---

### 2.2 Agent Tool Security vs. OS Sandboxing
- **Static Parameter Checks vs. Operating System Isolation**:
  `ToolSecurityEngine` validates parameter schemas, URL hosts, and file paths prior to tool invocation.
  - **Not a Container / Sandbox Replacement**: Intercepting `DROP TABLE` or `rm -rf` at the parameter layer is an application guardrail. It is **not** equivalent to running tools in an isolated Docker container, Firecracker microVM, or gVisor sandbox.
  - **Least Privilege**: Tools that execute shell commands or database queries must run with minimal database permissions and restricted operating system privileges.

---

### 2.3 Network & SSRF Boundaries
- **URL Validation**: `validate_url_safety()` checks protocols (blocking non-HTTP/HTTPS schemes), rejects private IP ranges (RFC 1918), and detects loopback and cloud metadata endpoints (`169.254.169.254`, `0x7f000001`, `2130706433`).
- **DNS Rebinding & TOCTOU**:
  - Resolving a hostname at validation time does not guarantee that the subsequent HTTP client socket connection connects to the same IP address (Time-of-Check to Time-of-Use DNS rebinding).
  - True DNS rebinding protection requires socket-level IP pinning, an egress forward proxy, or containerized network namespaces.

---

### 2.4 Filesystem & Path Traversal Boundaries
- **Path Security**: `validate_path_safety()` normalizes relative dot-segments (`../`) and rejects UNC paths (`\\server\share`).
- **Symlinks & TOCTOU**:
  - Validating a file path prior to opening it does not prevent an attacker from modifying symlinks concurrently.
  - Production deployments should mount restricted read-only filesystems or chroot environments for untrusted file operations.

---

### 2.5 Multi-Turn State Isolation
- **Stateless Core**:
  The primary `Firewall` orchestrator is intentionally **stateless by design**. It does not maintain global in-memory state across separate HTTP requests.
- **Explicit Session Tracking**:
  Applications requiring cross-turn threat scoring must explicitly supply `session_id` using `MultiTurnSecurityState`, `LLMFirewallClient.create_session()`, or `LangGraphStateGuard`.

---

## 3. Empirical Holdout v4 Benchmark Transparency

To prevent benchmark overfitting and marketing exaggeration, LLMFirewall evaluates detection accuracy against an untouched, novel holdout dataset:

- **Dataset File**: `benchmarks/datasets/holdout_v4_evaluation_dataset.json`
- **Dataset SHA-256 Checksum**:
  ```text
  ec382aed97a3a144607f072422d0e761993cd13e58fd894f4de05544102c9553
  ```
- **Holdout v4 Population & Results**:
  - Total Samples: 80
  - Benign Samples: 40
  - Adversarial Attack Samples: 40
  - **True Positives (TP)**: 24
  - **False Negatives (FN)**: 16
  - **True Negatives (TN)**: 40
  - **False Positives (FP)**: 0
  - **Precision**: 100.0%
  - **Recall**: 60.0%
  - **F1 Score**: 75.0%
  - **Accuracy**: 80.0%

*Note*: Holdout v4 results are kept strictly separate from synthetic developer benchmark suites. They demonstrate that while the heuristic engine produces zero false positives on benign developer prompts, novel holdout adversarial payloads sustain a 40% false-negative rate, underscoring the absolute necessity of defense-in-depth architecture.
