# LLMFirewall-Core: Known Limitations & Architecture Boundaries

This document provides transparent, evidence-based technical disclosure of the architectural boundaries, threat model limitations, and feature capabilities for **`llmfirewall-core` v1.4.0**.

Evaluators are strongly encouraged to review these limitations when designing security tests and production deployment architectures.

---

## 1. Threat Model & Detection Boundaries

### 1.1 Pre-Execution Semantic Evasions
- **Mechanism**: In `v1.4.0`, prompt injection detection relies on deterministic pattern matching, regex heuristics, structural keyword inspection, token density analysis, and multi-stage normalization (leetspeak, homoglyphs, and bracketed encoding).
- **Limitation**: While achieving 100% precision and zero false positives on standard developer benchmarks, pre-execution static inspection **cannot achieve 100% adversarial recall against previously unseen, deeply obfuscated semantic attacks** (e.g. multi-step roleplay, complex hypothetical framing, novel linguistic metaphors, or recursive cipher payloads).
- **Empirical Evaluation Evidence**: In frozen Holdout v4 benchmark evaluation against 80 diverse test prompts (40 adversarial injection attacks, 40 benign developer prompts), LLMFirewall-Core achieved **60.0% empirical recall** (24 True Positives, 16 False Negatives, 40 True Negatives, 0 False Positives, representing a 40% false-negative rate on unseen adversarial evasions with zero false alarms). Static pattern matching remains inherently complementary to runtime model safety layers and defense-in-depth architectures.

### 1.2 In-Process Memory Boundary
- **Mechanism**: `llmfirewall-core` executes as an in-process Python library.
- **Limitation**: The library does not manage kernel namespaces, container cgroups, or operating system network interfaces. It cannot protect against compromised host runtimes, interpreter bugs, or memory corruption vulnerabilities in native Python extensions.

### 1.3 Safe Audit Serialization Boundary
- **Mechanism**: `result.safe_dict()` scrubs raw prompt strings, sensitive payloads, and matched secret substrings before generating telemetry dictionaries.
- **Limitation**: While `safe_dict()` ensures local logs and traces do not retain cleartext secrets, it does not purge interpreter memory or govern the data retention, training, or logging policies of upstream third-party cloud LLM providers (e.g., OpenAI, Anthropic, cloud vector databases).

---

## 2. Tool Sandboxing & Parameter Inspection Boundaries

### 2.1 SSRF & DNS Rebinding (TOCTOU)
- **Mechanism**: `fw.check_tool_call` and `URLSecurityRule` inspect URLs against private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopbacks (`127.0.0.1`), and cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`).
- **Limitation**: Static URL string validation cannot prevent **Time-Of-Check to Time-Of-Use (TOCTOU) DNS rebinding attacks**, where a malicious external hostname resolves to a public IP during firewall inspection but resolves to `169.254.169.254` during the actual HTTP request.
- **Architectural Requirement**: Application-level tool parameter checking does not replace an operating system container or network firewall. Complete enterprise SSRF mitigation requires combining `fw.check_tool_call()` with an egress network proxy, local DNS pinning, or socket-level address resolution enforcement.

### 2.2 Filesystem Path Traversal & Symlinks
- **Mechanism**: Path security rules validate that target paths do not escape allowed root directories via `../` sequences or forbidden system directory prefixes (`/etc`, `/proc`, `/sys`).
- **Limitation**: String-based path inspection cannot prevent **runtime symlink swap race conditions** if a malicious concurrent process modifies directory symlinks after validation.
- **Architectural Requirement**: Production filesystem tools executing untrusted actions should run in ephemeral container environments (e.g., Docker, gVisor) or use POSIX `O_NOFOLLOW` file descriptors.

---

## 3. PII & Privacy Redaction Boundaries

### 3.1 Supported Standard Entity Patterns
- **Supported**: RFC-compliant email addresses, E.164 and North American phone numbers, US Social Security Numbers (SSNs), standard credit card numbers (Visa, Mastercard, Amex, Discover via Luhn check), and IPv4/IPv6 addresses.
- **Limitation**: Non-standard proprietary identifiers (e.g. internal employee badges, custom UUID schemas, proprietary customer IDs, medical record numbers) are not redacted by default.
- **Mitigation**: Evaluators can define custom regex rules using `PolicyConfig` and custom redaction patterns.

### 3.2 In-Memory Scan Cache TTL
- **Mechanism**: In `v1.4.0`, `Firewall(enable_cache=True)` caches scan decisions with a default TTL of 1,800 seconds (30 minutes) and a maximum size of 5,000 entries.
- **Limitation**: Cache entries retain SHA-256 hashes of scanned text to enable sub-millisecond repeated lookups. Applications with strict zero-cache mandates should initialize with `Firewall(enable_cache=False)`.

---

## 4. Streaming Guardrail Boundaries

### 4.1 Token-Boundary Sliding Window Latency vs Split Chunks
- **Mechanism**: `StreamingTextGuard` buffers emitted tokens across a sliding character window (default: 64 to 256 characters) to detect adversarial injections or secrets split across arbitrary chunk boundaries.
- **Limitation**: Chunks that have already been yielded and transmitted across network sockets prior to mid-stream attack detection cannot be retroactively recalled. When a mid-stream threat is detected, `StreamingTextGuard` terminates the generator and raises `SecurityViolation`.

---

## 5. Feature Availability & Verified Capabilities (v1.4.0)

All features below are verified, packaged in the official wheel (`llmfirewall_core-1.4.0-py3-none-any.whl`), and available on [PyPI](https://pypi.org/project/llmfirewall-core/1.4.0/):

| Feature | Status in v1.4.0 | Canonical Import & Usage |
|---|:---:|---|
| **Core Boundary Scans** (`fw.scan`) | **Available** | `from llmfirewall import Firewall, Action; fw = Firewall(); fw.scan(prompt)` |
| **Tool Execution Gating** (`fw.check_tool_call`, `@fw.protect_tool`) | **Available** | `from llmfirewall import Firewall, SecurityBlockError; fw.check_tool_call(tool, args)` |
| **Streaming Text Guard** (`StreamingTextGuard`) | **Available** | `from llmfirewall.integrations import StreamingTextGuard; guard.protect_stream(chunks)` |
| **Zero-Dependency ASGI** (`LLMFirewallASGIMiddleware`) | **Available** | `from llmfirewall.integrations import LLMFirewallASGIMiddleware` |
| **Policy String Presets** (`Firewall(policy="strict")`) | **Available** | `fw = Firewall(policy="strict")` (also `"default"`, `"permissive"`, `"privacy"`) |
| **Dedicated OpenAI Wrapper** (`OpenAIGuard`, `wrap_openai`) | **Available** | `from llmfirewall.integrations import OpenAIGuard; guard = OpenAIGuard()` |
| **Dedicated Anthropic Wrapper** (`AnthropicGuard`, `wrap_anthropic`) | **Available** | `from llmfirewall.integrations import AnthropicGuard; guard = AnthropicGuard()` |
| **Dedicated MCP Router** (`MCPToolGuard`) | **Available** | `from llmfirewall.integrations import MCPToolGuard; guard = MCPToolGuard()` |
| **LangGraph State Guard** (`LangGraphStateGuard`, `@guard_node`) | **Available** | `from llmfirewall.integrations.langgraph import LangGraphStateGuard` |
| **LangChain Callback Handler** (`FirewallCallbackHandler`) | **Available** | `from llmfirewall.integrations.langchain import FirewallCallbackHandler` |
| **Multi-Stage Normalizer** | **Available** | In-process normalization against homoglyphs, leetspeak, and zero-width chars. |

---

## 6. Adoption Status Disclosure

As of November 2026, LLMFirewall-Core reflects **0 verified external third-party evaluations and 0 verified production deployments**. All performance numbers and threat detection figures cited herein represent internal automated regression benchmarks, synthetic corpora, and frozen holdout datasets (Holdout v4). External developer validation is the explicit goal of the current developer pilot program.
