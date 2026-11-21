# 🛡️ LLMFirewall Live AI Threat Intelligence Feed

> **Automated Threat Pipeline Status:** 🟢 Active  
> **Last Synchronized:** `2026-11-21T01:05:08.733527+00:00`  
> **Total Monitored Advisories:** `519` (`83` Critical, `129` High, `286` Moderate)  
> **Monitored Ecosystem:** PyPI AI/ML Stack (`langchain`, `transformers`, `openai`, `chromadb`, `vllm`, `fastapi`, `torch`, etc.)

---

## 📊 OWASP Top 10 for LLMs Vulnerability Distribution

| OWASP Category | Active Advisories |
| :--- | :---: |
| **LLM01: Prompt Injection** | `172` |
| **LLM02: Insecure Output Handling** | `133` |
| **LLM04: Model Denial of Service** | `112` |
| **LLM05: Supply Chain Vulnerabilities** | `77` |
| **LLM06: Sensitive Information Disclosure** | `11` |
| **LLM08: Excessive Agency** | `8` |
| **LLM07: Insecure Plugin Design** | `3` |
| **LLM03: Training Data Poisoning** | `3` |

---

## 🚨 Latest AI & LLM Security Advisories

| ID / CVE | Package | Severity | OWASP Category | Summary |
| :--- | :--- | :---: | :--- | :--- |
| [GHSA-vvpg-rrww-wpmh](https://github.com/vllm-project/vllm/security/advisories/GHSA-vvpg-rrww-wpmh) (CVE-2026-115917) | `vllm` | `LOW` | LLM02: Insecure Output Handling | vLLM: Permissive default CORS origins allow cross-origin requests to the vLLM HTTP server... |
| [GHSA-8397-8qf6-f2gm](https://github.com/vllm-project/vllm/security/advisories/GHSA-8397-8qf6-f2gm) (CVE-2026-115913) | `vllm` | `MODERATE` | LLM02: Insecure Output Handling | vLLM: Phi-4 multimodal audio encoder materializes and retains full attention matrices: a s... |
| [GHSA-gq5q-89c7-vhvx](https://github.com/vllm-project/vllm/security/advisories/GHSA-gq5q-89c7-vhvx) (CVE-2026-115914) | `vllm` | `MODERATE` | LLM02: Insecure Output Handling | vLLM DeepSeek-OCR image processing vulnerable to denial of service... |
| [GHSA-h3rc-j82p-2c3h](https://github.com/vllm-project/vllm/security/advisories/GHSA-h3rc-j82p-2c3h) (CVE-2026-115915) | `vllm` | `HIGH` | LLM01: Prompt Injection | vLLM: Untrusted EPS inputs can trigger denial of service or Ghostscript RCE... |
| [GHSA-6757-hggm-hp2w](https://github.com/vllm-project/vllm/security/advisories/GHSA-6757-hggm-hp2w) (CVE-2026-115912) | `vllm` | `HIGH` | LLM01: Prompt Injection | vLLM: Public multimodal SHM handle forgery reaches worker-side `pickle.loads()` with insec... |
| [GHSA-q97c-p368-75c4](https://github.com/vllm-project/vllm/security/advisories/GHSA-q97c-p368-75c4) (CVE-2026-115916) | `vllm` | `MODERATE` | LLM01: Prompt Injection | vLLM: Out-of-vocabulary prompt token id passes input validation and triggers a CUDA device... |
| [GHSA-x567-49g5-p4cf](https://github.com/vllm-project/vllm/security/advisories/GHSA-x567-49g5-p4cf) (CVE-2026-115918) | `vllm` | `MODERATE` | LLM01: Prompt Injection | vLLM: Responses API bypasses trust_request_chat_template for chat_template_kwargs... |
| [GHSA-542m-9234-8gvf](https://github.com/vllm-project/vllm/security/advisories/GHSA-542m-9234-8gvf) (CVE-2026-115911) | `vllm` | `MODERATE` | LLM02: Insecure Output Handling | vLLM: DoS via unbounded chat_template Jinja2 rendering exhausts the renderer thread pool... |
| [GHSA-h3rc-6mm3-gc2m](https://github.com/vllm-project/vllm/security/advisories/GHSA-h3rc-6mm3-gc2m) (CVE-2026-114053) | `vllm` | `HIGH` | LLM01: Prompt Injection | vLLM: Request-controlled mm_processor_kwargs.code_revision allows remote code execution... |
| [GHSA-frvg-qw88-hww9](https://github.com/vllm-project/vllm/security/advisories/GHSA-frvg-qw88-hww9) (CVE-2026-94624) | `vllm` | `MODERATE` | LLM04: Model Denial of Service | vllm p2p never connected zmq_exhaustion... |
| [PYSEC-2026-4349](https://github.com/vllm-project/vllm/releases/tag/v0.32.0) (CVE-2026-115918) | `vllm` | `MEDIUM` | LLM01: Prompt Injection | No summary provided... |
| [PYSEC-2026-4348](https://github.com/vllm-project/vllm/releases/tag/v0.32.0) (CVE-2026-115917) | `vllm` | `MEDIUM` | LLM04: Model Denial of Service | No summary provided... |
| [PYSEC-2026-4347](https://github.com/vllm-project/vllm/releases/tag/v0.32.0) (CVE-2026-115916) | `vllm` | `MEDIUM` | LLM01: Prompt Injection | No summary provided... |
| [PYSEC-2026-4346](https://github.com/vllm-project/vllm/releases/tag/v0.32.0) (CVE-2026-115915) | `vllm` | `CRITICAL` | LLM02: Insecure Output Handling | No summary provided... |
| [PYSEC-2026-4345](https://github.com/vllm-project/vllm/releases/tag/v0.32.0) (CVE-2026-115912) | `vllm` | `CRITICAL` | LLM02: Insecure Output Handling | No summary provided... |
| [PYSEC-2026-4344](https://github.com/vllm-project/vllm/releases/tag/v0.32.0) (CVE-2026-115911) | `vllm` | `MEDIUM` | LLM02: Insecure Output Handling | No summary provided... |
| [PYSEC-2026-4353](https://www.vulncheck.com/advisories/vllm-0.20.0-before-0.30.0-dos-via-inference-v1-generate-mm-placeholders) (CVE-2026-116178) | `vllm` | `MEDIUM` | LLM04: Model Denial of Service | No summary provided... |
| [PYSEC-2026-4352](https://www.vulncheck.com/advisories/vllm-0.10.2-before-0.25.0-dos-via-nemotron-vl-processor-decompression-bomb-guard-bypass) (CVE-2026-116177) | `vllm` | `MEDIUM` | LLM04: Model Denial of Service | No summary provided... |
| [PYSEC-2026-4351](https://github.com/vllm-project/vllm/security/advisories/GHSA-vfp2-c8pq-v6h6) (CVE-2026-116176) | `vllm` | `HIGH` | LLM06: Sensitive Information Disclosure | No summary provided... |
| [PYSEC-2026-4350](https://github.com/vllm-project/vllm/security/advisories/GHSA-6pgw-f3pv-4h8q) (CVE-2026-116173) | `vllm` | `MEDIUM` | LLM01: Prompt Injection | No summary provided... |
| [GHSA-gx7p-2j49-hfq4](https://github.com/vllm-project/vllm/security/advisories/GHSA-gx7p-2j49-hfq4) (CVE-2026-114055) | `vllm` | `HIGH` | LLM01: Prompt Injection | vLLM : DoS via unvalidated mm_processor_kwargs in multimodal image processors (Isaac, Inte... |
| [GHSA-p92p-rxj5-7p2x](https://github.com/vllm-project/vllm/security/advisories/GHSA-p92p-rxj5-7p2x) (CVE-2026-114050) | `vllm` | `MODERATE` | LLM01: Prompt Injection | vLLM: Forged multimodal UUID + P0/P1 processor-cache eviction drift: unauthenticated remot... |
| [PYSEC-2026-4362](https://github.com/vllm-project/vllm/security/advisories/GHSA-rh6f-3x46-j33q) (CVE-2026-114054) | `vllm` | `MEDIUM` | LLM05: Supply Chain Vulnerabilities | No summary provided... |
| [PYSEC-2026-4361](https://github.com/vllm-project/vllm/security/advisories/GHSA-823j-m4cj-hmjf) (CVE-2026-114052) | `vllm` | `MEDIUM` | LLM01: Prompt Injection | No summary provided... |
| [PYSEC-2026-4308](https://github.com/vllm-project/vllm/security/advisories/GHSA-935w-9g4m-p28p) (CVE-2026-105752) | `vllm` | `HIGH` | LLM01: Prompt Injection | vLLM: Harmony tool continuations drop `cache_salt` — restoring a cross-tenant prefix-cache... |

---

## 🎯 Curated Prompt Injection & Jailbreak Heuristics

The guardrail engine enforces real-time runtime detection across these 5 primary vector categories:

1. **Direct Injection (LLM01.1):** System instruction overrides, developer mode impersonation.
2. **Indirect Injection (LLM01.2):** Payloads hidden in retrieved external contexts, HTML tags, or RAG documents.
3. **Token Smuggling (LLM01.3):** Base64, hex, rot13, and zero-width homoglyph encoding bypasses.
4. **Virtualization (LLM01.4):** Fictional roleplay framing and hypothetical scenario evasion.
5. **Structural Hijacking (LLM01.5):** Special delimiter and chat-markup injection (`<|im_start|>system`).

---
*Generated automatically by LLMFirewall Threat Intelligence Pipeline &bull; Author: Livesh L*
