# Getting Support

We want your experience with **LLMFirewall-Core** to be seamless and productive. This document outlines the best ways to get help, ask questions, report bugs, and request features.

---

## 1. Documentation & Self-Help

Before submitting an issue, please check our comprehensive documentation:

- **[5-Minute Quickstart](docs/quickstart.md)**: Fast walkthrough for basic scanning, redaction, and action checking.
- **[Installation Guide](docs/installation.md)**: Virtual environments, pip installation, and optional extras (`fastapi`, `crypto`, `langchain`).
- **[Public API Reference](docs/api.md)**: Exhaustive class, method, model, and error documentation.
- **[Framework Integration Recipes](docs/integrations/)**: Verified recipes for FastAPI, Flask, Django, OpenAI, Anthropic, LangGraph, and MCP.
- **[Frequently Asked Questions (FAQ)](docs/faq.md)**: Common architectural questions, latency characteristics, and air-gapped setups.
- **[Troubleshooting Guide](docs/troubleshooting.md)**: Diagnostic steps for common developer pitfalls.

---

## 2. Choosing the Right Support Channel

| Question / Need | Recommended Channel | Details |
|:---|:---|:---|
| **Suspected Security Vulnerability** | **[Private Security Advisory](https://github.com/Livesh-L-28/LLMFirewall/security/advisories/new)** | See [SECURITY.md](SECURITY.md). Never post security exploits in public issues. |
| **Bug Report** | **[GitHub Issues](https://github.com/Livesh-L-28/LLMFirewall/issues/new?template=bug_report.md)** | Reproducible issues with code snippets, version info, and error traces. |
| **Feature / Enhancement Request** | **[GitHub Issues](https://github.com/Livesh-L-28/LLMFirewall/issues/new?template=feature_request.md)** | Proposed API extensions, new detector heuristics, or framework adapters. |
| **General Discussion & Questions** | **[GitHub Discussions](https://github.com/Livesh-L-28/LLMFirewall/discussions)** | Conceptual questions, integration advice, and community best practices. |

---

## 3. Best Practices When Filing Issues

To help maintainers diagnose and resolve your issue rapidly, please provide:

1. **Exact Environment Info**:
   ```bash
   python --version
   pip show llmfirewall-core
   uname -a  # Operating system details
   ```
2. **Minimal Reproducible Example**: A short, standalone Python script demonstrating the unexpected behavior.
3. **Traceback / Diagnostic Output**: Full Python exception traceback or `result.trace` output if available.
4. **Sanitized Payloads**: **Never include live API keys, private passwords, internal corporate endpoints, or real personal data** in issue descriptions or logs. Use synthetic placeholders like `admin@example.test` and `ghp_FAKETOKEN1234567890`.

---

## 4. Professional & Commercial Support

LLMFirewall-Core is an open-source project maintained under the Apache-2.0 license. Community support is provided on a best-effort basis by maintainers and volunteers. If your organization requires custom integration consulting or security advisory assistance, please reach out via GitHub Discussions.

