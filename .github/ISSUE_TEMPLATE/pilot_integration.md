---
name: Pilot Integration Issue
about: Report a framework integration incompatibility or runtime failure in the external pilot
title: '[Pilot Integration] '
labels: ['external-pilot', 'pilot-integration']
assignees: ''
---

## Confidentiality & Privacy Confirmation
- [ ] **I confirm that this report contains NO real API keys, production tokens, customer data, or proprietary prompts.**

---

## 1. Environment Details
- **Package Version**: `llmfirewall-core==1.3.2`
- **Python Version**: [e.g. Python 3.11.8]
- **Operating System**: [e.g. macOS Sonoma 14.5 arm64 / Ubuntu 22.04 LTS]
- **Target Framework & Version**: [e.g. FastAPI 0.111.0, Starlette 0.37.2, OpenAI 1.35.0, Anthropic 0.28.0, LangChain 0.2.5]
- **Integration Primitive Evaluated**:
  - [ ] `LLMFirewallASGIMiddleware`
  - [ ] `@fw.protect`
  - [ ] `@fw.protect_tool`
  - [ ] `fw.check_tool_call()`
  - [ ] `StreamingTextGuard`
  - [ ] `fw.context_orchestrator`

---

## 2. Problem Description
A clear and concise description of the integration failure or incompatibility.

---

## 3. Minimal Reproducible Example (MRE)
Provide a standalone Python script demonstrating the failure without external network access or live API credentials:

```python
from llmfirewall import Firewall
# Paste minimal reproduction code here
```

---

## 4. Expected vs. Actual Behavior
### Expected Behavior:
*Describe expected framework behavior or return types according to documentation.*

### Actual Behavior:
*Describe actual behavior, including status codes or unhandled exceptions.*

### Full Exception Traceback:
```text
[Paste exception traceback here if applicable]
```

---

> [!NOTE] Security Disclosure
> If this integration bug causes an exploitable denial of service or perimeter bypass, report privately via [`SECURITY.md`](https://github.com/Livesh-L-28/LLMFirewall/blob/main/SECURITY.md).

