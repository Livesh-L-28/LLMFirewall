---
name: Pilot Installation Issue
about: Report a failure or unexpected friction installing llmfirewall-core in the external pilot
title: '[Pilot Install] '
labels: ['external-pilot', 'pilot-installation']
assignees: ''
---

## Confidentiality & Privacy Confirmation
- [ ] **I confirm that this report contains NO proprietary environment paths, secrets, or confidential infrastructure data.**

---

## 1. Environment Details
- **Package Version Tested**: `llmfirewall-core==1.3.2`
- **Python Version**: [e.g. Python 3.10.12, 3.11.8, 3.12.2]
- **Operating System & Architecture**: [e.g. macOS Sonoma 14.5 arm64, Ubuntu 22.04 LTS x86_64, Windows 11 WSL2]
- **Virtual Environment Tool**: [e.g. venv, virtualenv, conda, poetry, uv]
- **Pip Version**: [e.g. pip 24.0]

---

## 2. Installation Command & Failure Description
### Exact Command Executed:
```bash
pip install llmfirewall-core==1.3.2
```

### Complete Terminal Output / Error Traceback:
```text
[Paste terminal output here]
```

---

## 3. Expected vs. Actual Behavior
### Expected Behavior:
Package installs cleanly with only core dependencies (`pydantic>=2.0.0`, `pyyaml>=6.0.0`) without compilation errors.

### Actual Behavior:
*Describe what failed (e.g. wheel build error, dependency conflict, import failure).*

---

## 4. Minimal Reproducible Example (MRE)
Can the issue be reproduced with a clean virtual environment script?
```bash
python3 -m venv test_env && source test_env/bin/activate
pip install llmfirewall-core==1.3.2
```

---

> [!NOTE] Security Vulnerabilities Notice
> If you suspect this installation failure involves a supply chain vulnerability, report it privately via [`SECURITY.md`](https://github.com/Livesh-L-28/LLMFirewall/blob/main/SECURITY.md) rather than public issues.

