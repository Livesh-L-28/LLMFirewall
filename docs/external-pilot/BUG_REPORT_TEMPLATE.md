# LLMFirewall-Core: Bug Report Template

> [!CAUTION] Privacy Reminder
> **Do not include production secrets, API tokens, proprietary system instructions, or confidential customer data in this report.** Use sanitized mock strings (e.g. `mock-api-key`, `user@example.com`).

---

## 1. Issue Overview

- **Title / Summary**: `[BUG / FP / FN / COMPAT]: Brief description of the issue`
- **Issue Classification**:
  - [ ] **Crash / Unhandled Exception**: Python error terminates worker or request.
  - [ ] **False Positive**: Legitimate, benign input was blocked (`Action.BLOCK`) or incorrectly corrupted.
  - [ ] **False Negative**: Hostile adversarial input evaded detection (`Action.ALLOW`).
  - [ ] **Integration Incompatibility**: Framework adapter or middleware contract broken.
  - [ ] **Performance / Resource Spike**: Excessive CPU time or memory allocation.
  - [ ] **Documentation Discrepancy**: Official guide or docstring provides incorrect or non-functional code.

---

## 2. Environment Specifications

```text
Operating System : [e.g. macOS 14.5 arm64 / Ubuntu 22.04 LTS / Windows 11 WSL2]
Python Version   : [e.g. Python 3.11.8]
Package Version  : [e.g. llmfirewall-core 1.4.0]
Related Packages : [e.g. fastapi==0.111.0, uvicorn==0.30.1, openai==1.35.0, pydantic==2.7.4]
```

---

## 3. Minimal Reproducible Example (MRE)

Provide a self-contained, standalone Python script that reproduces the behavior without external dependencies or live network connections:

```python
from llmfirewall import Firewall, Action

# 1. Setup
fw = Firewall()

# 2. Trigger input
trigger_input = """
[Paste sanitized reproduction string here]
"""

# 3. Execution
result = fw.scan(trigger_input)

# 4. Assert or print failure
print("Action:", result.action)
print("Reason:", result.reason)
```

---

## 4. Expected vs. Actual Behavior

### Expected Behavior
*Describe what should have happened according to SDK documentation and security principles:*

```text
Expected Action: Action.ALLOW (for benign query) OR Action.BLOCK (for injection)
Expected Status Code: 200 OK / 403 Forbidden
```

### Actual Behavior
*Describe what actually happened:*

```text
Actual Action: ...
Actual Exception / Traceback:
[Paste traceback if an exception occurred]
```

---

## 5. Decision Trace & Diagnostics (If Applicable)

If diagnosing a scan decision, provide the output of `fw.trace_decision(trigger_input)`:

```text
Trace Output:
- Final Action: ...
- Contributing Detectors: ...
- Risk Score: ...
```

---

## 6. Impact & Severity Assessment

- **Severity Level**:
  - [ ] **Critical**: System crash, unhandled crash in ASGI loop, or complete security bypass.
  - [ ] **High**: High-frequency false positive blocking core user queries, or integration failure with supported framework.
  - [ ] **Medium**: Edge-case bypass, minor redaction distortion, or documentation discrepancy.
  - [ ] **Low**: Ergonomic inconvenience, typo, or minor diagnostic message ambiguity.
- **Workaround Available**:
  - [ ] Yes (please describe): 
  - [ ] No (blocking evaluation)

