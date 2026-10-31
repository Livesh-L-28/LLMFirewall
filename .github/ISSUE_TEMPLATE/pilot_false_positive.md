---
name: Pilot False Positive Report
about: Report a legitimate, benign user prompt or query incorrectly blocked or corrupted by LLMFirewall
title: '[Pilot FP] '
labels: ['external-pilot', 'pilot-false-positive']
assignees: ''
---

## Confidentiality & Privacy Confirmation
- [ ] **I confirm that this report contains NO real customer data, confidential enterprise text, or private credentials.**

---

## 1. Environment Details
- **Package Version**: `llmfirewall-core==1.3.2`
- **Python Version**: [e.g. Python 3.11.8]
- **Active Policy**: [Default Policy / Custom PolicyConfig]
- **Scan Direction**: [ ] Inbound Input / [ ] Outbound Completion

---

## 2. False Positive Description
Describe the legitimate context of the query (e.g. coding question, customer support request, normal conversational query):

---

## 3. Minimal Reproducible Example (MRE)
Provide the exact synthetic or sanitized query that triggered the false block:

```python
from llmfirewall import Firewall, Action

fw = Firewall()
benign_query = """[Paste sanitized benign text here]"""

result = fw.scan(benign_query)
print("Action:", result.action)
print("Reason:", result.reason)
print("Findings:", [f.detector_name for f in result.findings])
```

---

## 4. Observed vs. Expected Behavior
- **Observed Action**: `Action.BLOCK` / `Action.REDACT`
- **Expected Action**: `Action.ALLOW` (Clean query should pass downstream)
- **Triggered Detector / Rule**: [e.g. prompt_injection, pii, secrets]
- **Risk Score**: [e.g. 1.0]

---

## 5. Decision Trace Output
Output of `fw.trace_decision(benign_query)`:
```text
[Paste trace output here]
```

---

> [!NOTE] Privacy Reminder
> Please sanitize any proprietary company terminology or sensitive internal business names before posting.

