---
name: Pilot False Negative / Evasion Report
about: Report a known adversarial injection category or synthetic evasion that was not detected
title: '[Pilot FN] '
labels: ['external-pilot', 'pilot-false-negative']
assignees: ''
---

> [!CAUTION] Security Vulnerability Reporting Notice
> **DO NOT post unpatched zero-day exploits, novel critical bypass techniques, or production attack payloads in public issues.**
> If this evasion represents a serious zero-day vulnerability in deployed systems, please report it privately via:
> 1. **GitHub Private Security Advisory**: Navigate to repository **Security** tab -> **Advisories** -> **Report a vulnerability**.
> 2. **Security Email**: Contact `security@llmfirewall.org`.
>
> Use this public issue template **ONLY** for general semantic evasion categories, benchmark gaps, or known pattern limitations using synthetic test inputs.

---

## Confidentiality & Privacy Confirmation
- [ ] **I confirm that this report contains NO proprietary attack code, real target hostnames, or confidential system prompts.**

---

## 1. Environment Details
- **Package Version**: `llmfirewall-core==1.3.2`
- **Python Version**: [e.g. Python 3.11.8]
- **Target Boundary**: [ ] Inbound Prompt / [ ] Outbound Generation / [ ] Tool Call Sandboxing / [ ] RAG Context

---

## 2. Evasion Category & Description
Describe the general attack taxonomy or technique (e.g. roleplay metaphor, recursive encoding, linguistic translation, indirect delimiter injection):

---

## 3. Minimal Reproducible Example (MRE)
Provide a synthetic or sanitized reproduction string:

```python
from llmfirewall import Firewall, Action

fw = Firewall()
evasion_prompt = """[Paste sanitized synthetic evasion prompt here]"""

result = fw.scan(evasion_prompt)
print("Action:", result.action)
print("Risk Score:", result.risk_score.score)
print("Is Allowed:", result.is_allowed)
```

---

## 4. Observed vs. Expected Behavior
- **Observed Action**: `Action.ALLOW` (Evasion succeeded in bypassing detector)
- **Expected Action**: `Action.BLOCK`
- **Observed Risk Score**: [e.g. 0.0]

---

## 5. Potential Mitigation / Rule Idea
*If you have suggestions on detector rules, normalization steps, or heuristics that would catch this pattern, please share:*

