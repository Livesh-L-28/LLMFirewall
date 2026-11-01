---
name: Bug Report
about: Create a report to help us improve LLMFirewall-Core
title: '[BUG] '
labels: ['bug', 'triage']
assignees: ''
---

## Description
A clear and concise description of the bug or unexpected behavior.

## Reproduction Steps
Steps to reproduce the behavior:
1. Initialize Firewall with `...`
2. Run scan on input `...`
3. See error or unexpected action

## Minimal Reproducible Code Example
```python
from llmfirewall import Firewall, Action

fw = Firewall()
result = fw.scan("...")
# Observed behavior vs Expected behavior
```

## Expected Behavior
A clear and concise description of what you expected to happen.

## Environment Details
- **LLMFirewall-Core Version**: [e.g. 1.3.2]
- **Python Version**: [e.g. 3.12.1]
- **Operating System**: [e.g. macOS 27.0.1, Ubuntu 22.04, Windows 11]
- **Installed Extras**: [e.g. none, fastapi, flask, crypto]

## Additional Context
Add any other context about the problem here (e.g. exception tracebacks without raw user prompts or secret tokens).
