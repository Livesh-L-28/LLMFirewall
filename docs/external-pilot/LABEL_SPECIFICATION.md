# LLMFirewall-Core: GitHub Issues Label Specification

This document defines the label taxonomy, color codes, descriptions, and automated setup commands for managing the external developer pilot on GitHub.

> [!CAUTION] Authorization Notice
> **Do NOT create or modify remote GitHub labels via automated scripts or API calls without explicit maintainer authorization.**
> The maintainer should run the commands below when ready to launch the pilot issue infrastructure.

---

## 1. Pilot Label Taxonomy

| Label Name | Color (Hex) | Description | Target Use Case |
|---|:---:|---|---|
| `external-pilot` | `#1D76DB` (Blue) | Issues and feedback submitted as part of the external developer pilot | Umbrella tag applied to all pilot submissions |
| `pilot-installation` | `#E11D48` (Rose Red) | Installation failures, dependency conflicts, wheel packaging issues | Task A failures or environment setup friction |
| `pilot-integration` | `#7C3AED` (Purple) | Framework adapter issues, ASGI middleware, decorator incompatibilities | Task C framework integration defects |
| `pilot-security` | `#DC2626` (Red) | Security issues, perimeter bypasses, unmasked secret disclosures | High-priority security concerns or escalations |
| `pilot-false-positive` | `#F59E0B` (Amber) | Legitimate benign user inputs blocked or corrupted by detectors | Detection accuracy issues on benign text |
| `pilot-false-negative` | `#D97706` (Orange) | Adversarial prompts or evasions that bypassed detection heuristics | Detection gaps or novel evasion patterns |
| `pilot-performance` | `#059669` (Emerald) | Latency spikes, excessive memory usage, event-loop blocking | Performance degradation or profiling issues |
| `pilot-documentation` | `#0284C7` (Sky Blue) | Documentation typos, broken snippets, missing docstrings, API drift | Inaccurate or out-of-date guide snippets |

---

## 2. Maintainer Setup Instructions

The repository maintainer can create all labels automatically using the GitHub CLI (`gh`):

```bash
# Verify authentication
gh auth status

# Create pilot labels in the repository
gh label create "external-pilot" --color "1D76DB" --description "Issues and feedback from external developer pilot" --force
gh label create "pilot-installation" --color "E11D48" --description "Pilot: installation and packaging issues" --force
gh label create "pilot-integration" --color "7C3AED" --description "Pilot: framework adapter and ASGI integration issues" --force
gh label create "pilot-security" --color "DC2626" --description "Pilot: security findings and bypass reports" --force
gh label create "pilot-false-positive" --color "F59E0B" --description "Pilot: benign prompts incorrectly blocked" --force
gh label create "pilot-false-negative" --color "D97706" --description "Pilot: adversarial inputs that evaded detection" --force
gh label create "pilot-performance" --color "059669" --description "Pilot: latency spikes and memory overhead" --force
gh label create "pilot-documentation" --color "0284C7" --description "Pilot: documentation bugs and broken snippets" --force
```

### Alternative: GitHub Web UI
1. Navigate to `https://github.com/Livesh-L-28/LLMFirewall/labels`.
2. Click **New label**.
3. Copy and paste the label name, hex color, and description from the taxonomy table above.
4. Click **Create label**.
