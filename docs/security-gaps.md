# Security Gaps

## 1. Overview

A [SecurityGap](file:///Users/livesh/LLMFirewall/src/llmfirewall/spm/models.py) represents an actionable deficiency, missing defensive control, untested security boundary, or architectural risk identified by the Posture Engine.

Unlike raw vulnerability scans, a SecurityGap is grounded in evidence and linked directly to defensive controls and attack paths.

---

## 2. Schema

```python
class SecurityGap(BaseModel):
    gap_id: str                      # Deterministic or unique identifier (e.g. 'GAP-A1B2C3D4')
    asset_id: str                    # Target asset identifier
    dimension: str                   # PostureDimension category
    title: str                       # Concise human-readable title
    description: str                 # Detailed technical description of deficiency
    severity: Severity               # CRITICAL, HIGH, MEDIUM, LOW
    evidence: List[str]              # Factual bullet points justifying gap
    related_control: Optional[str]   # Deficient or absent security control
    related_attack_path: Optional[str] # Attack path enabled by this deficiency
    status: SecurityGapStatus        # OPEN, RESOLVED, ACCEPTED, UNVERIFIED
    remediation_guidance: Optional[str] # Actionable engineering guidance
    created_at: float
    updated_at: float
```

---

## 3. Gap Lifecycle States

| Status | Description |
|---|---|
| `OPEN` | Active gap confirmed by engine evaluation. |
| `UNVERIFIED` | Potential deficiency where observation evidence is incomplete or stale. |
| `RESOLVED` | Defensive control configured and verified passing; gap closed. |
| `ACCEPTED` | Formal security risk waiver accepted via Phase 31 Governance. |

---

## 4. SARIF 2.1.0 Export

Actionable security gaps export directly to OASIS SARIF 2.1.0 for integration with CI/CD gates, GitHub Advanced Security, or external SIEM/SOC platforms:

```bash
llmfirewall posture export --format sarif --output posture_gaps.sarif
```

Example SARIF Result:
```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "LLMFirewall AI-SPM",
          "version": "0.1.0"
        }
      },
      "results": [
        {
          "ruleId": "LLMFIREWALL-SPM-TOOL_SECURITY",
          "level": "error",
          "message": {
            "text": "[HIGH] Tool Authorization Not Configured or Verified (agent:customer-support): Agent has access to 2 callable tool(s) but tool authorization policy is not configured or validated. Guidance: Configure explicit ToolPermission guardrails or RBAC policy specifying callable tools."
          },
          "properties": {
            "gap_id": "GAP-7F3A9D12",
            "asset_id": "agent:customer-support",
            "dimension": "tool_security",
            "severity": "HIGH",
            "status": "OPEN",
            "related_control": "control:tool_authorization"
          }
        }
      ]
    }
  ]
}
```
