# Plugins & Extensibility

LLMFirewall is designed for seamless extensibility across detectors, risk calculators, policy handlers, and containment hooks.

---

## 1. Custom Detectors

Implement custom threat detectors by subclassing `BaseDetector`:

```python
from typing import List
from llmfirewall.detectors.base import BaseDetector
from llmfirewall.core.models import Finding, ThreatType, Severity

class CustomDomainDetector(BaseDetector):
    def __init__(self, name: str = "custom_domain_detector") -> None:
        super().__init__(name=name)

    def detect(self, text: str, **kwargs) -> List[Finding]:
        findings = []
        if "prohibited_internal_keyword" in text.lower():
            findings.append(
                Finding(
                    threat_type=ThreatType.CUSTOM,
                    severity=Severity.HIGH,
                    detector_name=self.name,
                    description="Prohibited internal keyword detected.",
                )
            )
        return findings
```

---

## 2. Custom Containment Hooks

Attach custom containment handlers to the Incident Manager:

```python
from llmfirewall import Firewall

def my_custom_containment(target_id: str, **kwargs):
    print(f"Executing cloud IAM revocation for {target_id}")
    return {"revoked": True}

fw = Firewall()
fw.incidents.containment_handlers["revoke_iam"] = my_custom_containment

# Dry-run test
res = fw.incidents.execute_containment_action("revoke_iam", "role:ai-agent", dry_run=True)
assert res["status"] == "SIMULATED"
```
