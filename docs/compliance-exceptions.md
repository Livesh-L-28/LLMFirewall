# Compliance Exceptions, Waivers & Remediation Lifecycle

Organizations occasionally require formal business exceptions, temporary waivers, or remediation grace periods when rolling out new controls.

---

## 1. ComplianceException Model

A compliance exception represents an approved operational or business waiver:

| Field | Type | Invariant |
|---|---|---|
| `exception_id` | `str` | Auto-generated unique ID (e.g. `CEXC-12345678`). |
| `control_id` | `str` | Target compliance control. |
| `asset_id` | `str` | Target asset ID or wildcard (`*`). |
| `reason` | `str` | Documented business or operational justification. |
| `approved_by` | `str` | **Mandatory** approving officer, team, or CISO role (non-empty). |
| `created_at` | `float` | Approval epoch timestamp. |
| `expires_at` | `float` | **Mandatory** expiration epoch timestamp. |
| `status` | `ExceptionStatus` | `ACTIVE`, `EXPIRED`, `REVOKED`. |

---

## 2. Automatic Expiration Invariant (Section 39)

> [!CAUTION]
> Compliance exceptions **never** grant indefinite exemptions.
> If `current_time > exception.expires_at`:
> 1. The exception status transitions automatically to `EXPIRED`.
> 2. The compliance engine emits an audit event: `COMPLIANCE_EXCEPTION_EXPIRED`.
> 3. The control is **re-assessed immediately** against live evidence.
> 4. If evidence is missing, a new `ComplianceGap` is generated.

---

## 3. Registering an Exception

```python
from llmfirewall.compliance import ComplianceEngine

engine = ComplianceEngine()

exc = engine.add_exception(
    control_id="ai-baseline:AC-01",
    asset_id="agent:customer-support",
    reason="Legacy plugin migration in progress until Q4 security release.",
    approved_by="Jane Doe, VP of Information Security",
    duration_seconds=30 * 86400,  # 30 days
)

print(f"Exception granted: {exc.exception_id}, active: {exc.is_active}")
```

---

## 4. Gap Remediation Lifecycle (Sections 36 & 37)

Identified compliance deficiencies are tracked as `ComplianceGap`:

```text
Remediation Statuses:
- OPEN         : Gap identified, remediation not started
- IN_PROGRESS  : Active guardrail or test development underway
- RESOLVED     : Required evidence collected and verified fresh
- ACCEPTED     : Formally accepted by risk committee
- WAIVED       : Formal active exception granted
- UNKNOWN      : Status unverified
```

### Defensive Guidance
Remediation guidance suggests specific actions and missing evidence tokens (e.g. `authorization_policy`, `authorization_test`, `production_configuration`).
> [!NOTE]
> The engine **never automatically modifies production systems**. It provides defensive remediation guidance for security engineers.
