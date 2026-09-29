# Risk Acceptance, Finding Lifecycle & Security Waivers

## 1. Finding Lifecycle

Every security issue in LLMFirewall tracks a normalized lifecycle state:

```text
       ┌──────────────┐
       │     OPEN     │
       └──────┬───────┘
              │
       ┌──────┴───────┐
       │ ACKNOWLEDGED │
       └──────┬───────┘
              ├──────────────────────────┐
              ↓                          ↓
       ┌──────────────┐           ┌──────────────┐
       │  MITIGATED   │           │   ACCEPTED   │ (Active Waiver)
       └──────┬───────┘           └──────┬───────┘
              │                          │ Expiration / Tamper
              ↓                          ↓
       ┌──────────────┐           ┌──────────────┐
       │   RESOLVED   │           │   EXPIRED    │
       └──────────────┘           └──────────────┘
```

---

## 2. Deterministic Fingerprinting (Zero Secret Leakage)

To correlate identical flaws across continuous CI runs without duplicating entries, findings are fingerprinted via:

$$\text{SHA-256}(\text{category} \parallel \text{test\_id} \parallel \text{rule\_id} \parallel \text{resource})$$

Raw secret tokens, sensitive payloads, or user inputs are strictly excluded from fingerprint computation.

---

## 3. Auditable Security Waivers

A `SecurityWaiver` allows temporary, explicit risk acceptance.

Mandatory invariants:
1. **Mandatory Owner**: Anonymous waivers (`owner=""`) are rejected during schema validation.
2. **Mandatory Reason**: Every waiver must explain the technical or business justification.
3. **Mandatory Expiration**: Permanent waivers (`expires_at=None`) are strictly prohibited.
4. **Scope Isolation**: A waiver scoped to `PI-001` never silences `TOOL-001`.
5. **Tamper Resistance**: Each waiver carries an internal SHA-256 checksum over its scope and parameters.

Example waiver definition:

```yaml
waivers:
  - id: WAIVER-PI-001
    owner: security-team@example.com
    reason: Benign customer support prompt format edge case
    expires_at: 1790000000
    test_id: PI-001
```
