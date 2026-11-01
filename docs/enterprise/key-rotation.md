# Cryptographic Key Rotation & Lifecycle Management

## 1. Overview

Enterprise policy integrity, tamper-proof audit trails, and token hashing require dynamic cryptographic key management. Static encryption keys stored in code or configuration files represent a critical compliance vulnerability.

`DynamicKeyManager` manages automated cryptographic key lifecycles, active/previous dual-key state for zero-downtime key rollover, configurable grace periods, and secure memory erasure.

---

## 2. Key Lifecycle State Machine

```
              ┌───────────────┐
              │  Key Created  │
              └───────┬───────┘
                      │
                      ▼
              ┌───────────────┐
              │    ACTIVE     │  ◄── Enforces new encryptions & signatures
              └───────┬───────┘
                      │ Rotation Event
                      ▼
              ┌───────────────┐
              │  GRACE_PERIOD │  ◄── Accepts verification & decryption
              └───────┬───────┘      for existing in-flight tokens
                      │ Grace period expired / Revoked
                      ▼
              ┌───────────────┐
              │   RETIRED     │  ◄── Pruned from memory
              └───────────────┘
```

---

## 3. Production Key Rotation Recipe

```python
from llmfirewall.enterprise import DynamicKeyManager

# 1. Initialize Key Manager with 24-hour grace period
key_mgr = DynamicKeyManager(
    key_name="policy-signing-key",
    grace_period_seconds=86400.0,  # 24 hours
)

# 2. Key manager generates an initial cryptographically secure 256-bit key
active_key = key_mgr.get_active_key()
print(f"Active Version: {active_key.version}") # e.g. "v1"

# 3. Perform atomic rotation when rotating secrets
rotation = key_mgr.rotate_key(description="Scheduled 90-day rotation")
print(f"Rotated from {rotation.previous_version} to {rotation.new_version}")

# 4. Decryption or signature verification supports dual-version lookup
# If token was encrypted with v1 during grace period:
token_version = "v1"
v1_key = key_mgr.get_key_for_verification(token_version)
assert v1_key is not None

# 5. Revoking a compromised key immediately
key_mgr.revoke_key(version="v1", reason="Suspected credential compromise")
# v1 is immediately rejected and pruned from memory
```

---

## 4. Key Security Invariants

1. **CSPRN Random Generation**: Keys are generated using Python standard library `secrets.token_bytes(32)`, satisfying NIST SP 800-90A CSPRNG standards.
2. **Safe Representation**: `KeyVersion` and `DynamicKeyManager` redact raw key bytes from all string formatting and debugging representations:
   ```python
   repr(active_key)
   # => "<KeyVersion(name='policy-signing-key', version='v2', created_at=1730000000.0, key_material='[REDACTED]')>"
   ```
3. **Atomic Swapping**: The switch between `active` and `previous` keys occurs under a re-entrant thread lock to prevent mid-flight race conditions during parallel requests.
