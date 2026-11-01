# Enterprise Secrets Management & Vault Integration

## 1. Overview

Enterprise AI firewalls require dynamic access to sensitive credentials, encryption keys, and external service tokens without baking secrets into container images, environment variables, or config maps.

LLMFirewall-Core provides an extensible secrets abstraction hierarchy with native support for HashiCorp Vault KV v2 engines, Kubernetes secret projections, and environment overrides.

---

## 2. Secrets Provider Hierarchy

```
                      ┌────────────────────────────┐
                      │     BaseSecretProvider     │
                      │  (Abstract TTL-Cached Base)│
                      └──────────────┬─────────────┘
                                     │
         ┌───────────────────────────┼───────────────────────────┐
         ▼                           ▼                           ▼
┌──────────────────┐       ┌──────────────────┐       ┌─────────────────────┐
│ EnvSecretProvider│       │FileSecretProvider│       │ VaultSecretProvider │
│ (Environment)    │       │(Kubernetes /tmp) │       │(HashiCorp Vault v2) │
└──────────────────┘       └──────────────────┘       └─────────────────────┘
```

### 2.1 Supported Providers

| Provider | Description | Best Suited For |
| :--- | :--- | :--- |
| `EnvSecretProvider` | Reads secrets from process environment variables. | Local development and container testing. |
| `FileSecretProvider` | Reads secrets from filesystem paths (e.g., Kubernetes projected volumes). | Production Kubernetes with HashiCorp Vault Agent or External Secrets Operator. |
| `VaultSecretProvider` | Direct API integration with HashiCorp Vault KV v2 engine. Uses standard library `urllib` if `hvac` is not installed. | Enterprise deployments requiring dynamic secret retrieval and zero third-party package dependencies. |

---

## 3. HashiCorp Vault Integration Recipe

`VaultSecretProvider` connects directly to Vault over TLS. It supports automatic TTL caching to avoid throttling Vault clusters under high request volumes.

```python
from llmfirewall.enterprise import VaultSecretProvider

# Initialize provider against HashiCorp Vault KV-v2
vault = VaultSecretProvider(
    vault_url="https://vault.internal.corp:8200",
    token="s.enterprise_service_account_token",
    mount_point="secret",  # Default KV-v2 mount point
    ttl_seconds=300.0,      # Cache secrets in-process for 5 minutes
    verify_tls=True,
)

# Fetch secret key from path: secret/data/llmfirewall/api-keys
api_key = vault.get_secret("llmfirewall/api-keys", key="openai_key")
```

---

## 4. Kubernetes Projected Volume Recipe

When using Kubernetes Projected Volumes or CSI Secret Store Driver, secrets are mounted into `/var/run/secrets/llmfirewall`:

```python
from llmfirewall.enterprise import FileSecretProvider

provider = FileSecretProvider(base_directory="/var/run/secrets/llmfirewall")
signing_key = provider.get_secret("crypto/signing_key.pem")
```

---

## 5. Security Invariants & Zero-Exposure Guarantees

1. **Zero Secret Representation in Logs**: All secret providers and models override `__repr__` and `__str__` to prevent credentials from ever leaking in stack traces or logs:
   ```python
   repr(vault) # => "<VaultSecretProvider(vault_url='https://vault.internal.corp:8200', mount='secret')>"
   ```
2. **Deterministic Cache Expiry**: When `ttl_seconds` elapses, cached values are evicted and re-read from the authoritative source.
3. **Graceful Fallbacks**: If Vault becomes temporarily unreachable and cached data exists within a soft grace period, the cached value is returned alongside an audit warning.
