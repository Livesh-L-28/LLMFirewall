"""Dynamic Secrets and Cryptographic Key Management subsystem."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import hashlib
import json
import logging
import os
from pathlib import Path
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger("llmfirewall.enterprise.secrets")


class SecretNotFoundError(Exception):
    """Raised when a requested secret key cannot be found in the provider."""
    def __init__(self, key_name: str, provider_name: str) -> None:
        super().__init__(f"Secret '{key_name}' not found in provider '{provider_name}'")
        self.key_name = key_name
        self.provider_name = provider_name


class BaseSecretProvider(ABC):
    """Abstract interface for provider-independent secret retrieval."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        pass

    @abstractmethod
    def get_secret(self, key_name: str) -> Optional[str]:
        """Retrieve plaintext secret string by key name."""
        pass

    def has_secret(self, key_name: str) -> bool:
        """Check availability without logging or leaking secret material."""
        try:
            return self.get_secret(key_name) is not None
        except Exception:
            return False


class EnvSecretProvider(BaseSecretProvider):
    """Reads secrets from process environment variables."""

    def __init__(self, prefix: str = "") -> None:
        self.prefix = prefix

    @property
    def provider_name(self) -> str:
        return "environment"

    def get_secret(self, key_name: str) -> Optional[str]:
        env_var = f"{self.prefix}{key_name}"
        return os.environ.get(env_var)


class FileSecretProvider(BaseSecretProvider):
    """Reads secrets from mounted container filesystem (Kubernetes Secrets / Docker Secrets)."""

    def __init__(self, secrets_dir: Union[str, Path] = "/var/run/secrets") -> None:
        self.secrets_dir = Path(secrets_dir)

    @property
    def provider_name(self) -> str:
        return "filesystem"

    def get_secret(self, key_name: str) -> Optional[str]:
        file_path = self.secrets_dir / key_name
        if not file_path.is_file():
            return None
        try:
            return file_path.read_text(encoding="utf-8").strip()
        except Exception as exc:
            logger.warning("Failed to read secret file '%s': %s", key_name, exc)
            return None


class VaultSecretProvider(BaseSecretProvider):
    """HashiCorp Vault KV v2 secret engine client adapter with zero mandatory dependencies."""

    def __init__(
        self,
        vault_addr: Optional[str] = None,
        vault_token: Optional[str] = None,
        mount_point: str = "secret",
        timeout_seconds: float = 5.0,
        vault_client: Optional[Any] = None,
    ) -> None:
        self.addr = (vault_addr or os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")).rstrip("/")
        self.token = vault_token or os.environ.get("VAULT_TOKEN", "")
        self.mount = mount_point.strip("/")
        self.timeout = timeout_seconds
        self._client = vault_client  # Optional hvac.Client instance

    @property
    def provider_name(self) -> str:
        return "hashicorp_vault"

    def get_secret(self, key_name: str) -> Optional[str]:
        # Path split: e.g. "ai-gateway/openai" -> secret path "ai-gateway", field "openai"
        if "/" in key_name:
            path, field = key_name.rsplit("/", 1)
        else:
            path, field = key_name, "value"

        # 1. Use hvac client if injected
        if self._client is not None and hasattr(self._client, "secrets"):
            try:
                res = self._client.secrets.kv.v2.read_secret_version(mount_point=self.mount, path=path)
                data = res.get("data", {}).get("data", {})
                return data.get(field)
            except Exception as exc:
                logger.warning("Vault hvac read failed on '%s': %s", key_name, exc)
                return None

        # 2. Pure standard library urllib fallback (Zero external dependencies)
        import urllib.error
        import urllib.request

        url = f"{self.addr}/v1/{self.mount}/data/{path}"
        req = urllib.request.Request(
            url,
            headers={
                "X-Vault-Token": self.token,
                "Content-Type": "application/json",
            },
            method="GET",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
                secret_data = payload.get("data", {}).get("data", {})
                return secret_data.get(field)
        except urllib.error.HTTPError as http_err:
            if http_err.code == 404:
                return None
            logger.warning("Vault HTTP error %d reading '%s'", http_err.code, key_name)
            return None
        except Exception as exc:
            logger.warning("Vault network failure on '%s': %s", key_name, exc)
            return None

    def __repr__(self) -> str:
        return f"<VaultSecretProvider(addr='{self.addr}', mount='{self.mount}')>"


@dataclass
class KeyVersion:
    version: int
    key_bytes: bytes
    created_at: float = field(default_factory=time.time)
    revoked_at: Optional[float] = None

    def __repr__(self) -> str:
        return f"<KeyVersion v{self.version} created_at={self.created_at} [REDACTED_KEY_MATERIAL]>"

    def __str__(self) -> str:
        return self.__repr__()


# Backward-compatible alias
KeyMetadata = KeyVersion


@dataclass
class KeyRotationResult:
    new_version: int
    previous_version: int
    grace_period_seconds: float
    timestamp: float = field(default_factory=time.time)


class DynamicKeyManager:
    """Manages cryptographic keys with versioning, zero-downtime rotation, and grace periods.

    Guarantees:
    - Zero Downtime: Maintains active key and previous keys simultaneously.
    - Safe Encryption: Encryptions always bind to the active key version.
    - Safe Decryption: Decryptions verify active key first, then gracefully test previous unrevoked keys.
    - Zero Exposure: Secret key bytes are scrubbed from __repr__ and audit logs.
    """

    def __init__(
        self,
        initial_key: Optional[Union[str, bytes]] = None,
        grace_period_seconds: float = 86400.0,  # 24 hour default rotation grace period
    ) -> None:
        self.grace_period_seconds = max(1.0, grace_period_seconds)
        self._keys: Dict[int, KeyVersion] = {}
        self._active_version: int = 1

        if initial_key:
            raw = self._normalize_key(initial_key)
        else:
            raw = secrets.token_bytes(32)  # Secure AES-256 random key

        self._keys[1] = KeyVersion(version=1, key_bytes=raw)

    @property
    def active_version(self) -> int:
        return self._active_version

    @property
    def active_key(self) -> bytes:
        return self._keys[self._active_version].key_bytes

    def get_key(self, version: int) -> Optional[bytes]:
        kv = self._keys.get(version)
        if kv and kv.revoked_at is None:
            return kv.key_bytes
        return None

    def get_all_valid_keys(self) -> List[Tuple[int, bytes]]:
        """Returns list of (version, key_bytes) for active and unrevoked previous keys."""
        valid = []
        for v in sorted(self._keys.keys(), reverse=True):
            kv = self._keys[v]
            if kv.revoked_at is None:
                valid.append((v, kv.key_bytes))
        return valid

    def rotate_key(self, new_key: Optional[Union[str, bytes]] = None) -> KeyRotationResult:
        """Atomically promote a new active key while preserving previous keys in grace period."""
        raw = self._normalize_key(new_key) if new_key else secrets.token_bytes(32)
        prev_version = self._active_version
        new_version = prev_version + 1

        self._keys[new_version] = KeyVersion(version=new_version, key_bytes=raw)
        self._active_version = new_version

        logger.info(
            "Cryptographic key rotated: active v%d -> v%d (grace period: %.1fs)",
            prev_version,
            new_version,
            self.grace_period_seconds,
        )
        return KeyRotationResult(
            new_version=new_version,
            previous_version=prev_version,
            grace_period_seconds=self.grace_period_seconds,
        )

    def revoke_key(self, version: int, reason: str = "") -> bool:
        """Immediately revoke a specific key version."""
        kv = self._keys.get(version)
        if kv and kv.revoked_at is None:
            kv.revoked_at = time.time()
            logger.warning("Key version v%d revoked immediately. Reason: %s", version, reason)
            return True
        return False

    def __repr__(self) -> str:
        return f"<DynamicKeyManager(active_v={self._active_version}, total_keys={len(self._keys)}, [REDACTED])>"

    def prune_expired_keys(self, now: Optional[float] = None) -> int:
        """Revoke keys whose grace period has expired since rotation."""
        current_time = now or time.time()
        pruned_count = 0

        for v, kv in list(self._keys.items()):
            if v == self._active_version:
                continue
            if kv.revoked_at is None:
                # Key is previous; check if past grace period
                if current_time - kv.created_at >= self.grace_period_seconds:
                    kv.revoked_at = current_time
                    pruned_count += 1
                    logger.info("Key version v%d revoked after grace period expiration", v)

        return pruned_count

    @staticmethod
    def _normalize_key(key_material: Union[str, bytes]) -> bytes:
        if isinstance(key_material, str):
            # Derive 32 bytes via SHA-256 if string provided
            return hashlib.sha256(key_material.encode("utf-8")).digest()
        elif isinstance(key_material, bytes):
            if len(key_material) == 32:
                return key_material
            return hashlib.sha256(key_material).digest()
        raise TypeError("Key material must be str or bytes")
