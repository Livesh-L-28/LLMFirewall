"""Encrypted persistence adapter wrapper for protecting security data at rest.

Guarantees:
- Payload confidentiality via industry-standard AES-256-GCM authenticated encryption (NIST SP 800-38D).
- 96-bit cryptographically secure random nonce per record.
- Authentication, integrity, and tamper detection via 128-bit GCM authentication tag.
- Authenticated Associated Data (AAD) binding to record ID, type, and tenant to prevent swap attacks.
- Key rotation support via previous_keys parameter.
- Key generation utility via generate_key().
- Safe error handling without key or plaintext leakage.
"""

import base64
import hashlib
import json
import os
import secrets
from typing import Any, Dict, List, Optional, Union

from llmfirewall.persistence.base import BasePersistenceAdapter
from llmfirewall.persistence.models import PersistenceRecord, StorageFilter

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    AESGCM = None  # type: ignore
    _HAS_CRYPTOGRAPHY = False


class EncryptedStorageAdapter(BasePersistenceAdapter):
    """Decorator adapter that encrypts/decrypts record payloads before persisting.
    
    Uses AES-256-GCM (NIST SP 800-38D) authenticated encryption with a 96-bit random nonce
    per record. Provides payload confidentiality, tamper detection, and key rotation.
    """

    def __init__(
        self,
        inner_adapter: BasePersistenceAdapter,
        secret_key: Union[str, bytes],
        previous_keys: Optional[List[Union[str, bytes]]] = None,
    ) -> None:
        if not _HAS_CRYPTOGRAPHY:
            raise RuntimeError(
                "The 'cryptography' library is required to use EncryptedStorageAdapter. "
                "Install it with 'pip install cryptography' or 'pip install llmfirewall-core[crypto]'."
            )
        if isinstance(secret_key, str) and len(secret_key) < 16:
            raise ValueError("secret_key must be at least 16 characters long")
        elif isinstance(secret_key, bytes) and len(secret_key) < 16:
            raise ValueError("secret_key must be at least 16 bytes long")

        self._inner = inner_adapter
        self._key = self._derive_key(secret_key)
        self._previous_keys: List[bytes] = [self._derive_key(k) for k in (previous_keys or [])]

    @staticmethod
    def _derive_key(key_material: Union[str, bytes]) -> bytes:
        if isinstance(key_material, str):
            key_bytes = key_material.encode("utf-8")
        else:
            key_bytes = key_material
        if len(key_bytes) == 32:
            return key_bytes
        return hashlib.sha256(key_bytes).digest()

    @staticmethod
    def generate_key() -> str:
        """Generate a cryptographically secure 256-bit URL-safe secret key for AES-256-GCM."""
        return secrets.token_urlsafe(32)

    def __repr__(self) -> str:
        return f"EncryptedStorageAdapter(inner={self._inner!r}, algorithm='AES-256-GCM', key='***masked***')"

    def _encrypt_payload(self, payload: Dict[str, Any], aad: Optional[bytes] = None) -> Dict[str, Any]:
        """Encrypt payload into an AES-256-GCM protected envelope."""
        plain_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        nonce = os.urandom(12)  # 96-bit standard GCM nonce
        aesgcm = AESGCM(self._key)
        ct_with_tag = aesgcm.encrypt(nonce, plain_bytes, aad)

        # In AESGCM, the last 16 bytes are the 128-bit authentication tag
        cipher_bytes = ct_with_tag[:-16]
        tag_bytes = ct_with_tag[-16:]

        envelope: Dict[str, Any] = {
            "__encrypted": True,
            "version": "1.2",
            "algorithm": "AES-256-GCM",
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "salt": base64.b64encode(nonce).decode("ascii"),  # Backward compatibility alias
            "ciphertext": base64.b64encode(cipher_bytes).decode("ascii"),
            "auth_tag": base64.b64encode(tag_bytes).decode("ascii"),
        }
        if aad is not None:
            envelope["aad_bound"] = True
        return envelope

    def _decrypt_payload(self, envelope: Dict[str, Any], aad: Optional[bytes] = None) -> Dict[str, Any]:
        """Decrypt payload from AES-256-GCM protected envelope."""
        if not isinstance(envelope, dict) or not envelope.get("__encrypted"):
            return envelope  # Pass through unencrypted payloads safely

        try:
            nonce_b64 = envelope.get("nonce") or envelope.get("salt")
            if not nonce_b64 or not envelope.get("ciphertext"):
                raise ValueError("Malformed encrypted envelope: missing nonce or ciphertext")
            nonce = base64.b64decode(nonce_b64)
            cipher_bytes = base64.b64decode(envelope["ciphertext"])

            if "auth_tag" in envelope and envelope["auth_tag"]:
                tag_bytes = base64.b64decode(envelope["auth_tag"])
                ct_with_tag = cipher_bytes + tag_bytes
            else:
                ct_with_tag = cipher_bytes
        except Exception as e:
            if isinstance(e, ValueError) and "Integrity check failed" in str(e):
                raise
            raise ValueError(f"Integrity check failed: invalid or corrupted ciphertext encoding ({e})") from e

        # If envelope was encrypted with AAD binding, ensure aad is passed
        effective_aad = aad if envelope.get("aad_bound") else None

        all_keys = [self._key] + self._previous_keys
        for key in all_keys:
            try:
                aesgcm = AESGCM(key)
                plain_bytes = aesgcm.decrypt(nonce, ct_with_tag, effective_aad)
                return json.loads(plain_bytes.decode("utf-8"))
            except Exception:
                continue

        raise ValueError("Integrity check failed: corrupted, tampered, or wrong key")

    def save(self, record: PersistenceRecord) -> str:
        aad = f"{record.id}:{record.record_type}:{record.tenant_id or ''}".encode("utf-8")
        encrypted_payload = self._encrypt_payload(record.payload, aad=aad)
        enc_record = PersistenceRecord(
            id=record.id,
            tenant_id=record.tenant_id,
            record_type=record.record_type,
            timestamp=record.timestamp,
            payload=encrypted_payload,
        )
        return self._inner.save(enc_record)

    def get(self, record_id: str) -> Optional[PersistenceRecord]:
        rec = self._inner.get(record_id)
        if not rec:
            return None
        aad = f"{rec.id}:{rec.record_type}:{rec.tenant_id or ''}".encode("utf-8")
        decrypted_payload = self._decrypt_payload(rec.payload, aad=aad)
        return PersistenceRecord(
            id=rec.id,
            tenant_id=rec.tenant_id,
            record_type=rec.record_type,
            timestamp=rec.timestamp,
            payload=decrypted_payload,
        )

    def query(self, filter_params: Optional[StorageFilter] = None) -> List[PersistenceRecord]:
        records = self._inner.query(filter_params)
        decrypted_list: List[PersistenceRecord] = []
        for r in records:
            aad = f"{r.id}:{r.record_type}:{r.tenant_id or ''}".encode("utf-8")
            decrypted_payload = self._decrypt_payload(r.payload, aad=aad)
            decrypted_list.append(
                PersistenceRecord(
                    id=r.id,
                    tenant_id=r.tenant_id,
                    record_type=r.record_type,
                    timestamp=r.timestamp,
                    payload=decrypted_payload,
                )
            )
        return decrypted_list

    def count(self, tenant_id: Optional[str] = None) -> int:
        return self._inner.count(tenant_id)

    def close(self) -> None:
        self._inner.close()
