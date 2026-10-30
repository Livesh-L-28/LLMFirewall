"""Unit, integration, and security tests for Phase 64 — Security Data Persistence."""

from datetime import datetime, timezone
import json
import pytest

from llmfirewall.persistence import (
    EncryptedStorageAdapter,
    InMemoryPersistenceAdapter,
    JSONLPersistenceAdapter,
    PersistenceRecord,
    SQLitePersistenceAdapter,
    StorageFilter,
)
from llmfirewall.persistence.encryption import _HAS_CRYPTOGRAPHY

crypto_required = pytest.mark.skipif(
    not _HAS_CRYPTOGRAPHY,
    reason="cryptography library is not installed (install with: pip install 'llmfirewall-core[crypto]')",
)


def test_record_checksum_and_tamper_detection():
    """Verify that PersistenceRecord automatically computes sha256 checksum and flags tampering."""
    record = PersistenceRecord(
        record_type="audit_event",
        payload={"event": "prompt_injection_blocked", "severity": "HIGH", "score": 0.95},
    )
    assert record.checksum != ""
    assert record.verify_integrity() is True

    # Tampered payload
    tampered = PersistenceRecord.model_construct(
        id=record.id,
        tenant_id=record.tenant_id,
        record_type=record.record_type,
        timestamp=record.timestamp,
        payload={"event": "prompt_injection_blocked", "severity": "LOW"},  # downgraded!
        checksum=record.checksum,
    )
    assert tampered.verify_integrity() is False


def test_in_memory_persistence_adapter():
    """Verify bounded capacity and filtering in InMemoryPersistenceAdapter."""
    adapter = InMemoryPersistenceAdapter(max_records=3)

    for i in range(5):
        adapter.save(
            PersistenceRecord(
                id=f"rec-{i}",
                tenant_id="tenant-alpha" if i % 2 == 0 else "tenant-beta",
                record_type="scan_event",
                payload={"index": i},
            )
        )

    assert adapter.count() == 3  # Evicted rec-0 and rec-1
    assert adapter.get("rec-0") is None
    assert adapter.get("rec-4") is not None

    # Query tenant partition
    alpha_records = adapter.query(StorageFilter(tenant_id="tenant-alpha"))
    assert all(r.tenant_id == "tenant-alpha" for r in alpha_records)


def test_jsonl_persistence_adapter(tmp_path):
    """Verify JSONLPersistenceAdapter durability, reload, and query."""
    file_path = tmp_path / "security_audit.jsonl"
    adapter = JSONLPersistenceAdapter(str(file_path))

    r1 = PersistenceRecord(
        id="rec-j1",
        tenant_id="tenant-finance",
        record_type="alert",
        payload={"metric": "secret_leak"},
    )
    r2 = PersistenceRecord(
        id="rec-j2",
        tenant_id="tenant-hr",
        record_type="alert",
        payload={"metric": "pii_leak"},
    )
    adapter.save(r1)
    adapter.save(r2)

    assert adapter.count() == 2
    assert adapter.count(tenant_id="tenant-finance") == 1

    fetched = adapter.get("rec-j1")
    assert fetched is not None
    assert fetched.payload["metric"] == "secret_leak"

    # Reload from fresh adapter instance
    adapter2 = JSONLPersistenceAdapter(str(file_path))
    results = adapter2.query(StorageFilter(tenant_id="tenant-hr"))
    assert len(results) == 1
    assert results[0].id == "rec-j2"


def test_sqlite_persistence_adapter(tmp_path):
    """Verify SQLitePersistenceAdapter relational queries, tenant isolation, and pagination."""
    db_file = tmp_path / "audit.db"
    adapter = SQLitePersistenceAdapter(str(db_file))

    for i in range(10):
        adapter.save(
            PersistenceRecord(
                id=f"sql-{i}",
                tenant_id="tenant-eu" if i < 5 else "tenant-us",
                record_type="event",
                payload={"index": i},
            )
        )

    assert adapter.count() == 10
    assert adapter.count("tenant-eu") == 5
    assert adapter.count("tenant-us") == 5

    # Paginated query
    page1 = adapter.query(StorageFilter(tenant_id="tenant-eu", limit=3, offset=0))
    assert len(page1) == 3
    page2 = adapter.query(StorageFilter(tenant_id="tenant-eu", limit=3, offset=3))
    assert len(page2) == 2

    adapter.close()


@crypto_required
def test_encrypted_storage_adapter():
    """Verify EncryptedStorageAdapter secures payload at rest and prevents tampering."""
    raw_adapter = InMemoryPersistenceAdapter()
    crypto_adapter = EncryptedStorageAdapter(raw_adapter, secret_key="super-secret-key-32-chars-long!")

    rec = PersistenceRecord(
        id="enc-1",
        tenant_id="tenant-vault",
        record_type="sensitive_audit",
        payload={"raw_user_id": "usr_99182", "auth_token_hash": "a1b2c3d4"},
    )
    crypto_adapter.save(rec)

    # 1. Inspect underlying raw storage: MUST NOT contain plaintext
    raw_stored = raw_adapter.get("enc-1")
    assert raw_stored is not None
    assert raw_stored.payload.get("__encrypted") is True
    assert "usr_99182" not in json.dumps(raw_stored.payload)

    # 2. Retrieve via crypto adapter: cleanly decrypted
    decrypted = crypto_adapter.get("enc-1")
    assert decrypted is not None
    assert decrypted.payload["raw_user_id"] == "usr_99182"

    # 3. Tampering with encrypted payload triggers ValueError
    import base64
    tampered_payload = dict(raw_stored.payload)
    tampered_payload["ciphertext"] = base64.b64encode(b"corrupted_tampered_bytes").decode("ascii")
    tampered_rec = PersistenceRecord(
        id="enc-tampered",
        record_type="sensitive_audit",
        payload=tampered_payload,
    )
    raw_adapter.save(tampered_rec)

    with pytest.raises(ValueError, match="Integrity check failed"):
        crypto_adapter.get("enc-tampered")


@crypto_required
def test_encrypted_storage_single_bit_tamper_detection():
    """Verify that flipping even a single bit in ciphertext or tag fails authentication."""
    import base64
    raw_adapter = InMemoryPersistenceAdapter()
    crypto_adapter = EncryptedStorageAdapter(raw_adapter, secret_key="secure-key-for-bit-flip-test-123")

    rec = PersistenceRecord(
        id="rec-bitflip",
        record_type="audit",
        payload={"secret_key": "confidential_api_token"},
    )
    crypto_adapter.save(rec)

    raw_rec = raw_adapter.get("rec-bitflip")
    assert raw_rec is not None

    # Flip bit 0 of the first byte of ciphertext
    ct_bytes = bytearray(base64.b64decode(raw_rec.payload["ciphertext"]))
    ct_bytes[0] ^= 0x01
    tampered_payload = dict(raw_rec.payload)
    tampered_payload["ciphertext"] = base64.b64encode(bytes(ct_bytes)).decode("ascii")

    raw_adapter.save(PersistenceRecord(id="rec-bitflip", record_type="audit", payload=tampered_payload))

    with pytest.raises(ValueError, match="Integrity check failed"):
        crypto_adapter.get("rec-bitflip")


@crypto_required
def test_encrypted_storage_wrong_key_rejection():
    """Verify that an adapter initialized with a different key cannot decrypt payloads."""
    raw_adapter = InMemoryPersistenceAdapter()
    adapter_a = EncryptedStorageAdapter(raw_adapter, secret_key="key-for-tenant-alpha-encryption-1")
    adapter_b = EncryptedStorageAdapter(raw_adapter, secret_key="key-for-tenant-beta-encryption-22")

    rec = PersistenceRecord(
        id="rec-secret-a",
        record_type="audit",
        payload={"authorized_user": "alice", "clearance": "top_secret"},
    )
    adapter_a.save(rec)

    # Valid read under correct key
    assert adapter_a.get("rec-secret-a").payload["authorized_user"] == "alice"

    # Attempted read under wrong key fails-closed
    with pytest.raises(ValueError, match="Integrity check failed"):
        adapter_b.get("rec-secret-a")


@crypto_required
def test_encrypted_storage_key_rotation():
    """Verify key rotation: new key writes, but previous_keys decrypts legacy records."""
    raw_adapter = InMemoryPersistenceAdapter()
    old_key = "old-legacy-key-phase64-secret-key-1"
    new_key = "new-active-key-phase64-secret-key-2"

    legacy_adapter = EncryptedStorageAdapter(raw_adapter, secret_key=old_key)
    legacy_adapter.save(PersistenceRecord(id="rec-legacy", record_type="audit", payload={"phase": "v1.1"}))

    # Rotated adapter configured with new key and previous old key
    rotated_adapter = EncryptedStorageAdapter(raw_adapter, secret_key=new_key, previous_keys=[old_key])

    # Should transparently decrypt legacy record
    recovered = rotated_adapter.get("rec-legacy")
    assert recovered is not None
    assert recovered.payload["phase"] == "v1.1"

    # New writes use new key
    rotated_adapter.save(PersistenceRecord(id="rec-new", record_type="audit", payload={"phase": "v1.2"}))
    assert rotated_adapter.get("rec-new").payload["phase"] == "v1.2"


@crypto_required
def test_encrypted_storage_aad_swap_attack_prevention():
    """Verify that swapping an encrypted payload to a different record ID or tenant fails AAD check."""
    raw_adapter = InMemoryPersistenceAdapter()
    crypto_adapter = EncryptedStorageAdapter(raw_adapter, secret_key="aad-binding-verification-key-123")

    rec_a = PersistenceRecord(
        id="rec-victim",
        tenant_id="tenant-victim",
        record_type="audit",
        payload={"financial_balance": 1000000},
    )
    crypto_adapter.save(rec_a)

    stored_a = raw_adapter.get("rec-victim")
    assert stored_a is not None

    # Attacker tries to transplant record A's encrypted payload into record B
    swapped_rec = PersistenceRecord(
        id="rec-attacker",
        tenant_id="tenant-attacker",
        record_type="audit",
        payload=stored_a.payload,
    )
    raw_adapter.save(swapped_rec)

    with pytest.raises(ValueError, match="Integrity check failed"):
        crypto_adapter.get("rec-attacker")


@crypto_required
def test_encrypted_storage_confidentiality_and_nonce_uniqueness():
    """Verify semantic security: identical plaintexts produce distinct nonces and distinct ciphertexts."""
    raw_adapter = InMemoryPersistenceAdapter()
    crypto_adapter = EncryptedStorageAdapter(raw_adapter, secret_key="nonce-uniqueness-test-key-12345")

    identical_payload = {"fixed_command": "EXECUTE_AUTHORIZED_ACTION", "param": 42}
    nonces = set()
    ciphertexts = set()

    for i in range(50):
        rec_id = f"unique-{i}"
        crypto_adapter.save(PersistenceRecord(id=rec_id, record_type="audit", payload=identical_payload))
        raw = raw_adapter.get(rec_id)
        assert raw is not None
        nonces.add(raw.payload["nonce"])
        ciphertexts.add(raw.payload["ciphertext"])

    # All 50 nonces and all 50 ciphertexts must be distinct
    assert len(nonces) == 50
    assert len(ciphertexts) == 50


@crypto_required
def test_encrypted_storage_malformed_and_key_masking():
    """Verify malformed envelope rejection and key masking in __repr__."""
    raw_adapter = InMemoryPersistenceAdapter()
    key = "super-secret-key-that-must-never-leak"
    crypto_adapter = EncryptedStorageAdapter(raw_adapter, secret_key=key)

    # 1. Key must never leak in repr()
    repr_str = repr(crypto_adapter)
    assert key not in repr_str
    assert "masked" in repr_str

    # 2. Key generator utility
    gen_key = EncryptedStorageAdapter.generate_key()
    assert len(gen_key) >= 32

    # 3. Missing nonce or corrupted base64 in envelope
    malformed_rec = PersistenceRecord(
        id="rec-malformed",
        record_type="audit",
        payload={"__encrypted": True, "ciphertext": "not-valid-base64-%%$#"},
    )
    raw_adapter.save(malformed_rec)
    with pytest.raises(ValueError, match="Integrity check failed"):
        crypto_adapter.get("rec-malformed")


def test_encrypted_storage_adapter_absent_dependency_error(monkeypatch):
    """Verify EncryptedStorageAdapter fails closed with actionable message when cryptography is absent."""
    import llmfirewall.persistence.encryption as enc_module

    raw_adapter = InMemoryPersistenceAdapter()
    monkeypatch.setattr(enc_module, "_HAS_CRYPTOGRAPHY", False)

    with pytest.raises(RuntimeError, match="Install it with 'pip install cryptography' or 'pip install llmfirewall-core\\[crypto\\]'"):
        enc_module.EncryptedStorageAdapter(raw_adapter, secret_key="super-secret-key-32-chars-long!")
