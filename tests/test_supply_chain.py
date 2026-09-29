"""Tests for Phase 28: AI Supply-Chain & Model Security."""

import json
import os
import tempfile
import pytest

from llmfirewall import (
    Action,
    ConfigArtifact,
    DependencyArtifact,
    DependencyScanner,
    DependencyScope,
    DependencySourceType,
    DeploymentMetadata,
    Firewall,
    FirewallConfig,
    IntegrityManager,
    IntegrityResult,
    IntegrityStatus,
    ModelApprovalStatus,
    ModelArtifact,
    ModelFormat,
    ModelLoadingGuard,
    ModelManifest,
    ModelProvenance,
    ModelSecurityDecision,
    ModelSecurityRegistry,
    ModelSourceType,
    ModelTrustLevel,
    ModelVerifier,
    OfflineVulnerabilityProvider,
    PolicyArtifact,
    PromptArtifact,
    SecuritySnapshot,
    SnapshotDiff,
    VulnerabilityFinding,
    compute_streaming_hash,
    detect_model_format,
    hash_configuration,
    hash_policy_artifact,
    hash_prompt_artifact,
    is_unsafe_serialization,
)
from llmfirewall.core.exceptions import BlockedPromptError


@pytest.fixture
def mock_model_file():
    """Create a temporary deterministic model file for verification testing."""
    with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as f:
        f.write(b"MOCK_MODEL_WEIGHTS_DATA_BLOCK_1234567890")
        f.flush()
        file_path = f.name
    yield file_path
    if os.path.exists(file_path):
        os.remove(file_path)


@pytest.fixture
def unsafe_pickle_model_file():
    """Create a temporary synthetic file matching pickle magic headers without executing payload."""
    with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
        # Protocol 4 magic header: \x80\x04
        f.write(b"\x80\x04\x95\x10\x00\x00\x00\x00\x00\x00\x00}\x94.")
        f.flush()
        file_path = f.name
    yield file_path
    if os.path.exists(file_path):
        os.remove(file_path)


def test_streaming_hash_correct_and_wrong(mock_model_file):
    """Test cryptographic SHA-256 and SHA-512 streaming hash calculation and verification."""
    actual_sha256 = compute_streaming_hash(mock_model_file, algorithm="sha256")
    actual_sha512 = compute_streaming_hash(mock_model_file, algorithm="sha512")
    assert len(actual_sha256) == 64
    assert len(actual_sha512) == 128

    verifier = ModelVerifier()

    # 1. Correct hash match
    res_match = verifier.verify_artifact(mock_model_file, expected_hash=actual_sha256)
    assert res_match.status == IntegrityStatus.MATCH
    assert res_match.actual_hash == actual_sha256

    # 2. Hash mismatch
    res_mismatch = verifier.verify_artifact(mock_model_file, expected_hash="0000000000000000000000000000000000000000000000000000000000000000")
    assert res_mismatch.status == IntegrityStatus.MISMATCH

    # 3. Missing expected hash
    res_unavail = verifier.verify_artifact(mock_model_file, expected_hash=None)
    assert res_unavail.status == IntegrityStatus.UNAVAILABLE
    assert res_unavail.actual_hash == actual_sha256

    # 4. Non-existent file
    res_err = verifier.verify_artifact("/path/does/not/exist/model.bin", expected_hash=actual_sha256)
    assert res_err.status == IntegrityStatus.ERROR


def test_model_format_detection_and_unsafe_serialization(mock_model_file, unsafe_pickle_model_file):
    """Test format detection and safe detection of executable serialization formats."""
    # Safe format
    fmt_safe = detect_model_format(mock_model_file)
    assert fmt_safe == ModelFormat.SAFETENSORS
    assert not is_unsafe_serialization(fmt_safe)

    # Unsafe pickle format
    fmt_unsafe = detect_model_format(unsafe_pickle_model_file)
    assert fmt_unsafe == ModelFormat.PICKLE
    assert is_unsafe_serialization(fmt_unsafe)


def test_model_evaluator_unsafe_serialization_policy(unsafe_pickle_model_file):
    """Test that attempting to evaluate an unsafe serialization model causes BLOCK finding."""
    verifier = ModelVerifier(allow_unsafe_serialization=False, require_hash=False)
    artifact = ModelArtifact(
        name="unsafe_pickle_model",
        version="1.0.0",
        location=unsafe_pickle_model_file,
        format=ModelFormat.PICKLE,
        source="local",
    )
    decision = verifier.evaluate_model(artifact)
    assert decision.action == Action.BLOCK
    assert any(f.metadata.get("violation") == "MODEL_FORMAT_UNSAFE" for f in decision.findings)


def test_model_loading_guard_context_manager(mock_model_file, unsafe_pickle_model_file):
    """Test ModelLoadingGuard context manager allowing valid models and raising BlockedPromptError on unsafe models."""
    sha = compute_streaming_hash(mock_model_file)
    guard = ModelLoadingGuard()

    # Allowed safe model
    with guard.guard(model_name="safe_model", path_or_location=mock_model_file, expected_hash=sha) as dec:
        assert dec.action == Action.ALLOW
        assert dec.hash_status == IntegrityStatus.MATCH

    # Blocked unsafe model raises BlockedPromptError
    with pytest.raises(BlockedPromptError) as exc_info:
        with guard.guard(model_name="unsafe_model", path_or_location=unsafe_pickle_model_file):
            pass
    assert "MODEL_FORMAT_UNSAFE" in str(exc_info.value) or "blocked" in str(exc_info.value).lower()


def test_model_security_registry_and_revocation(mock_model_file):
    """Test registering models, detecting changes (same version different hash), and explicit revocation."""
    reg = ModelSecurityRegistry()
    sha_v1 = "1111111111111111111111111111111111111111111111111111111111111111"
    sha_v1_tampered = "2222222222222222222222222222222222222222222222222222222222222222"

    reg.register_approval("prod_model", version="1.0.0", sha256=sha_v1)
    prov = reg.get_provenance("prod_model")
    assert prov.approval_status == ModelApprovalStatus.APPROVED

    # Tampered model detection
    tampered_artifact = ModelArtifact(
        name="prod_model",
        version="1.0.0",
        sha256=sha_v1_tampered,
    )
    drift_finding = reg.detect_model_change(tampered_artifact)
    assert drift_finding is not None
    assert drift_finding.metadata["violation"] == "MODEL_ARTIFACT_CHANGED"

    # Revocation
    reg.revoke_model("prod_model", reason="Compromised credentials")
    assert reg.is_revoked("prod_model")
    assert reg.get_provenance("prod_model").approval_status == ModelApprovalStatus.REVOKED


def test_model_manifest_parsing(tmp_path):
    """Test safe parsing of a models manifest without arbitrary code execution."""
    manifest_file = tmp_path / "models.json"
    manifest_data = {
        "version": "1.0",
        "models": {
            "llama-guard": {
                "version": "3.0.0",
                "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                "source": "internal_registry",
                "format": "safetensors",
            }
        },
    }
    manifest_file.write_text(json.dumps(manifest_data), encoding="utf-8")

    manifest = ModelManifest.load_from_file(manifest_file)
    assert manifest.version == "1.0"
    m = manifest.get_model("llama-guard")
    assert m is not None
    assert m.version == "3.0.0"
    assert m.format == ModelFormat.SAFETENSORS
    assert m.source == "internal_registry"


def test_dependency_scanner_offline_and_policy():
    """Test offline dependency inventory scan, allowlist/blocklist policy, and SBOM generation."""
    scanner = DependencyScanner(
        blocked_packages=["malicious-pkg"],
        allowed_packages=None,
    )
    deps = scanner.scan_environment()
    assert isinstance(deps, list)
    assert len(deps) > 0  # At least current environment packages (pytest, pydantic, etc.)

    # Synthetic check with blocked package
    synthetic_deps = [
        DependencyArtifact(name="pydantic", version="2.0.0", scope=DependencyScope.DIRECT),
        DependencyArtifact(name="malicious-pkg", version="1.0.0", scope=DependencyScope.DIRECT),
    ]
    findings = scanner.evaluate_dependencies(synthetic_deps)
    assert len(findings) == 1
    assert findings[0].metadata["violation"] == "DEPENDENCY_BLOCKED"

    # SBOM generation (CycloneDX & normalized)
    cyclonedx_sbom = scanner.generate_sbom(synthetic_deps, format_type="cyclonedx")
    assert cyclonedx_sbom["bomFormat"] == "CycloneDX"
    assert len(cyclonedx_sbom["components"]) == 2

    norm_sbom = scanner.generate_sbom(synthetic_deps, format_type="normalized")
    assert norm_sbom["schema_version"] == "1"
    assert len(norm_sbom["dependencies"]) == 2


def test_vulnerability_provider_offline_intelligence():
    """Test OfflineVulnerabilityProvider matching advisory databases."""
    vuln_db = {
        "vulnerable_lib": [
            {
                "id": "CVE-2024-9999",
                "severity": "CRITICAL",
                "summary": "Remote code execution in vulnerable_lib",
                "affected_versions": ["1.0.0"],
                "fixed_versions": ["1.0.1"],
            }
        ]
    }
    provider = OfflineVulnerabilityProvider(local_advisories=vuln_db)
    scanner = DependencyScanner(vulnerability_provider=provider)

    deps = [
        DependencyArtifact(name="vulnerable_lib", version="1.0.0"),
        DependencyArtifact(name="safe_lib", version="2.0.0"),
    ]
    findings = scanner.evaluate_dependencies(deps)
    assert len(findings) == 1
    assert findings[0].metadata["violation"] == "VULNERABILITY_FOUND"
    assert findings[0].metadata["cve"] == "CVE-2024-9999"


def test_configuration_integrity_and_secret_safety():
    """Test that configuration hashing strips sensitive secrets and detects configuration drift."""
    config_1 = {
        "temperature": 0.7,
        "api_key": "sk-secret-1234567890",
        "model": "gpt-4o",
    }
    config_2 = {
        "temperature": 0.7,
        "api_key": "sk-secret-different-password",  # Secret changed, but non-secret parameters identical
        "model": "gpt-4o",
    }
    config_drifted = {
        "temperature": 1.5,  # Parameter drifted
        "api_key": "sk-secret-1234567890",
        "model": "gpt-4o",
    }

    art1 = hash_configuration(config_1, config_type="runtime_hyperparameters")
    art2 = hash_configuration(config_2, config_type="runtime_hyperparameters")
    art3 = hash_configuration(config_drifted, config_type="runtime_hyperparameters")

    # Hashes of art1 and art2 must match because api_key was safely redacted
    assert art1.sha256 == art2.sha256
    assert art1.sha256 != art3.sha256

    # Drift manager
    mgr = IntegrityManager()
    mgr.set_baseline_config(art1)

    assert mgr.check_config_drift(config_2, config_type="runtime_hyperparameters") is None
    drift_f = mgr.check_config_drift(config_drifted, config_type="runtime_hyperparameters")
    assert drift_f is not None
    assert drift_f.metadata["violation"] == "SECURITY_CONFIG_DRIFT"


def test_security_snapshot_creation_and_diff():
    """Test SecuritySnapshot generation and drift diffing."""
    fw = Firewall()
    snap1 = fw.create_security_snapshot(application_version="1.0.0")
    assert len(snap1.snapshot_hash) == 64
    assert len(snap1.dependencies) > 0

    # Diff with self
    diff_same = snap1.diff(snap1)
    assert diff_same.is_identical
    assert len(diff_same.models_changed) == 0

    # Create modified candidate snapshot with an additional model
    snap2 = SecuritySnapshot.create(
        deployment=DeploymentMetadata(application_version="1.0.1"),
        models=[ModelArtifact(name="new_model", version="1.0.0", sha256="abc")],
        dependencies=snap1.dependencies,
        configurations=snap1.configurations,
        policies=snap1.policies,
        prompts=snap1.prompts,
    )

    diff_changed = snap1.diff(snap2)
    assert not diff_changed.is_identical
    assert "new_model" in diff_changed.models_added


def test_firewall_integration_verify_model_and_snapshot(mock_model_file):
    """Test top-level Firewall.verify_model() and Firewall.create_security_snapshot()."""
    fw = Firewall()
    sha = compute_streaming_hash(mock_model_file)

    # 1. Successful verification
    decision = fw.verify_model(path_or_location=mock_model_file, expected_hash=sha, model_name="test_model")
    assert decision.action == Action.ALLOW
    assert decision.hash_status == IntegrityStatus.MATCH

    # 2. Hash mismatch verification
    decision_bad = fw.verify_model(
        path_or_location=mock_model_file,
        expected_hash="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        model_name="test_model",
    )
    assert decision_bad.action == Action.BLOCK
    assert decision_bad.hash_status == IntegrityStatus.MISMATCH

    # 3. Snapshot
    snapshot = fw.create_security_snapshot()
    assert snapshot.snapshot_hash
    assert len(snapshot.configurations) > 0
