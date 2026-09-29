"""Cryptographic model artifact verification and format security inspection."""

import hmac
import hashlib
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from llmfirewall.core.models import Action, Finding, Severity, ThreatType
from llmfirewall.supply_chain.models import (
    IntegrityResult,
    IntegrityStatus,
    ModelArtifact,
    ModelFormat,
    ModelSecurityDecision,
    ModelSourceType,
)
from llmfirewall.tools.path_security import validate_path_safety

# Chunk size for streaming file reads: 64 KB (bounded memory usage for multi-GB models)
HASH_CHUNK_SIZE = 64 * 1024

# Serialization format indicators and magic bytes
PICKLE_MAGIC_PREFIXES = [
    b"\x80\x02",  # Protocol 2
    b"\x80\x03",  # Protocol 3
    b"\x80\x04",  # Protocol 4
    b"\x80\x05",  # Protocol 5
]
TORCH_MAGIC_ZIP = b"PK\x03\x04"  # Modern torch save files are zip archives containing pickle bytecode


def compute_streaming_hash(
    file_path: Union[str, Path],
    algorithm: str = "sha256",
    chunk_size: int = HASH_CHUNK_SIZE,
) -> str:
    """Compute cryptographic hash of a file using streaming reads to bound memory consumption.
    
    Args:
        file_path: Absolute or relative path to target file.
        algorithm: 'sha256' or 'sha512'.
        chunk_size: Byte size of chunks read per iteration (default 64 KB).
        
    Returns:
        Hex-encoded digest string.
        
    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If unsupported hash algorithm requested.
    """
    algo = algorithm.lower().strip()
    if algo == "sha256":
        hasher = hashlib.sha256()
    elif algo == "sha512":
        hasher = hashlib.sha512()
    else:
        raise ValueError(f"Unsupported hash algorithm '{algorithm}'. Supported: sha256, sha512")

    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)

    return hasher.hexdigest()


def detect_model_format(file_path: Union[str, Path]) -> ModelFormat:
    """Detect model serialization format via file extension and header inspections.
    
    Does NOT deserialize any objects.
    """
    path = Path(file_path)
    ext = path.suffix.lower()

    if ext == ".safetensors":
        return ModelFormat.SAFETENSORS
    if ext == ".onnx":
        return ModelFormat.ONNX
    if ext in (".gguf", ".bin") and "gguf" in path.name.lower():
        return ModelFormat.GGUF
    if ext in (".pkl", ".pickle"):
        return ModelFormat.PICKLE
    if ext == ".joblib":
        return ModelFormat.JOBLIB
    if ext in (".pt", ".pth", ".bin"):
        # Inspect header bytes to distinguish PyTorch/Pickle
        if path.is_file():
            try:
                with open(path, "rb") as f:
                    header = f.read(16)
                    for magic in PICKLE_MAGIC_PREFIXES:
                        if header.startswith(magic):
                            return ModelFormat.PICKLE
                    if header.startswith(TORCH_MAGIC_ZIP):
                        return ModelFormat.TORCH_CHECKPOINT
            except Exception:
                pass
        return ModelFormat.TORCH_CHECKPOINT

    return ModelFormat.UNKNOWN


def is_unsafe_serialization(format_type: ModelFormat) -> bool:
    """Return True if serialization format permits arbitrary code execution (e.g. pickle)."""
    return format_type in (
        ModelFormat.PICKLE,
        ModelFormat.TORCH_CHECKPOINT,
        ModelFormat.JOBLIB,
    )


class ModelVerifier:
    """Verifies model artifacts against integrity, format, and source policies."""

    def __init__(
        self,
        require_hash: bool = True,
        allow_unknown_source: bool = False,
        allow_unsafe_serialization: bool = False,
        allowed_sources: Optional[List[str]] = None,
        allowed_base_dirs: Optional[List[str]] = None,
    ) -> None:
        self.require_hash = require_hash
        self.allow_unknown_source = allow_unknown_source
        self.allow_unsafe_serialization = allow_unsafe_serialization
        self.allowed_sources = set(allowed_sources) if allowed_sources else set()
        self.allowed_base_dirs = allowed_base_dirs

    def verify_artifact(
        self,
        path: Union[str, Path],
        expected_hash: Optional[str] = None,
        algorithm: str = "sha256",
    ) -> IntegrityResult:
        """Verify the cryptographic integrity of a local model file.
        
        Uses constant-time comparison (hmac.compare_digest) to prevent timing attacks.
        """
        raw_str = str(path)
        path_finding = validate_path_safety(raw_str, allowed_base_dirs=self.allowed_base_dirs)
        if path_finding:
            return IntegrityResult(
                status=IntegrityStatus.ERROR,
                algorithm=algorithm,
                expected_hash=expected_hash,
                details=f"Path validation failed: {path_finding.description}",
            )

        resolved = Path(raw_str).resolve()
        if not resolved.exists() or not resolved.is_file():
            return IntegrityResult(
                status=IntegrityStatus.ERROR,
                algorithm=algorithm,
                expected_hash=expected_hash,
                details=f"File does not exist or is not a regular file: {resolved}",
            )

        if not expected_hash:
            # Hash expected is unavailable
            try:
                actual = compute_streaming_hash(resolved, algorithm=algorithm)
                return IntegrityResult(
                    status=IntegrityStatus.UNAVAILABLE,
                    algorithm=algorithm,
                    expected_hash=None,
                    actual_hash=actual,
                    details="No expected hash was provided for verification.",
                )
            except Exception as exc:
                return IntegrityResult(
                    status=IntegrityStatus.ERROR,
                    algorithm=algorithm,
                    details=f"Failed to compute hash: {str(exc)}",
                )

        try:
            actual = compute_streaming_hash(resolved, algorithm=algorithm)
            # Constant-time comparison
            if hmac.compare_digest(actual.lower().strip(), expected_hash.lower().strip()):
                return IntegrityResult(
                    status=IntegrityStatus.MATCH,
                    algorithm=algorithm,
                    expected_hash=expected_hash,
                    actual_hash=actual,
                    details="Integrity verified successfully.",
                )
            else:
                return IntegrityResult(
                    status=IntegrityStatus.MISMATCH,
                    algorithm=algorithm,
                    expected_hash=expected_hash,
                    actual_hash=actual,
                    details="Cryptographic hash mismatch detected.",
                )
        except Exception as exc:
            return IntegrityResult(
                status=IntegrityStatus.ERROR,
                algorithm=algorithm,
                expected_hash=expected_hash,
                details=f"Error hashing file: {str(exc)}",
            )

    def evaluate_model(
        self,
        artifact: ModelArtifact,
        expected_version: Optional[str] = None,
        expected_hash: Optional[str] = None,
        manifest_pinned: bool = False,
    ) -> ModelSecurityDecision:
        """Evaluate a model artifact against security policies, format rules, and pinning."""
        findings: List[Finding] = []

        # 1. Path Safety & Integrity (if local file)
        integrity_status = IntegrityStatus.UNAVAILABLE
        if artifact.location and os.path.exists(artifact.location):
            exp_hash = expected_hash or artifact.sha256
            int_res = self.verify_artifact(artifact.location, expected_hash=exp_hash)
            integrity_status = int_res.status

            if int_res.status == IntegrityStatus.MISMATCH:
                findings.append(
                    Finding(
                        detector_name="model_integrity",
                        threat_type=ThreatType.POLICY_VIOLATION,
                        description=(
                            f"Model artifact '{artifact.name}' hash mismatch: "
                            f"expected '{int_res.expected_hash}', got '{int_res.actual_hash}'."
                        ),
                        severity=Severity.CRITICAL,
                        confidence=1.0,
                        metadata={
                            "violation": "MODEL_HASH_MISMATCH",
                            "expected": int_res.expected_hash,
                            "actual": int_res.actual_hash,
                        },
                    )
                )
            elif int_res.status == IntegrityStatus.ERROR:
                findings.append(
                    Finding(
                        detector_name="model_integrity",
                        threat_type=ThreatType.POLICY_VIOLATION,
                        description=f"Model artifact verification error: {int_res.details}",
                        severity=Severity.HIGH,
                        confidence=1.0,
                        metadata={"violation": "MODEL_ARTIFACT_MISSING", "error": int_res.details},
                    )
                )
            elif int_res.status == IntegrityStatus.UNAVAILABLE and self.require_hash:
                findings.append(
                    Finding(
                        detector_name="model_integrity",
                        threat_type=ThreatType.POLICY_VIOLATION,
                        description=f"Model artifact '{artifact.name}' is missing required cryptographic hash pinning.",
                        severity=Severity.HIGH,
                        confidence=1.0,
                        metadata={"violation": "MODEL_NOT_PINNED"},
                    )
                )
        elif self.require_hash and not artifact.sha256 and artifact.source_type == ModelSourceType.LOCAL_FILE:
            findings.append(
                Finding(
                    detector_name="model_integrity",
                    threat_type=ThreatType.POLICY_VIOLATION,
                    description=f"Model artifact '{artifact.name}' requires hash pinning under current policy.",
                    severity=Severity.HIGH,
                    confidence=1.0,
                    metadata={"violation": "MODEL_NOT_PINNED"},
                )
            )

        # 2. Version Pinning Check
        if expected_version and artifact.version != "unknown" and artifact.version != expected_version:
            findings.append(
                Finding(
                    detector_name="model_pinning",
                    threat_type=ThreatType.POLICY_VIOLATION,
                    description=(
                        f"Model version mismatch for '{artifact.name}': "
                        f"expected '{expected_version}', got '{artifact.version}'."
                    ),
                    severity=Severity.HIGH,
                    confidence=1.0,
                    metadata={
                        "violation": "MODEL_VERSION_MISMATCH",
                        "expected": expected_version,
                        "actual": artifact.version,
                    },
                )
            )

        # 3. Source Pinning & Trust
        if self.allowed_sources and artifact.source not in self.allowed_sources:
            findings.append(
                Finding(
                    detector_name="model_source",
                    threat_type=ThreatType.POLICY_VIOLATION,
                    description=f"Model source '{artifact.source}' is not in allowed sources list.",
                    severity=Severity.HIGH,
                    confidence=1.0,
                    metadata={"violation": "MODEL_SOURCE_UNTRUSTED", "source": artifact.source},
                )
            )
        elif not self.allow_unknown_source and artifact.source_type == ModelSourceType.UNKNOWN:
            findings.append(
                Finding(
                    detector_name="model_source",
                    threat_type=ThreatType.POLICY_VIOLATION,
                    description=f"Model source for '{artifact.name}' is unknown and rejected by policy.",
                    severity=Severity.HIGH,
                    confidence=1.0,
                    metadata={"violation": "MODEL_SOURCE_UNTRUSTED", "source": artifact.source},
                )
            )

        # 4. Unsafe Serialization Format Detection
        fmt = artifact.format
        if fmt == ModelFormat.UNKNOWN and artifact.location and os.path.exists(artifact.location):
            fmt = detect_model_format(artifact.location)

        if not self.allow_unsafe_serialization and is_unsafe_serialization(fmt):
            findings.append(
                Finding(
                    detector_name="model_serialization",
                    threat_type=ThreatType.POLICY_VIOLATION,
                    description=(
                        f"Model '{artifact.name}' uses unsafe serialization format '{fmt.value}' "
                        f"(vulnerable to arbitrary code execution/pickling)."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    metadata={"violation": "MODEL_FORMAT_UNSAFE", "format": fmt.value},
                )
            )

        # Determine decision action
        has_critical = any(f.severity == Severity.CRITICAL for f in findings)
        has_high = any(f.severity == Severity.HIGH for f in findings)

        if has_critical:
            action = Action.BLOCK
        elif has_high:
            action = Action.BLOCK
        elif findings:
            action = Action.WARN
        else:
            action = Action.ALLOW

        return ModelSecurityDecision(
            action=action,
            model=artifact.name,
            version=artifact.version,
            source=artifact.source,
            hash_status=integrity_status,
            format=fmt,
            findings=findings,
            policy="model_security_policy",
        )
