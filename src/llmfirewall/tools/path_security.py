"""Filesystem path security and path traversal protection utilities."""

import os
from pathlib import Path
from typing import List, Optional, Set

from llmfirewall.core.models import Finding, Severity, ThreatType

SENSITIVE_SYSTEM_PATHS: Set[str] = {
    "/etc",
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/root",
    "/proc",
    "/sys",
    "/dev",
    "/var/run",
    "C:\\Windows\\System32",
    "C:\\Windows\\System32\\config",
}


def validate_path_safety(
    path_str: str,
    allowed_base_dirs: Optional[List[str]] = None,
    allow_absolute: bool = True,
) -> Optional[Finding]:
    """Inspect a file path argument for directory traversal and sensitive path access.
    
    Args:
        path_str: The raw path string from the tool argument.
        allowed_base_dirs: If provided, paths must resolve inside one of these directories.
        allow_absolute: Whether absolute paths are allowed (defaults to True).
        
    Returns:
        Optional[Finding]: Emitted finding if traversal or sensitive access detected, else None.
    """
    if not path_str or not isinstance(path_str, str):
        return None

    raw = path_str.strip()

    # 1. Obvious Directory Traversal Tokens
    # Check for raw or encoded ../ or ..\
    if ".." in raw or "%2e%2e" in raw.lower() or "..%2f" in raw.lower() or "%2e%2e%2f" in raw.lower():
        return Finding(
            detector_name="path_security",
            threat_type=ThreatType.POLICY_VIOLATION,
            description=f"Directory traversal pattern detected in path: '{raw[:64]}'.",
            severity=Severity.HIGH,
            confidence=1.0,
            metadata={"path": raw[:128], "violation": "directory_traversal"},
        )

    # Check for null byte injection
    if "\x00" in raw or "%00" in raw:
        return Finding(
            detector_name="path_security",
            threat_type=ThreatType.POLICY_VIOLATION,
            description="Null byte injection detected in path.",
            severity=Severity.CRITICAL,
            confidence=1.0,
            metadata={"path": raw[:128], "violation": "null_byte"},
        )

    try:
        norm_path = os.path.normpath(raw)
    except Exception as exc:
        return Finding(
            detector_name="path_security",
            threat_type=ThreatType.POLICY_VIOLATION,
            description=f"Malformed path format: {exc}",
            severity=Severity.MEDIUM,
            confidence=0.9,
            metadata={"path": raw[:128], "error": "malformed_path"},
        )

    # 2. Absolute Path Restriction
    if not allow_absolute and os.path.isabs(norm_path):
        return Finding(
            detector_name="path_security",
            threat_type=ThreatType.POLICY_VIOLATION,
            description=f"Absolute paths are forbidden: '{raw[:64]}'.",
            severity=Severity.HIGH,
            confidence=1.0,
            metadata={"path": raw[:128], "violation": "absolute_path_forbidden"},
        )

    # 3. Sensitive System Directory Matching
    # Normalize for comparison
    clean_norm = norm_path.replace("\\", "/")
    for sensitive in SENSITIVE_SYSTEM_PATHS:
        sens_norm = sensitive.replace("\\", "/")
        if clean_norm == sens_norm or clean_norm.startswith(sens_norm + "/"):
            return Finding(
                detector_name="path_security",
                threat_type=ThreatType.POLICY_VIOLATION,
                description=f"Access to sensitive system path '{sens_norm}' is forbidden.",
                severity=Severity.CRITICAL,
                confidence=1.0,
                metadata={"path": raw[:128], "sensitive_target": sensitive, "violation": "sensitive_system_path"},
            )

    # 4. Base Directory Sandboxing
    if allowed_base_dirs:
        resolved = Path(norm_path).resolve()
        in_sandbox = False
        for base in allowed_base_dirs:
            base_resolved = Path(base).resolve()
            try:
                resolved.relative_to(base_resolved)
                in_sandbox = True
                break
            except ValueError:
                continue

        if not in_sandbox:
            return Finding(
                detector_name="path_security",
                threat_type=ThreatType.POLICY_VIOLATION,
                description=f"Path '{raw[:64]}' escapes configured base directory sandbox.",
                severity=Severity.CRITICAL,
                confidence=1.0,
                metadata={"path": raw[:128], "violation": "path_sandbox_escape"},
            )

    return None
