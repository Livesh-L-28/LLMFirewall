"""Filesystem path security and path traversal protection utilities."""

import os
from pathlib import Path
from typing import List, Optional, Set
from urllib.parse import unquote

from llmfirewall.core.models import Finding, Severity, ThreatType

SENSITIVE_SYSTEM_PATHS: Set[str] = {
    "/etc",
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/root",
    "/root/.ssh",
    "/proc",
    "/sys",
    "/dev",
    "/var/run",
    "/var/log",
    "/boot",
    "~/.ssh",
    "~/.aws",
    "~/.kube",
    "~/.gnupg",
    "~/.bashrc",
    "~/.zshrc",
    "~/.env",
    "/private/etc",
    "/Library/Preferences/SystemConfiguration",
    "C:\\Windows\\System32",
    "C:\\Windows\\System32\\config",
    "C:\\Windows\\System32\\drivers\\etc",
    "C:\\Windows",
    "C:\\ProgramData",
}


def is_unc_path(path: str) -> bool:
    """Check if a path string is a Windows UNC (Universal Naming Convention) or device network path."""
    if not path or not isinstance(path, str):
        return False
    s = path.strip()
    # Check Win32 device namespace prefixes (case-insensitive)
    lower = s.lower().replace("/", "\\")
    if lower.startswith(("\\\\?\\unc\\", "\\??\\unc\\")):
        return True
    if lower.startswith(("\\\\?\\", "\\??\\", "\\\\.\\")):
        return True
    # Check standard UNC \\host\share or //host/share
    if s.startswith(("\\\\", "//", "\\/", "/\\")):
        remainder = s[2:]
        if remainder and not remainder.startswith(("\\", "/")):
            return True
    return False


def validate_path_safety(
    path_str: str,
    allowed_base_dirs: Optional[List[str]] = None,
    allow_absolute: bool = True,
    allow_unc: bool = False,
) -> Optional[Finding]:
    """Inspect a file path argument for directory traversal, sensitive path access, and sandbox escapes.

    Args:
        path_str: The raw path string from the tool argument.
        allowed_base_dirs: If provided, paths must resolve inside one of these directories.
        allow_absolute: Whether absolute paths are allowed (defaults to True).
        allow_unc: Whether Windows UNC network paths are allowed (defaults to False).

    Returns:
        Optional[Finding]: Emitted finding if traversal or sensitive access detected, else None.
    """
    if not path_str or not isinstance(path_str, str):
        return None

    raw = path_str.strip()

    # 1. Directory Traversal Token Inspection (raw, URL-encoded, overlong UTF-8)
    lower_raw = raw.lower()
    unquoted_raw = unquote(raw).lower()
    traversal_indicators = [
        "..",
        "%2e%2e",
        "..%2f",
        "%2e%2e%2f",
        "..%5c",
        "%2e%2e%5c",
        "%c0%ae%c0%ae",  # Overlong UTF-8 dot
        "%c0%2e%c0%2e",
    ]
    if any(ind in lower_raw or ind in unquoted_raw for ind in traversal_indicators):
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

    # 2. Windows UNC Network Path Inspection
    if not allow_unc and is_unc_path(raw):
        return Finding(
            detector_name="path_security",
            threat_type=ThreatType.POLICY_VIOLATION,
            description=f"Windows UNC network path is forbidden: '{raw[:64]}'.",
            severity=Severity.CRITICAL,
            confidence=1.0,
            metadata={"path": raw[:128], "violation": "unc_path_forbidden"},
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

    # 3. Absolute Path Restriction
    if not allow_absolute and os.path.isabs(norm_path):
        return Finding(
            detector_name="path_security",
            threat_type=ThreatType.POLICY_VIOLATION,
            description=f"Absolute paths are forbidden: '{raw[:64]}'.",
            severity=Severity.HIGH,
            confidence=1.0,
            metadata={"path": raw[:128], "violation": "absolute_path_forbidden"},
        )

    # 4. Sensitive System Directory Matching (case-insensitive)
    # Normalize path and expand user directory
    clean_norm = norm_path.replace("\\", "/")
    clean_lower = clean_norm.casefold()
    expanded_norm = os.path.expanduser(clean_norm)
    expanded_lower = expanded_norm.casefold()

    for sensitive in SENSITIVE_SYSTEM_PATHS:
        sens_norm = sensitive.replace("\\", "/")
        sens_lower = sens_norm.casefold()
        sens_expanded = os.path.expanduser(sens_norm).casefold()

        if (
            clean_lower == sens_lower
            or clean_lower.startswith(sens_lower + "/")
            or expanded_lower == sens_expanded
            or expanded_lower.startswith(sens_expanded + "/")
        ):
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
        try:
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
        except Exception:
            pass

    return None
