"""Dangerous command, shell execution, and dangerous SQL inspection utilities.

Security Invariant & Risk Disclosure:
LLMFirewall performs static, non-executing heuristic checks on tool command strings and argument arrays.
STATIC STRING MATCHING CANNOT GUARANTEE PROTECTION AGAINST ARBITRARY SHELL EXECUTION.
Any tool providing shell or command execution capability MUST be isolated within an OS-level sandbox
(e.g., Linux namespaces, seccomp, gVisor, Firecracker microVMs, or ephemeral Docker containers).
LLMFirewall validates tool intent; it does NOT replace kernel-level execution boundaries.
"""

import re
import shlex
from typing import List, Optional, Set, Union

from llmfirewall.core.models import Finding, Severity, ThreatType

# Destructive / dangerous shell command substrings and patterns
DANGEROUS_SHELL_PATTERNS: List[re.Pattern] = [
    re.compile(r"\brm\s+-[rfR]+\s+[/~]", re.IGNORECASE),
    re.compile(r"\bmkfs\b", re.IGNORECASE),
    re.compile(r"\bdd\s+if=", re.IGNORECASE),
    re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", re.IGNORECASE),  # Fork bomb
    re.compile(r"\bchmod\s+777\b", re.IGNORECASE),
    re.compile(r"\bshutdown\b|\breboot\b|\binit\s+0\b", re.IGNORECASE),
    re.compile(r"\bcurl\b.*\|\s*(?:bash|sh|zsh)\b", re.IGNORECASE),
    re.compile(r"\bwget\b.*\|\s*(?:bash|sh|zsh)\b", re.IGNORECASE),
]

# Privilege escalation binaries and commands
PRIVILEGE_ESCALATION_PATTERNS: List[re.Pattern] = [
    re.compile(r"\b(?:sudo|su|doas|pkexec)\b", re.IGNORECASE),
    re.compile(r"\bchmod\s+[+]?s\b", re.IGNORECASE),
    re.compile(r"\bchown\s+root\b", re.IGNORECASE),
]

# Shell metacharacters indicating command chaining or subshell execution
SHELL_CHAINING_PATTERNS: List[re.Pattern] = [
    re.compile(r"[;&|]{1,2}"),
    re.compile(r"`[^`]+`"),
    re.compile(r"\$\([^)]+\)"),
    re.compile(r"[><]{1,2}"),
]

# Destructive SQL patterns
DESTRUCTIVE_SQL_KEYWORDS: Set[str] = {
    "drop table",
    "drop database",
    "truncate table",
    "alter table",
    "grant all",
    "revoke all",
    "xp_cmdshell",
}


def inspect_command_safety(
    command_str: Union[str, List[str]],
    allow_shell_chaining: bool = False,
    allow_privilege_escalation: bool = False,
) -> Optional[Finding]:
    """Inspect shell or executable command arguments for high-risk destructive commands.

    Args:
        command_str: Raw command string or tokenized list of arguments.
        allow_shell_chaining: If False, disallow pipe, semicolon, and background chaining operators.
        allow_privilege_escalation: If False, disallow sudo/su/doas privilege escalation commands.

    Returns:
        Optional[Finding]: Emitted finding if high-risk command patterns detected.
    """
    if not command_str:
        return None

    if isinstance(command_str, list):
        raw = " ".join(str(a) for a in command_str).strip()
        tokens = [str(a) for a in command_str]
    else:
        raw = str(command_str).strip()
        try:
            tokens = shlex.split(raw)
        except Exception:
            tokens = raw.split()

    # 1. Destructive Shell Command Patterns
    for pattern in DANGEROUS_SHELL_PATTERNS:
        if pattern.search(raw):
            return Finding(
                detector_name="command_security",
                threat_type=ThreatType.POLICY_VIOLATION,
                description=f"Destructive or high-risk shell command pattern detected: '{pattern.pattern}'.",
                severity=Severity.CRITICAL,
                confidence=1.0,
                metadata={
                    "command": raw[:128],
                    "violation": "destructive_shell_command",
                    "sandbox_notice": "OS-level isolation (seccomp/containers) required for command execution tools.",
                },
            )

    # 2. Privilege Escalation Commands
    if not allow_privilege_escalation:
        for pattern in PRIVILEGE_ESCALATION_PATTERNS:
            if pattern.search(raw):
                return Finding(
                    detector_name="command_security",
                    threat_type=ThreatType.POLICY_VIOLATION,
                    description=f"Unauthorized privilege escalation pattern detected in command: '{raw[:64]}'.",
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    metadata={
                        "command": raw[:128],
                        "violation": "privilege_escalation",
                        "sandbox_notice": "Tools must execute with minimum necessary unprivileged credentials.",
                    },
                )

    # 3. Shell Chaining and Subshell Execution (if chaining is not explicitly allowed)
    if not allow_shell_chaining:
        for pattern in SHELL_CHAINING_PATTERNS:
            if pattern.search(raw):
                return Finding(
                    detector_name="command_security",
                    threat_type=ThreatType.POLICY_VIOLATION,
                    description=f"Unauthorized shell chaining or redirection operator detected in command: '{raw[:64]}'.",
                    severity=Severity.HIGH,
                    confidence=0.95,
                    metadata={
                        "command": raw[:128],
                        "violation": "shell_chaining_operator",
                        "sandbox_notice": "Tools expecting structured arguments must disallow raw shell metacharacters.",
                    },
                )

    return None


def inspect_sql_safety(query_str: str) -> Optional[Finding]:
    """Inspect SQL query arguments for destructive DDL/DCL operations.

    Note: Application/database roles and permissions remain the authoritative control.
    """
    if not query_str or not isinstance(query_str, str):
        return None

    lower = query_str.lower()
    for kw in DESTRUCTIVE_SQL_KEYWORDS:
        if kw in lower:
            return Finding(
                detector_name="database_security",
                threat_type=ThreatType.POLICY_VIOLATION,
                description=f"Destructive SQL operation '{kw.upper()}' detected in query argument.",
                severity=Severity.HIGH,
                confidence=0.95,
                metadata={"query": query_str[:128], "keyword": kw, "violation": "destructive_sql"},
            )

    return None
