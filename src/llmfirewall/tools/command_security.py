"""Dangerous command, shell execution, and dangerous SQL inspection utilities."""

import re
from typing import List, Optional, Set

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


def inspect_command_safety(command_str: str) -> Optional[Finding]:
    """Inspect shell or executable command arguments for high-risk destructive commands.
    
    Note: LLMFirewall validates/checks the tool call; this is NOT an OS-level sandbox replacement.
    """
    if not command_str or not isinstance(command_str, str):
        return None

    raw = command_str.strip()

    for pattern in DANGEROUS_SHELL_PATTERNS:
        if pattern.search(raw):
            return Finding(
                detector_name="command_security",
                threat_type=ThreatType.POLICY_VIOLATION,
                description=f"Destructive or high-risk shell command pattern detected: '{pattern.pattern}'.",
                severity=Severity.CRITICAL,
                confidence=1.0,
                metadata={"command": raw[:128], "violation": "destructive_shell_command"},
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
