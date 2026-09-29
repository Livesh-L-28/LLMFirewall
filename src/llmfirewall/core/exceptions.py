"""Custom exceptions for LLMFirewall."""

from typing import Any


class LLMFirewallError(Exception):
    """Base exception for all llmfirewall errors."""
    pass


class ConfigurationError(LLMFirewallError):
    """Raised when firewall configuration or rules are invalid."""
    pass


class BlockedPromptError(LLMFirewallError):
    """Raised when an input prompt is blocked by policy enforcement."""
    def __init__(self, message: str, decision: Any = None):
        super().__init__(message)
        self.decision = decision


class BlockedOutputError(LLMFirewallError):
    """Raised when an LLM output is blocked by policy enforcement."""
    def __init__(self, message: str, decision: Any = None):
        super().__init__(message)
        self.decision = decision
