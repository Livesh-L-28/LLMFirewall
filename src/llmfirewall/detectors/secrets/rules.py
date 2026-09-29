"""Modular rules for secret and credential pattern detection."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
import re
from typing import List, Optional

from llmfirewall.core.models import Severity
from llmfirewall.detectors.secrets.entropy import calculate_shannon_entropy


@dataclass(frozen=True)
class SecretMatch:
    """Internal match representation for a detected secret.
    
    SECURITY INVARIANT:
    raw_secret is strictly internal and NEVER exposed in Finding objects or logs.
    """
    rule_id: str
    description: str
    severity: Severity
    confidence: float
    start_pos: int
    end_pos: int
    replacement_text: str
    entropy: float


class SecretRule(ABC):
    """Abstract interface for a specific secret detection rule."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique identifier for this secret rule."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this rule detects."""
        pass

    @abstractmethod
    def evaluate(self, text: str) -> List[SecretMatch]:
        """Scan text and emit secret matches."""
        pass


class APIKeyRule(SecretRule):
    """Detects provider-specific API keys with distinctive prefix signatures."""

    def __init__(self) -> None:
        self._patterns = [
            # OpenAI API Key (standard sk-... and project sk-proj-...)
            (
                re.compile(r"\b(sk-[A-Za-z0-9]{32,64}|sk-proj-[A-Za-z0-9_-]{40,120})\b"),
                "OpenAI API Key detected",
                Severity.CRITICAL,
                0.98,
                "[REDACTED_OPENAI_KEY]",
                3.0,
            ),
            # AWS Access Key ID (AKIA...)
            (
                re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
                "AWS Access Key ID detected",
                Severity.HIGH,
                0.95,
                "[REDACTED_AWS_ACCESS_KEY]",
                2.5,
            ),
            # Anthropic API Key (sk-ant-...)
            (
                re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{40,120})\b"),
                "Anthropic API Key detected",
                Severity.CRITICAL,
                0.98,
                "[REDACTED_ANTHROPIC_KEY]",
                3.0,
            ),
            # Stripe API Keys (sk_live_..., rk_live_...)
            (
                re.compile(r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,34})\b"),
                "Stripe Live API Key detected",
                Severity.CRITICAL,
                0.99,
                "[REDACTED_STRIPE_KEY]",
                3.0,
            ),
            # Generic Bearer / API token assignment
            (
                re.compile(r"""(?i)\b(?:api[_-]?key|api[_-]?secret)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,80})['"]?"""),
                "Generic API Key assignment detected",
                Severity.HIGH,
                0.88,
                "[REDACTED_API_KEY]",
                3.2,  # Require minimum entropy to avoid false positives on words
            ),
        ]

    @property
    def rule_id(self) -> str:
        return "api_key_rule"

    @property
    def description(self) -> str:
        return "Detects cloud and AI provider API keys (OpenAI, AWS, Anthropic, Stripe, generic)."

    def evaluate(self, text: str) -> List[SecretMatch]:
        matches: List[SecretMatch] = []
        for pattern, desc, severity, conf, replacement, min_entropy in self._patterns:
            for m in pattern.finditer(text):
                # The secret value is either captured in group 1 or the entire match
                candidate = m.group(1) if m.groups() else m.group(0)
                entropy = calculate_shannon_entropy(candidate)

                if entropy < min_entropy:
                    # Ignore low-entropy strings that lack randomness (e.g. repeated characters or plain words)
                    continue

                start = m.start(1) if m.groups() else m.start(0)
                end = m.end(1) if m.groups() else m.end(0)

                matches.append(
                    SecretMatch(
                        rule_id=self.rule_id,
                        description=desc,
                        severity=severity,
                        confidence=conf,
                        start_pos=start,
                        end_pos=end,
                        replacement_text=replacement,
                        entropy=round(entropy, 2),
                    )
                )
        return matches


class TokenRule(SecretRule):
    """Detects authorization tokens, GitHub tokens, Slack tokens, and JWTs."""

    def __init__(self) -> None:
        self._patterns = [
            # GitHub Personal Access Token (classic ghp_... and fine-grained github_pat_...)
            (
                re.compile(r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,100})\b"),
                "GitHub Personal Access Token detected",
                Severity.CRITICAL,
                0.99,
                "[REDACTED_GITHUB_TOKEN]",
                3.0,
            ),
            # Slack Bot / User Token (xoxb-..., xoxp-...)
            (
                re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})\b"),
                "Slack Token detected",
                Severity.HIGH,
                0.99,
                "[REDACTED_SLACK_TOKEN]",
                3.0,
            ),
            # Slack Webhook URL
            (
                re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
                "Slack Incoming Webhook URL detected",
                Severity.HIGH,
                0.96,
                "[REDACTED_SLACK_WEBHOOK]",
                2.5,
            ),
            # JSON Web Token (JWT) - Header.Payload.Signature
            (
                re.compile(r"\beyJ[A-Za-z0-9-_]{10,}\.eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\b"),
                "JSON Web Token (JWT) detected",
                Severity.HIGH,
                0.95,
                "[REDACTED_JWT_TOKEN]",
                3.2,
            ),
        ]

    @property
    def rule_id(self) -> str:
        return "token_rule"

    @property
    def description(self) -> str:
        return "Detects authorization tokens (GitHub PATs, Slack tokens/webhooks, JWTs)."

    def evaluate(self, text: str) -> List[SecretMatch]:
        matches: List[SecretMatch] = []
        for pattern, desc, severity, conf, replacement, min_entropy in self._patterns:
            for m in pattern.finditer(text):
                candidate = m.group(1) if m.groups() else m.group(0)
                entropy = calculate_shannon_entropy(candidate)

                if entropy < min_entropy:
                    continue

                start = m.start(1) if m.groups() else m.start(0)
                end = m.end(1) if m.groups() else m.end(0)

                matches.append(
                    SecretMatch(
                        rule_id=self.rule_id,
                        description=desc,
                        severity=severity,
                        confidence=conf,
                        start_pos=start,
                        end_pos=end,
                        replacement_text=replacement,
                        entropy=round(entropy, 2),
                    )
                )
        return matches


class PrivateKeyRule(SecretRule):
    """Detects cryptographic private key headers and blocks (RSA, EC, OPENSSH, PGP)."""

    def __init__(self) -> None:
        self._pattern = re.compile(
            r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|PGP\s+)?PRIVATE\s+KEY-----"
            r"[\s\S]+?"
            r"-----END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|PGP\s+)?PRIVATE\s+KEY-----",
            re.MULTILINE,
        )

    @property
    def rule_id(self) -> str:
        return "private_key_rule"

    @property
    def description(self) -> str:
        return "Detects asymmetric private key blocks (RSA, EC, OpenSSH, PGP)."

    def evaluate(self, text: str) -> List[SecretMatch]:
        matches: List[SecretMatch] = []
        for m in self._pattern.finditer(text):
            candidate = m.group(0)
            entropy = calculate_shannon_entropy(candidate)
            matches.append(
                SecretMatch(
                    rule_id=self.rule_id,
                    description="Cryptographic Private Key block detected",
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    start_pos=m.start(0),
                    end_pos=m.end(0),
                    replacement_text="[REDACTED_PRIVATE_KEY]",
                    entropy=round(entropy, 2),
                )
            )
        return matches


class CredentialConfigRule(SecretRule):
    """Detects database connection strings and password configurations."""

    def __init__(self) -> None:
        self._patterns = [
            # URI Connection Strings: postgresql://user:password@host:port/db
            (
                re.compile(
                    r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://"
                    r"[^:\s/]+:([^@\s/]+)@[^:\s/]+(?::\d+)?(?:/[^\s]*)?",
                    re.IGNORECASE,
                ),
                "Database connection string with plaintext password detected",
                Severity.CRITICAL,
                0.97,
                "[REDACTED_DB_CREDENTIALS]",
                2.0,
            ),
            # Password assignments in configuration or code: password = "..."
            (
                re.compile(
                    r"""(?i)\b(?:db_password|password|passwd|pwd|secret_key)\s*[:=]\s*['"]([^'"\s]{8,64})['"]"""
                ),
                "Plaintext password configuration detected",
                Severity.HIGH,
                0.90,
                "[REDACTED_PASSWORD]",
                2.8,  # Entropy check prevents flagging password = "password" or password = "TODO"
            ),
        ]

    @property
    def rule_id(self) -> str:
        return "credential_config_rule"

    @property
    def description(self) -> str:
        return "Detects database connection strings and plaintext password configuration values."

    def evaluate(self, text: str) -> List[SecretMatch]:
        matches: List[SecretMatch] = []
        for pattern, desc, severity, conf, replacement, min_entropy in self._patterns:
            for m in pattern.finditer(text):
                # The full match is the span to redact; password is group 1
                password_str = m.group(1) if m.groups() else m.group(0)
                entropy = calculate_shannon_entropy(password_str)

                if entropy < min_entropy:
                    continue

                matches.append(
                    SecretMatch(
                        rule_id=self.rule_id,
                        description=desc,
                        severity=severity,
                        confidence=conf,
                        start_pos=m.start(0),
                        end_pos=m.end(0),
                        replacement_text=replacement,
                        entropy=round(entropy, 2),
                    )
                )
        return matches
