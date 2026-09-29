"""Modular sub-detectors for specific PII categories."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
import re
from typing import List, Optional

from llmfirewall.core.models import Finding, Severity, ThreatType
from llmfirewall.detectors.pii.validators import is_valid_ip_address, luhn_checksum_is_valid


@dataclass(frozen=True)
class PIIMatch:
    """Internal representation of a matched PII span."""
    category: str
    description: str
    severity: Severity
    confidence: float
    start_pos: int
    end_pos: int
    replacement_text: str
    raw_match: str  # Kept internal for span verification; NOT exported to finding unless requested


class PIISubDetector(ABC):
    """Abstract interface for a specific PII category detector."""

    @property
    @abstractmethod
    def category_name(self) -> str:
        """Name of the PII category (e.g. 'email', 'phone', 'ip', 'payment')."""
        pass

    @abstractmethod
    def find_matches(self, text: str) -> List[PIIMatch]:
        """Scan text and return detected matches."""
        pass


class EmailSubDetector(PIISubDetector):
    """Detects RFC-compliant email addresses while avoiding false positives."""

    def __init__(self) -> None:
        # Standard email pattern requiring valid domain and TLD (min 2 chars)
        self._pattern = re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        )

    @property
    def category_name(self) -> str:
        return "email"

    def find_matches(self, text: str) -> List[PIIMatch]:
        matches: List[PIIMatch] = []
        for m in self._pattern.finditer(text):
            matched = m.group(0)
            start, end = m.span()
            matches.append(
                PIIMatch(
                    category=self.category_name,
                    description="Email address detected",
                    severity=Severity.MEDIUM,
                    confidence=0.98,
                    start_pos=start,
                    end_pos=end,
                    replacement_text="[REDACTED_EMAIL]",
                    raw_match=matched,
                )
            )
        return matches


class PhoneSubDetector(PIISubDetector):
    """Detects international and North American telephone numbers with context boundaries.
    
    Avoids false positives on simple dates (YYYY-MM-DD), timestamps, or version strings.
    """

    def __init__(self) -> None:
        # Matches:
        # +1-800-555-0199, (555) 234-5678, +44 20 7946 0958, 555-678-1234
        self._pattern = re.compile(
            r"(?:(?:\+|00)\d{1,3}[\s.-]*)?"
            r"(?:\(\d{2,4}\)|\b\d{2,4})[\s.-]*"
            r"\d{3,4}[\s.-]*\d{3,4}\b"
        )

    @property
    def category_name(self) -> str:
        return "phone"

    def find_matches(self, text: str) -> List[PIIMatch]:
        matches: List[PIIMatch] = []
        for m in self._pattern.finditer(text):
            matched = m.group(0).strip()
            digits_count = sum(c.isdigit() for c in matched)
            if digits_count < 10 or digits_count > 15:
                continue

            matches.append(
                PIIMatch(
                    category=self.category_name,
                    description="Phone number detected",
                    severity=Severity.MEDIUM,
                    confidence=0.92,
                    start_pos=m.start(0),
                    end_pos=m.end(0),
                    replacement_text="[REDACTED_PHONE]",
                    raw_match=matched,
                )
            )
        return matches


class IPSubDetector(PIISubDetector):
    """Detects valid IPv4 and IPv6 addresses.
    
    Validates octets numerically to avoid false positives on software versions like '1.2.3.4'
    where numbers exceed 255.
    """

    def __init__(self) -> None:
        self._ipv4_pattern = re.compile(
            r"(?<![\w\.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\w\.])"
        )
        # Matches potential IPv6 tokens containing hex characters and colons
        self._ipv6_token_pattern = re.compile(
            r"(?<![\w:])([0-9a-fA-F:]{3,39})(?![\w:])"
        )

    @property
    def category_name(self) -> str:
        return "ip"

    def find_matches(self, text: str) -> List[PIIMatch]:
        matches: List[PIIMatch] = []

        # Check IPv4
        for m in self._ipv4_pattern.finditer(text):
            candidate = m.group(1)
            if is_valid_ip_address(candidate):
                matches.append(
                    PIIMatch(
                        category=self.category_name,
                        description="IPv4 address detected",
                        severity=Severity.LOW,
                        confidence=0.95,
                        start_pos=m.start(1),
                        end_pos=m.end(1),
                        replacement_text="[REDACTED_IP]",
                        raw_match=candidate,
                    )
                )

        # Check IPv6
        for m in self._ipv6_token_pattern.finditer(text):
            candidate = m.group(1)
            if ":" in candidate and is_valid_ip_address(candidate):
                matches.append(
                    PIIMatch(
                        category=self.category_name,
                        description="IPv6 address detected",
                        severity=Severity.LOW,
                        confidence=0.95,
                        start_pos=m.start(1),
                        end_pos=m.end(1),
                        replacement_text="[REDACTED_IP]",
                        raw_match=candidate,
                    )
                )

        return matches

    @property
    def category_name(self) -> str:
        return "ip"


class PaymentSubDetector(PIISubDetector):
    """Detects credit/debit card numbers with Luhn checksum validation.
    
    Checks Visa, MasterCard, Amex, Discover, Diners Club, JCB format,
    and runs the Luhn algorithm to reject invalid random numbers.
    """

    def __init__(self) -> None:
        # Matches numbers formatted with spaces, dashes, or contiguous digits
        self._pattern = re.compile(
            r"(?<!\d)(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2}|3(?:0[0-5]|[68]\d)\d)"
            r"[- ]?\d{4}[- ]?\d{4}[- ]?\d{1,4}(?!\d)"
        )

    @property
    def category_name(self) -> str:
        return "payment"

    def find_matches(self, text: str) -> List[PIIMatch]:
        matches: List[PIIMatch] = []
        for m in self._pattern.finditer(text):
            matched = m.group(0)
            # Perform Luhn checksum verification
            if luhn_checksum_is_valid(matched):
                matches.append(
                    PIIMatch(
                        category=self.category_name,
                        description="Credit/Debit card number detected (Luhn-verified)",
                        severity=Severity.HIGH,
                        confidence=0.99,
                        start_pos=m.start(0),
                        end_pos=m.end(0),
                        replacement_text="[REDACTED_PAYMENT_CARD]",
                        raw_match=matched,
                    )
                )
        return matches


class CustomPatternSubDetector(PIISubDetector):
    """Allows user-configured custom regex patterns for tenant-specific PII (e.g. employee IDs)."""

    def __init__(
        self,
        name: str,
        pattern: str,
        description: str = "Custom PII pattern matched",
        severity: Severity = Severity.MEDIUM,
        confidence: float = 0.90,
        replacement_text: Optional[str] = None,
    ) -> None:
        self._name = name
        self._regex = re.compile(pattern)
        self._description = description
        self._severity = severity
        self._confidence = confidence
        self._replacement_text = replacement_text or f"[REDACTED_{name.upper()}]"

    @property
    def category_name(self) -> str:
        return self._name

    def find_matches(self, text: str) -> List[PIIMatch]:
        matches: List[PIIMatch] = []
        for m in self._regex.finditer(text):
            matches.append(
                PIIMatch(
                    category=self.category_name,
                    description=self._description,
                    severity=self._severity,
                    confidence=self._confidence,
                    start_pos=m.start(0),
                    end_pos=m.end(0),
                    replacement_text=self._replacement_text,
                    raw_match=m.group(0),
                )
            )
        return matches


class SSNSubDetector(PIISubDetector):
    """Detects standard US Social Security Numbers (SSN)."""

    def __init__(self) -> None:
        self._pattern = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

    @property
    def category_name(self) -> str:
        return "ssn"

    def find_matches(self, text: str) -> List[PIIMatch]:
        matches: List[PIIMatch] = []
        for m in self._pattern.finditer(text):
            matched = m.group(0)
            matches.append(
                PIIMatch(
                    category=self.category_name,
                    description="Social Security Number (SSN) detected",
                    severity=Severity.HIGH,
                    confidence=0.95,
                    start_pos=m.start(0),
                    end_pos=m.end(0),
                    replacement_text="[REDACTED_SSN]",
                    raw_match=matched,
                )
            )
        return matches
