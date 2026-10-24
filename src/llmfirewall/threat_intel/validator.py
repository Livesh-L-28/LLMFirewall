"""Phase 60 — Threat Feed Validation, ReDoS Prevention, and Sanitization."""

import re
from typing import List, Optional, Tuple

from llmfirewall.threat_intel.models import (
    AIThreatIndicator,
    ThreatIntelFeed,
    ThreatPatternType,
)

# Common catastrophic backtracking / ReDoS patterns
_DANGEROUS_REGEX_PATTERNS = [
    re.compile(r"(\[[^\]]*[\+\*]\]|\([^)]*[\+\*]\))[\+\*]"),   # Nested quantifiers (a+)+, (a*)*
    re.compile(r"(\[[^\]]*[\+\*]\]|\([^)]*[\+\*]\))\{"),      # Quantifier followed by range
    re.compile(r"(\.\*){2,}"),                                 # Repeated greedy wildcard .*.*
    re.compile(r"(\.\+){2,}"),                                 # Repeated greedy wildcard .+.+
]

MAX_PATTERN_LENGTH = 1000


class ThreatFeedValidator:
    """Validates threat feeds and indicators for cryptographic integrity and execution safety."""

    @staticmethod
    def validate_feed_integrity(
        feed: ThreatIntelFeed,
        expected_checksum: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Verify feed hash against expected checksum or embedded feed checksum."""
        actual_hash = feed.compute_indicators_hash()
        target = expected_checksum or feed.checksum

        if target is None:
            return True, "No checksum supplied; hash calculated successfully."

        if actual_hash.lower() != target.strip().lower():
            return False, f"Checksum mismatch: expected '{target}', computed '{actual_hash}'"

        return True, "Integrity verified successfully."

    @staticmethod
    def validate_indicator_safety(indicator: AIThreatIndicator) -> List[str]:
        """Inspect indicator pattern for ReDoS vulnerabilities, length violations, and invalid syntax."""
        errors: List[str] = []

        if len(indicator.pattern) > MAX_PATTERN_LENGTH:
            errors.append(f"Pattern length ({len(indicator.pattern)}) exceeds max allowed {MAX_PATTERN_LENGTH}.")

        if indicator.pattern_type == ThreatPatternType.REGEX:
            # Check for known ReDoS patterns
            for dangerous in _DANGEROUS_REGEX_PATTERNS:
                if dangerous.search(indicator.pattern):
                    errors.append(
                        f"Pattern '{indicator.pattern}' contains catastrophic backtracking (ReDoS) vulnerability."
                    )
                    break

            # Check if regex compiles
            try:
                re.compile(indicator.pattern)
            except re.error as err:
                errors.append(f"Invalid regular expression syntax: {err}")

        return errors
