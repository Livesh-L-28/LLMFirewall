"""Dedicated Safe Redactor service adhering to strict separation of concerns.

SEPARATION OF CONCERNS:
- Detectors detect: Find offsets and emit structured Finding objects.
- Policy engine decides: Determines WHEN to redact (Action.REDACT).
- Redactor executes: Pure functional string transformation without evaluating policy rules.
- Security Invariant: Original sensitive text values are NEVER leaked in logs, exceptions, or error messages.
"""

from typing import List, Optional

from llmfirewall.core.models import Finding
from llmfirewall.policy.redaction_config import RedactionConfig


class SafeRedactor:
    """Production-grade string sanitization engine for sensitive spans."""

    def __init__(self, config: Optional[RedactionConfig] = None) -> None:
        self._config = config or RedactionConfig()

    @property
    def config(self) -> RedactionConfig:
        return self._config

    def redact(self, text: str, findings: List[Finding]) -> str:
        """Sanitize text by replacing sensitive character spans with configured placeholder tokens.
        
        Guarantees:
        1. Context Preservation: Only the exact sensitive character offsets [start_pos, end_pos]
           are replaced. All surrounding punctuation, formatting, and text are strictly preserved.
        2. Non-Overlapping Spans: Overlapping spans are resolved by prioritizing the broadest
           outer span to prevent partial token artifacts.
        3. Index Safety: Replacements are applied in reverse order (right-to-left) so that
           earlier character offsets are not invalidated by varying replacement token lengths.
        4. Information Privacy: Never prints or embeds the sensitive string value into error traces.
        """
        if not text or not findings:
            return text

        # 1. Filter out findings without valid span information and clamp bounds
        valid_findings = []
        text_len = len(text)
        for f in findings:
            if f.start_pos is not None and f.end_pos is not None:
                start = max(0, f.start_pos)
                end = min(text_len, f.end_pos)
                if start < end:
                    valid_findings.append((start, end, f))
        if not valid_findings:
            return text

        # 2. Sort spans ascending by start_pos, then descending by length (broadest first)
        sorted_spans = sorted(
            valid_findings,
            key=lambda item: (item[0], -(item[1] - item[0])),
        )

        # 3. Deduplicate / resolve overlapping spans
        non_overlapping: List[tuple[int, int, Finding]] = []
        for item in sorted_spans:
            if not non_overlapping:
                non_overlapping.append(item)
                continue
            last = non_overlapping[-1]
            # If current start_pos is less than previous end_pos, they overlap
            if item[0] < last[1]:
                continue
            non_overlapping.append(item)

        # 4. Sort descending by start_pos for safe right-to-left replacement
        non_overlapping.sort(key=lambda item: item[0], reverse=True)

        # 5. Execute character replacement
        chars = list(text)
        for start, end, f in non_overlapping:
            category = f.metadata.get("pii_category") or f.metadata.get("rule_id") or f.category
            replacement_token = self._config.get_token_for(
                category=category,
                threat_type=f.threat_type,
                default_suggestion=f.replacement_text,
            )

            chars[start:end] = list(replacement_token)

        return "".join(chars)


# Convenience module-level redactor instance
default_redactor = SafeRedactor()


def redact_text_spans(
    text: str,
    findings: List[Finding],
    config: Optional[RedactionConfig] = None,
) -> str:
    """Functional helper for redacting sensitive character spans in text."""
    redactor = SafeRedactor(config=config) if config else default_redactor
    return redactor.redact(text, findings)
