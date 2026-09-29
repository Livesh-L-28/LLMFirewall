"""Secret detector implementation."""

from typing import Any, Dict, List, Optional

from llmfirewall.core.models import Finding, ThreatType
from llmfirewall.detectors.base import Detector
from llmfirewall.detectors.metadata import DetectorMetadata
from llmfirewall.detectors.secrets.rules import (
    APIKeyRule,
    CredentialConfigRule,
    PrivateKeyRule,
    SecretMatch,
    SecretRule,
    TokenRule,
)


class SecretDetector(Detector):
    """Local, high-precision detector for credentials, API tokens, and private keys.
    
    Architecture:
      Input Text
          ↓
      Rule Evaluation (Prefix matching + Regex)
          ↓
      Shannon Entropy Gating (Reject low-randomness matches)
          ↓
      Span Deduplication & Sorting
          ↓
      Safe Redaction Preparation (matched_text=None strictly enforced)
      
    Security Invariants:
      1. Zero Credential Exposure: The detected secret value is NEVER stored in
         Finding.matched_text and NEVER logged.
      2. Non-Overlapping Spans: Character offsets (start_pos, end_pos) are sorted
         and deduplicated to allow clean downstream text replacement.
      3. Shannon Entropy Gating: Prevents excessive false positives on generic
         code variables, placeholders, or plain English words.
         
    Limitations:
      - Does not detect custom or non-standard token formats lacking identifiable prefixes
        or structure without generating high false positives.
      - Secrets split across multiple lines or obfuscated with character encodings
        (e.g. base64 fragments) may require specialized pre-decoding pipelines.
    """

    def __init__(self, rules: Optional[List[SecretRule]] = None) -> None:
        self._rules: List[SecretRule] = rules if rules is not None else [
            APIKeyRule(),
            TokenRule(),
            PrivateKeyRule(),
            CredentialConfigRule(),
        ]

    @property
    def metadata(self) -> DetectorMetadata:
        return DetectorMetadata(
            name="secret_detector",
            description=(
                "Detects API keys, tokens, JWTs, private keys, database connection "
                "strings, and password configs using high-entropy signature matching."
            ),
            version="0.1.0",
            supported_threats=[ThreatType.SECRET],
            supported_directions=["input", "output"],
            is_enabled_by_default=True,
            author="LLMFirewall Authors",
        )

    def detect(self, text: str, context: Optional[Dict[str, Any]] = None) -> List[Finding]:
        if not text or not text.strip():
            return []

        all_matches: List[SecretMatch] = []
        for rule in self._rules:
            matches = rule.evaluate(text)
            if matches:
                all_matches.extend(matches)

        if not all_matches:
            return []

        # Sort matches by start_pos ascending, then longest match first
        sorted_matches = sorted(
            all_matches,
            key=lambda m: (m.start_pos, -(m.end_pos - m.start_pos)),
        )

        # Deduplicate overlapping spans
        deduped: List[SecretMatch] = []
        for m in sorted_matches:
            overlaps = False
            for existing in deduped:
                if max(m.start_pos, existing.start_pos) < min(m.end_pos, existing.end_pos):
                    overlaps = True
                    break
            if not overlaps:
                deduped.append(m)

        # SECURITY GUARANTEE: Never populate matched_text with raw secret values!
        findings: List[Finding] = []
        for m in deduped:
            findings.append(
                Finding(
                    detector_name=self.name,
                    threat_type=ThreatType.SECRET,
                    description=m.description,
                    severity=m.severity,
                    confidence=m.confidence,
                    start_pos=m.start_pos,
                    end_pos=m.end_pos,
                    matched_text=None,  # STRICT PRIVACY & SAFETY: Never store detected secret
                    replacement_text=m.replacement_text,
                    metadata={
                        "rule_id": m.rule_id,
                        "entropy": m.entropy,
                    },
                )
            )

        return findings
