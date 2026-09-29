"""PII Detector orchestrator."""

from typing import Any, Dict, List, Optional, Set

from llmfirewall.core.models import Finding, Severity, ThreatType
from llmfirewall.detectors.base import Detector
from llmfirewall.detectors.metadata import DetectorMetadata
from llmfirewall.detectors.pii.sub_detectors import (
    CustomPatternSubDetector,
    EmailSubDetector,
    IPSubDetector,
    PIIMatch,
    PIISubDetector,
    PaymentSubDetector,
    PhoneSubDetector,
    SSNSubDetector,
)


class PIIDetector(Detector):
    """Modular, local detector for Personally Identifiable Information (PII).
    
    Sub-detectors:
      - EmailSubDetector: RFC-compliant email detection.
      - PhoneSubDetector: International / North American phone numbers.
      - IPSubDetector: IPv4 and IPv6 addresses with octet bounds validation.
      - PaymentSubDetector: Credit/debit cards with Luhn checksum validation.
      - CustomPatternSubDetector: User-defined organizational regex patterns.
      
    Privacy by Default:
      - Does NOT include raw sensitive text in Finding.matched_text by default (avoids
        leaking raw credit cards/PII into downstream audit logs).
      - Records character span offsets (start_pos, end_pos) and replacement_text
        so redactors can sanitize text without re-scanning.
        
    Limitations:
      - Pattern-based PII detection cannot guarantee complete identification of all PII.
      - It cannot detect arbitrary unstructured names or addresses without full NER models.
      - Obfuscated PII (e.g. 'john dot doe at gmail dot com') may not be caught.
    """

    def __init__(
        self,
        enabled_categories: Optional[Set[str]] = None,
        custom_sub_detectors: Optional[List[PIISubDetector]] = None,
        store_matched_text: bool = False,
    ) -> None:
        """
        Args:
            enabled_categories: Set of category names to run ('email', 'phone', 'ip', 'payment').
                                Defaults to all categories.
            custom_sub_detectors: Optional list of additional custom PIISubDetectors.
            store_matched_text: If True, include raw matched string in Finding.matched_text.
                                Defaults to False for privacy and compliance (GDPR/HIPAA/PCI-DSS).
        """
        self._store_matched_text = store_matched_text
        self._sub_detectors: List[PIISubDetector] = []

        # Default sub-detectors
        defaults: List[PIISubDetector] = [
            EmailSubDetector(),
            PhoneSubDetector(),
            IPSubDetector(),
            PaymentSubDetector(),
        ]

        if custom_sub_detectors:
            defaults.extend(custom_sub_detectors)

        if enabled_categories is None:
            self._sub_detectors = defaults
        else:
            self._sub_detectors = [
                sd for sd in defaults if sd.category_name in enabled_categories
            ]

    @property
    def metadata(self) -> DetectorMetadata:
        return DetectorMetadata(
            name="pii_detector",
            description=(
                "Detects PII including email addresses, phone numbers, IP addresses, "
                "and Luhn-validated credit card numbers with zero third-party calls."
            ),
            version="0.1.0",
            supported_threats=[ThreatType.PII],
            supported_directions=["input", "output"],
            is_enabled_by_default=True,
            author="LLMFirewall Authors",
        )

    def detect(self, text: str, context: Optional[Dict[str, Any]] = None) -> List[Finding]:
        if not text or not text.strip():
            return []

        all_matches: List[PIIMatch] = []
        for sub in self._sub_detectors:
            matches = sub.find_matches(text)
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
        deduped: List[PIIMatch] = []
        for m in sorted_matches:
            overlaps = False
            for existing in deduped:
                if max(m.start_pos, existing.start_pos) < min(m.end_pos, existing.end_pos):
                    overlaps = True
                    break
            if not overlaps:
                deduped.append(m)

        # Build Finding objects
        findings: List[Finding] = []
        for match in deduped:
            matched_content = match.raw_match if self._store_matched_text else None
            findings.append(
                Finding(
                    detector_name=self.name,
                    threat_type=ThreatType.PII,
                    description=match.description,
                    severity=match.severity,
                    confidence=match.confidence,
                    start_pos=match.start_pos,
                    end_pos=match.end_pos,
                    matched_text=matched_content,
                    replacement_text=match.replacement_text,
                    metadata={
                        "pii_category": match.category,
                        "stored_raw": self._store_matched_text,
                    },
                )
            )

        return findings
