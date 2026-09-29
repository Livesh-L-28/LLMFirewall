"""Minimal example detector used for framework testing and verification."""

import re
from typing import Any, Dict, List, Optional

from llmfirewall.core.models import Finding, Severity, ThreatType
from llmfirewall.detectors.base import Detector
from llmfirewall.detectors.metadata import DetectorMetadata


class KeywordDetector(Detector):
    """Simple test detector that searches for prohibited keywords."""

    def __init__(
        self,
        keywords: Optional[List[str]] = None,
        severity: Severity = Severity.HIGH,
        threat_type: ThreatType = ThreatType.CUSTOM,
    ) -> None:
        self._keywords = [kw.lower() for kw in (keywords or ["forbidden_test_token"])]
        self._severity = severity
        self._threat_type = threat_type

    @property
    def metadata(self) -> DetectorMetadata:
        return DetectorMetadata(
            name="keyword_test_detector",
            description="Minimal keyword matching detector for testing framework execution.",
            version="0.1.0",
            supported_threats=[self._threat_type],
            supported_directions=["input", "output"],
            is_enabled_by_default=True,
        )

    def detect(self, text: str, context: Optional[Dict[str, Any]] = None) -> List[Finding]:
        findings: List[Finding] = []
        lower_text = text.lower()

        for kw in self._keywords:
            for match in re.finditer(re.escape(kw), lower_text):
                start, end = match.span()
                findings.append(
                    Finding(
                        detector_name=self.name,
                        threat_type=self._threat_type,
                        description=f"Matched prohibited keyword: '{kw}'",
                        severity=self._severity,
                        confidence=1.0,
                        start_pos=start,
                        end_pos=end,
                        matched_text=text[start:end],
                        replacement_text="[REDACTED]",
                    )
                )
        return findings
