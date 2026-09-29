"""Execution engine for coordinating detector invocations."""

import logging
from typing import Any, Dict, List, Optional

from llmfirewall.core.exceptions import LLMFirewallError
from llmfirewall.core.models import Finding
from llmfirewall.detectors.base import Detector
from llmfirewall.detectors.collection import FindingCollection

logger = logging.getLogger(__name__)


class DetectorEngine:
    """Orchestrates running detectors across input or output text.
    
    Adheres strictly to 'Detectors detect':
    Executes detectors, collects Findings safely, isolates crashes,
    and returns a FindingCollection without making policy choices.
    """

    def __init__(
        self,
        detectors: Optional[List[Detector]] = None,
        fail_fast: bool = False,
    ) -> None:
        """
        Args:
            detectors: List of Detector instances to execute.
            fail_fast: If True, raise exception on first detector failure.
                       If False (default), capture error and continue other detectors.
        """
        self._detectors: List[Detector] = list(detectors or [])
        self._fail_fast = fail_fast

    @property
    def detectors(self) -> List[Detector]:
        return list(self._detectors)

    def add_detector(self, detector: Detector) -> None:
        """Append a detector to the engine execution list."""
        self._detectors.append(detector)

    def execute(
        self,
        text: str,
        direction: str = "input",
        context: Optional[Dict[str, Any]] = None,
    ) -> FindingCollection:
        """Execute all matching detectors against the provided text.
        
        Args:
            text: Text to scan.
            direction: 'input' or 'output'.
            context: Additional contextual attributes.
            
        Returns:
            FindingCollection: Collection of all detected findings and non-fatal errors.
        """
        collected_findings: List[Finding] = []
        collected_errors: List[Dict[str, str]] = []
        ctx = dict(context or {})
        ctx["direction"] = direction

        for detector in self._detectors:
            # Check if detector supports this direction
            if direction not in detector.metadata.supported_directions:
                continue

            try:
                results = detector.detect(text, context=ctx)
                if results:
                    collected_findings.extend(results)
            except Exception as exc:
                err_msg = f"Detector '{detector.name}' failed with error: {str(exc)}"
                logger.error(err_msg, exc_info=True)
                if self._fail_fast:
                    raise LLMFirewallError(err_msg) from exc
                collected_errors.append(
                    {"detector": detector.name, "error": str(exc)}
                )

        return FindingCollection(
            findings=collected_findings,
            errors=collected_errors,
        )
