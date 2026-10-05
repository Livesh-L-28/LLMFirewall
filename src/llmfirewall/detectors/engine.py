"""Execution engine for coordinating detector invocations in LLMFirewall."""

import logging
from typing import Any, Dict, List, Optional, Sequence, Union

from llmfirewall.core.exceptions import LLMFirewallError
from llmfirewall.core.models import Finding
from llmfirewall.detectors.aggregator import (
    FindingAggregator,
    calibrate_finding_confidence,
    compute_finding_fingerprint,
)
from llmfirewall.detectors.base import Detector
from llmfirewall.detectors.collection import FindingCollection
from llmfirewall.detectors.heuristics import (
    TokenHeuristics,
    compute_token_heuristics,
    normalize_detection_input,
)
from llmfirewall.detectors.planner import ExecutionPlanner
from llmfirewall.detectors.protocols import DetectorProtocol

logger = logging.getLogger(__name__)


class DetectorEngine:
    """Orchestrates running detectors across input or output text.
    
    Adheres strictly to 'Detectors detect':
    Executes detectors, collects Findings safely, isolates crashes,
    calibrates confidence, normalizes findings, and returns a FindingCollection
    without making policy choices.
    
    Pipeline Stages:
      1. Normalization & Token Heuristics
      2. Execution Planning & Candidate Pre-Filtering
      3. Staged Detector Execution & Failure Isolation
      4. Confidence Calibration
      5. Finding Aggregation & Deduplication
    """

    def __init__(
        self,
        detectors: Optional[Sequence[Union[Detector, DetectorProtocol]]] = None,
        fail_fast: bool = False,
        enable_prefilter: bool = True,
        enable_heuristics: bool = True,
    ) -> None:
        """
        Args:
            detectors: Sequence of Detector or DetectorProtocol instances to execute.
            fail_fast: If True, raise exception on first detector failure.
                       If False (default), capture error and continue other detectors.
            enable_prefilter: If True, use trigger hints and direction pre-filters.
            enable_heuristics: If True, extract token heuristics for contextual enrichment.
        """
        self._detectors: List[Union[Detector, DetectorProtocol]] = list(detectors or [])
        self._fail_fast = fail_fast
        self._enable_prefilter = enable_prefilter
        self._enable_heuristics = enable_heuristics

    @property
    def detectors(self) -> List[Union[Detector, DetectorProtocol]]:
        return list(self._detectors)

    def add_detector(self, detector: Union[Detector, DetectorProtocol]) -> None:
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

        # Stage 1: Normalization & Token Heuristics
        canonical_text, lower_text = normalize_detection_input(text)
        if self._enable_heuristics:
            heuristics = compute_token_heuristics(canonical_text)
            ctx["heuristics"] = heuristics.model_dump()

        # Stage 2: Execution Planning & Candidate Pre-filtering
        candidates = ExecutionPlanner.plan(
            detectors=self._detectors,
            text=text,
            lower_text=lower_text,
            direction=direction,
            enable_prefilter=self._enable_prefilter,
            context=ctx,
        )

        # Stage 3: Staged Detector Execution & Failure Isolation
        for detector in candidates:
            try:
                results = detector.detect(text, context=ctx)
                if results:
                    for f in results:
                        # Stage 4: Confidence Calibration
                        calibrated = calibrate_finding_confidence(f, context=ctx)
                        collected_findings.append(calibrated)
            except Exception as exc:
                err_msg = f"Detector '{detector.name}' failed with error: {str(exc)}"
                logger.error(err_msg, exc_info=True)
                if self._fail_fast:
                    raise LLMFirewallError(err_msg) from exc
                collected_errors.append(
                    {"detector": detector.name, "error": str(exc)}
                )

        # Stage 5: Finding Aggregation & Deduplication
        aggregated_findings = FindingAggregator.aggregate(collected_findings)

        return FindingCollection(
            findings=aggregated_findings,
            errors=collected_errors,
        )
