"""Lightweight pre-filter index and execution planner for detectors."""

from typing import Any, Dict, List, Optional, Sequence, Union
from llmfirewall.detectors.base import Detector
from llmfirewall.detectors.protocols import DetectorCost, DetectorProtocol


class DetectorPreFilter:
    """Evaluates whether specific detectors should be scheduled or skipped.
    
    CRITICAL RULE:
    The pre-filter NEVER produces security decisions or blocks requests.
    It only evaluates whether a detector with explicit trigger hints
    can be safely deferred when none of its prerequisites match.
    Detectors without trigger hints are ALWAYS executed.
    """

    @classmethod
    def should_execute(
        cls,
        detector: Union[Detector, DetectorProtocol],
        text: str,
        lower_text: str,
        direction: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Determine if detector should run for this input."""
        metadata = detector.metadata

        # 1. Direction filtering
        if direction not in metadata.supported_directions:
            return False

        # 2. If trigger_hints are explicitly specified, check if any hint exists in text
        hints = getattr(metadata, "trigger_hints", None)
        if hints and len(hints) > 0:
            # If hints are defined, at least one must be present in lowercase text
            if not any(h.lower() in lower_text for h in hints):
                return False

        return True


class ExecutionPlanner:
    """Plans and orders detector execution based on cost classes and pre-filtering."""

    @classmethod
    def plan(
        cls,
        detectors: Sequence[Union[Detector, DetectorProtocol]],
        text: str,
        lower_text: str,
        direction: str,
        enable_prefilter: bool = True,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[Union[Detector, DetectorProtocol]]:
        """Return an ordered candidate list of detectors to execute.
        
        Ordering:
          1. CHEAP detectors first (fast early findings)
          2. NORMAL detectors second
          3. EXPENSIVE detectors last
        Preserves deterministic relative ordering within same cost class.
        """
        candidates: List[Union[Detector, DetectorProtocol]] = []

        for detector in detectors:
            if enable_prefilter:
                if not DetectorPreFilter.should_execute(
                    detector=detector,
                    text=text,
                    lower_text=lower_text,
                    direction=direction,
                    context=context,
                ):
                    continue
            else:
                # Basic direction check only
                if direction not in detector.metadata.supported_directions:
                    continue

            candidates.append(detector)

        # Stable sort by cost priority: cheap (0) -> normal (1) -> expensive (2)
        cost_ranks = {
            DetectorCost.CHEAP.value: 0,
            "cheap": 0,
            DetectorCost.NORMAL.value: 1,
            "normal": 1,
            DetectorCost.EXPENSIVE.value: 2,
            "expensive": 2,
        }

        def get_rank(d: Union[Detector, DetectorProtocol]) -> int:
            cost = getattr(d.metadata, "cost", "normal")
            return cost_ranks.get(str(cost).lower(), 1)

        return sorted(candidates, key=get_rank)
