"""Detectors module exports."""

from llmfirewall.detectors.base import Detector
from llmfirewall.detectors.collection import FindingCollection
from llmfirewall.detectors.engine import DetectorEngine
from llmfirewall.detectors.examples import KeywordDetector
from llmfirewall.detectors.metadata import DetectorMetadata
from llmfirewall.detectors.pii import PIIDetector
from llmfirewall.detectors.prompt_injection import PromptInjectionDetector
from llmfirewall.detectors.protocols import DetectorCost, DetectorProtocol
from llmfirewall.detectors.registry import DetectorRegistry, default_detector_registry
from llmfirewall.detectors.secrets import SecretDetector
from llmfirewall.detectors.heuristics import TokenHeuristics, compute_token_heuristics
from llmfirewall.detectors.aggregator import FindingAggregator
from llmfirewall.detectors.adaptive import (
    AdaptiveThreatConfig,
    AdaptiveThreatEngine,
    ContextualSignal,
    HistoricalSignalTracker,
    compute_shannon_entropy,
    compute_token_repetition_ratio,
)

__all__ = [
    "Detector",
    "DetectorProtocol",
    "DetectorCost",
    "DetectorMetadata",
    "DetectorEngine",
    "FindingCollection",
    "DetectorRegistry",
    "default_detector_registry",
    "KeywordDetector",
    "PromptInjectionDetector",
    "PIIDetector",
    "SecretDetector",
    "TokenHeuristics",
    "compute_token_heuristics",
    "FindingAggregator",
    "AdaptiveThreatConfig",
    "AdaptiveThreatEngine",
    "ContextualSignal",
    "HistoricalSignalTracker",
    "compute_shannon_entropy",
    "compute_token_repetition_ratio",
]

