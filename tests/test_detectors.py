"""Unit tests for Phase 4: Detector Architecture."""

import pytest
from llmfirewall.core.exceptions import ConfigurationError, LLMFirewallError
from llmfirewall.core.models import Finding, Severity, ThreatType
from llmfirewall.detectors.base import Detector
from llmfirewall.detectors.collection import FindingCollection
from llmfirewall.detectors.engine import DetectorEngine
from llmfirewall.detectors.examples import KeywordDetector
from llmfirewall.detectors.metadata import DetectorMetadata
from llmfirewall.detectors.registry import DetectorRegistry


class CrashingDetector(Detector):
    @property
    def metadata(self) -> DetectorMetadata:
        return DetectorMetadata(
            name="crashing_detector",
            description="Always raises an unhandled error for testing failure isolation.",
        )

    def detect(self, text: str, context=None):
        raise RuntimeError("Simulated crash inside detector")


class OutputOnlyDetector(Detector):
    @property
    def metadata(self) -> DetectorMetadata:
        return DetectorMetadata(
            name="output_only_detector",
            description="Runs only on output text.",
            supported_directions=["output"],
        )

    def detect(self, text: str, context=None):
        return [
            Finding(
                detector_name=self.name,
                threat_type=ThreatType.POLICY_VIOLATION,
                description="Output check triggered",
                severity=Severity.LOW,
            )
        ]


def test_detector_metadata_and_name_property():
    detector = KeywordDetector(keywords=["test"])
    assert detector.name == "keyword_test_detector"
    assert detector.metadata.supported_threats == [ThreatType.CUSTOM]
    assert "input" in detector.metadata.supported_directions


def test_detector_registry():
    registry = DetectorRegistry()
    detector1 = KeywordDetector(keywords=["one"])
    detector2 = OutputOnlyDetector()

    # Register
    registry.register(detector1)
    registry.register(detector2)
    assert len(registry) == 2
    assert "keyword_test_detector" in registry
    assert "output_only_detector" in registry

    # Prevent duplicate registration without override
    with pytest.raises(ConfigurationError, match="is already registered"):
        registry.register(detector1)

    # Allow override
    registry.register(detector1, override=True)
    assert len(registry) == 2

    # Unregister & get
    assert registry.get("output_only_detector") is detector2
    registry.unregister("output_only_detector")
    assert len(registry) == 1
    assert registry.get("output_only_detector") is None

    # Clear
    registry.clear()
    assert len(registry) == 0


def test_detector_execution_empty_results():
    detector = KeywordDetector(keywords=["secret_phrase"])
    engine = DetectorEngine(detectors=[detector])

    collection = engine.execute(text="A perfectly benign message")
    assert isinstance(collection, FindingCollection)
    assert len(collection) == 0
    assert collection.is_empty is True
    assert collection.has_errors is False
    assert collection.max_severity is None


def test_detector_execution_multiple_findings():
    detector = KeywordDetector(
        keywords=["leak", "bypass"],
        severity=Severity.HIGH,
        threat_type=ThreatType.PROMPT_INJECTION,
    )
    engine = DetectorEngine(detectors=[detector])

    text = "We will attempt a bypass and cause a leak of secrets!"
    collection = engine.execute(text=text)

    assert len(collection) == 2
    assert collection.is_empty is False
    assert collection.max_severity == Severity.HIGH

    # Verify positions and matches
    matches = {f.matched_text for f in collection}
    assert matches == {"bypass", "leak"}

    # Test filtering utilities on FindingCollection
    by_threat = collection.filter_by_threat(ThreatType.PROMPT_INJECTION)
    assert len(by_threat) == 2

    by_min_sev = collection.filter_by_min_severity(Severity.HIGH)
    assert len(by_min_sev) == 2

    by_detector = collection.filter_by_detector("keyword_test_detector")
    assert len(by_detector) == 2


def test_detector_direction_filtering():
    out_detector = OutputOnlyDetector()
    engine = DetectorEngine(detectors=[out_detector])

    # Scanning input prompt: should be ignored
    input_res = engine.execute(text="Sample input prompt", direction="input")
    assert len(input_res) == 0

    # Scanning output: should execute
    output_res = engine.execute(text="Sample LLM response", direction="output")
    assert len(output_res) == 1
    assert output_res[0].detector_name == "output_only_detector"


def test_detector_failure_handling_default_isolated():
    # By default, fail_fast=False so an unhandled detector error is isolated
    crashing = CrashingDetector()
    keyword = KeywordDetector(keywords=["flag"])
    engine = DetectorEngine(detectors=[crashing, keyword], fail_fast=False)

    collection = engine.execute(text="Here is a flag to detect")

    # The failing detector does not halt execution; the keyword detector still runs
    assert len(collection) == 1
    assert collection[0].matched_text == "flag"

    # Non-fatal error is captured in collection.errors
    assert collection.has_errors is True
    assert len(collection.errors) == 1
    assert collection.errors[0]["detector"] == "crashing_detector"
    assert "Simulated crash" in collection.errors[0]["error"]


def test_detector_failure_handling_fail_fast():
    crashing = CrashingDetector()
    engine = DetectorEngine(detectors=[crashing], fail_fast=True)

    with pytest.raises(LLMFirewallError, match="crashing_detector.*Simulated crash"):
        engine.execute(text="Test input")
