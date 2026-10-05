"""Example demonstrating custom detector development in LLMFirewall v1.1.0.

This example showcases both supported detector extension patterns:
1. Classical Inheritance: Subclassing `Detector` (which inherits from `BaseDetector`).
2. Structural Typing: Implementing `DetectorProtocol` without framework inheritance.
"""

from typing import Any, Dict, List, Optional
from llmfirewall import (
    Action,
    Detector,
    DetectorCost,
    DetectorMetadata,
    DetectorProtocol,
    Finding,
    Firewall,
    Severity,
    ThreatType,
)


# ---------------------------------------------------------------------------
# Pattern 1: Classical Inheritance Subclass
# ---------------------------------------------------------------------------
class CustomForbiddenProjectDetector(Detector):
    """Detects internal confidential project codenames."""

    CODENAMES = ["project-titan", "operation-valkyrie", "confidential-phoenix"]

    @property
    def metadata(self) -> DetectorMetadata:
        return DetectorMetadata(
            name="custom_project_detector",
            description="Identifies confidential project codenames.",
            version="1.0.0",
            supported_threats=[ThreatType.POLICY_VIOLATION],
            supported_directions=["input", "output"],
            cost=DetectorCost.CHEAP,
            trigger_hints=["project-", "operation-"],
        )

    def detect(self, text: str, context: Optional[Dict[str, Any]] = None) -> List[Finding]:
        findings: List[Finding] = []
        lower = text.lower()
        for codename in self.CODENAMES:
            idx = lower.find(codename)
            if idx != -1:
                findings.append(
                    Finding(
                        detector_name=self.name,
                        threat_type=ThreatType.POLICY_VIOLATION,
                        description=f"Detected confidential codename '{codename}'",
                        severity=Severity.HIGH,
                        confidence=1.0,
                        start_pos=idx,
                        end_pos=idx + len(codename),
                        matched_text=text[idx : idx + len(codename)],
                        replacement_text="[CONFIDENTIAL_PROJECT]",
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# Pattern 2: Structural Typing (Protocol Conformance)
# ---------------------------------------------------------------------------
class ExternalVendorDetector:
    """Implements DetectorProtocol structurally WITHOUT subclassing any LLMFirewall class."""

    @property
    def name(self) -> str:
        return "external_vendor_detector"

    @property
    def metadata(self) -> DetectorMetadata:
        return DetectorMetadata(
            name=self.name,
            description="Third-party vendor structural detector.",
            version="2.1.0",
            supported_threats=[ThreatType.CUSTOM],
            supported_directions=["input"],
            cost=DetectorCost.NORMAL,
            trigger_hints=["vendor-key"],
        )

    def detect(self, text: str, context: Optional[Dict[str, Any]] = None) -> List[Finding]:
        if "vendor-key-forbidden" in text.lower():
            return [
                Finding(
                    detector_name=self.name,
                    threat_type=ThreatType.CUSTOM,
                    description="Prohibited third-party vendor test key encountered.",
                    severity=Severity.CRITICAL,
                    confidence=0.98,
                )
            ]
        return []


def main() -> None:
    # 1. Verify runtime structural typing check
    vendor_detector = ExternalVendorDetector()
    assert isinstance(vendor_detector, DetectorProtocol), "Must satisfy DetectorProtocol"

    # 2. Instantiate custom detector
    project_detector = CustomForbiddenProjectDetector()

    # 3. Initialize firewall and register detectors with internal DetectorEngine
    fw = Firewall()
    fw.detector_engine.add_detector(project_detector)
    fw.detector_engine.add_detector(vendor_detector)

    # 4. Test safe prompt
    safe_res = fw.scan("What is the weather forecast for tomorrow?")
    print(f"Safe prompt scan action: {safe_res.action} (Allowed: {safe_res.is_allowed})")

    # 5. Test confidential project detection
    confidential_res = fw.scan("Please review the architecture for project-titan.")
    print(f"Confidential project scan action: {confidential_res.action}")
    for f in confidential_res.findings:
        print(f"  Finding: [{f.threat_type}] {f.description} (Confidence: {f.confidence})")

    # 6. Test structural vendor detector
    vendor_res = fw.scan("Encountered vendor-key-forbidden in auth config.")
    print(f"Vendor detector scan action: {vendor_res.action}")
    for f in vendor_res.findings:
        print(f"  Finding: [{f.threat_type}] {f.description} (Severity: {f.severity})")


if __name__ == "__main__":
    main()
