"""Comprehensive unit tests for PIIDetector and modular PII sub-detectors."""

import pytest
from llmfirewall.core.models import Severity, ThreatType
from llmfirewall.detectors.pii.detector import PIIDetector
from llmfirewall.detectors.pii.sub_detectors import (
    CustomPatternSubDetector,
    EmailSubDetector,
    IPSubDetector,
    PaymentSubDetector,
    PhoneSubDetector,
    SSNSubDetector,
)
from llmfirewall.detectors.pii.validators import (
    is_valid_ip_address,
    is_valid_ssn,
    luhn_checksum_is_valid,
)


# -------------------------------------------------------------
# 1. Validator Tests
# -------------------------------------------------------------
def test_luhn_validator():
    # Valid Visa card numbers (synthetic test numbers: 4532 0150 1234 5671)
    assert luhn_checksum_is_valid("4532-0150-1234-5671") is True
    assert luhn_checksum_is_valid("4532015012345671") is True
    # Invalid card number (checksum wrong: 4532 0150 1234 5672)
    assert luhn_checksum_is_valid("4532-0150-1234-5672") is False
    # Too short / too long
    assert luhn_checksum_is_valid("123456") is False
    assert luhn_checksum_is_valid("12345678901234567890123") is False


def test_ip_validator():
    assert is_valid_ip_address("192.168.1.1") is True
    assert is_valid_ip_address("10.0.0.1") is True
    assert is_valid_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True
    assert is_valid_ip_address("::1") is True

    # Invalid: octets exceeding 255
    assert is_valid_ip_address("192.168.1.999") is False
    assert is_valid_ip_address("256.100.0.1") is False
    assert is_valid_ip_address("not.an.ip.address") is False


# -------------------------------------------------------------
# 2. Email Detection Tests (Positive & Negative)
# -------------------------------------------------------------
def test_email_sub_detector_positives():
    detector = EmailSubDetector()
    text = "Reach me at alice.smith+filter@example.com or bob_work@corp.co.uk."
    matches = detector.find_matches(text)
    assert len(matches) == 2
    assert matches[0].category == "email"
    assert matches[0].replacement_text == "[REDACTED_EMAIL]"


def test_email_sub_detector_negatives():
    detector = EmailSubDetector()
    # Code references, handles, or incomplete strings
    text = "Follow me @twitter and look at variable_name@2 for index."
    matches = detector.find_matches(text)
    assert len(matches) == 0


# -------------------------------------------------------------
# 3. Phone Detection Tests (Positive & Negative)
# -------------------------------------------------------------
def test_phone_sub_detector_positives():
    detector = PhoneSubDetector()
    examples = [
        "Call us at +1-800-555-0199 for help",
        "Cell: (555) 234-5678.",
        "Direct: +44 20 7946 0958",
        "Number: 555-678-1234",
    ]
    for ex in examples:
        matches = detector.find_matches(ex)
        assert len(matches) == 1, f"Failed on: {ex}"
        assert matches[0].category == "phone"
        assert matches[0].replacement_text == "[REDACTED_PHONE]"


def test_phone_sub_detector_negatives():
    detector = PhoneSubDetector()
    # Dates, timestamps, mathematical expressions, or version numbers
    examples = [
        "The release occurred on 2026-03-24 at 14:30.",
        "Calculate 100 - 200 - 300 - 400 for diff.",
        "Version v1.2.3.4 was deployed.",
        "Short number 555-123 is an extension.",
    ]
    for ex in examples:
        matches = detector.find_matches(ex)
        assert len(matches) == 0, f"False positive on: {ex}"


# -------------------------------------------------------------
# 4. IP Address Detection Tests (Positive & Negative)
# -------------------------------------------------------------
def test_ip_sub_detector_positives():
    detector = IPSubDetector()
    text = "Connected from server 192.168.1.150 and IPv6 gateway 2001:db8::1."
    matches = detector.find_matches(text)
    assert len(matches) == 2
    assert matches[0].replacement_text == "[REDACTED_IP]"


def test_ip_sub_detector_negatives():
    detector = IPSubDetector()
    # Semantic version numbers with >255 values, dates, or file names
    examples = [
        "We upgraded package to version 1.2.300.4 today.",
        "File model_v1.2.3.weights saved.",
    ]
    for ex in examples:
        matches = detector.find_matches(ex)
        assert len(matches) == 0, f"False positive on: {ex}"


# -------------------------------------------------------------
# 5. Payment Card Tests (Positive & Negative with Luhn)
# -------------------------------------------------------------
def test_payment_sub_detector_positives():
    detector = PaymentSubDetector()
    # Synthetic Luhn-valid Visa: 4532 0150 1234 5671
    text = "Charged card 4532-0150-1234-5671 for customer."
    matches = detector.find_matches(text)
    assert len(matches) == 1
    assert matches[0].category == "payment"
    assert matches[0].severity == Severity.HIGH
    assert matches[0].replacement_text == "[REDACTED_PAYMENT_CARD]"


def test_payment_sub_detector_negatives():
    detector = PaymentSubDetector()
    # Numbers that match the regex shape but fail the Luhn checksum
    text = "Invalid fake card number 4532-0150-1234-5675 should not trigger."
    matches = detector.find_matches(text)
    assert len(matches) == 0


# -------------------------------------------------------------
# 6. Custom Pattern Sub-Detector Tests
# -------------------------------------------------------------
def test_custom_pattern_sub_detector():
    # Example: Employee ID formatted as EMP-XXXXX
    custom = CustomPatternSubDetector(
        name="employee_id",
        pattern=r"\bEMP-\d{5}\b",
        description="Company Employee ID",
        replacement_text="[REDACTED_EMP_ID]",
    )
    text = "Employee EMP-98765 accessed the internal directory."
    matches = custom.find_matches(text)
    assert len(matches) == 1
    assert matches[0].category == "employee_id"
    assert matches[0].replacement_text == "[REDACTED_EMP_ID]"


# -------------------------------------------------------------
# 7. PIIDetector Orchestrator & Privacy by Default Tests
# -------------------------------------------------------------
def test_pii_detector_privacy_by_default():
    detector = PIIDetector()  # store_matched_text=False by default
    text = "User email is test@company.com with phone +1-555-123-4567."
    findings = detector.detect(text)

    assert len(findings) == 2
    # Verify no raw sensitive text leaked into matched_text
    assert findings[0].matched_text is None
    assert findings[1].matched_text is None

    # Spans and redaction templates are preserved
    assert findings[0].start_pos is not None
    assert findings[0].end_pos is not None
    assert findings[0].replacement_text is not None
    assert findings[0].threat_type == ThreatType.PII


def test_pii_detector_opt_in_matched_text():
    detector = PIIDetector(store_matched_text=True)
    text = "Contact: john@example.com"
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].matched_text == "john@example.com"


def test_pii_detector_category_filtering():
    # Enable only email detection
    detector = PIIDetector(enabled_categories={"email"})
    text = "Email: test@example.com, IP: 10.0.0.1, Phone: 555-123-4567"
    findings = detector.detect(text)

    assert len(findings) == 1
    assert findings[0].metadata["pii_category"] == "email"


def test_pii_detector_metadata():
    detector = PIIDetector()
    assert detector.metadata.name == "pii_detector"
    assert ThreatType.PII in detector.metadata.supported_threats
    assert "input" in detector.metadata.supported_directions
    assert "output" in detector.metadata.supported_directions


# -------------------------------------------------------------
# 8. Social Security Number (SSN) Tests
# -------------------------------------------------------------
def test_ssn_validator_positives_and_negatives():
    # Valid synthetic SSN patterns
    assert is_valid_ssn("219-45-7890") is True
    assert is_valid_ssn("123-45-6789") is True
    assert is_valid_ssn("456-78-9012") is True

    # Invalid area numbers: 000, 666, 900+
    assert is_valid_ssn("000-45-7890") is False
    assert is_valid_ssn("666-45-7890") is False
    assert is_valid_ssn("900-45-7890") is False
    assert is_valid_ssn("999-45-7890") is False

    # Invalid group numbers: 00
    assert is_valid_ssn("219-00-7890") is False

    # Invalid serial numbers: 0000
    assert is_valid_ssn("219-45-0000") is False

    # Non-PII context safety: order numbers, tracking numbers, and reference codes
    order_text = "Order reference code 123-45-6789 was completed on 2026-05-12."
    assert is_valid_ssn("123-45-6789", full_text=order_text, start_pos=21) is False


def test_ssn_sub_detector_positives():
    detector = SSNSubDetector()
    text = "Candidate identity confirmed with SSN 219-45-7890 on file."
    matches = detector.find_matches(text)
    assert len(matches) == 1
    assert matches[0].category == "ssn"
    assert matches[0].severity == Severity.HIGH
    assert matches[0].replacement_text == "[REDACTED_SSN]"
    assert matches[0].start_pos == 38
    assert matches[0].end_pos == 49


def test_ssn_sub_detector_negatives():
    detector = SSNSubDetector()
    # Order reference code should not be misidentified as SSN
    text = "Order reference code 123-45-6789 was completed on 2026-05-12."
    matches = detector.find_matches(text)
    assert len(matches) == 0

    # Structurally invalid numbers
    invalid_text = "Invalid tokens 000-12-3456 and 666-12-3456 and 912-34-5678 should not match."
    matches_invalid = detector.find_matches(invalid_text)
    assert len(matches_invalid) == 0


def test_pii_detector_default_includes_ssn():
    detector = PIIDetector()
    text = "Customer submitted SSN: 219-45-7890."
    findings = detector.detect(text)
    assert len(findings) == 1
    assert findings[0].metadata["pii_category"] == "ssn"
    assert findings[0].replacement_text == "[REDACTED_SSN]"
    assert findings[0].matched_text is None  # Privacy invariant preserved


def test_firewall_ssn_redaction_downstream():
    from llmfirewall import Action, Firewall

    fw = Firewall()
    prompt = "Please verify my application with SSN 219-45-7890 today."
    res = fw.scan(prompt)

    assert res.action == Action.REDACT
    assert res.is_allowed is True
    assert "219-45-7890" not in res.processed_text
    assert "[REDACTED_SSN]" in res.processed_text
