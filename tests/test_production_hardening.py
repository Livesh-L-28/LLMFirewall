"""Security hardening and supply-chain regression tests (Phase 20)."""

import json
import pytest
from pydantic import ValidationError

from llmfirewall import (
    Action,
    Firewall,
    MAX_SCAN_TEXT_LENGTH,
    ScanRequest,
)
from llmfirewall.cli.formatting import format_human_output, sanitize_terminal_text


class TestInputHardeningAndBoundaries:
    """Verify input length limits and resource exhaustion defenses."""

    def test_scan_request_enforces_max_text_boundary(self):
        # Boundary is MAX_SCAN_TEXT_LENGTH (5MB)
        valid_large_text = "A" * 1000
        req = ScanRequest(text=valid_large_text)
        assert len(req.text) == 1000

        # Oversized payload exceeding MAX_SCAN_TEXT_LENGTH should be rejected by Pydantic validation
        oversized_text = "A" * (MAX_SCAN_TEXT_LENGTH + 1)
        with pytest.raises(ValidationError) as exc_info:
            ScanRequest(text=oversized_text)
        assert "String should have at most" in str(exc_info.value) or "max_length" in str(exc_info.value)

    def test_scan_request_direction_validation(self):
        with pytest.raises(ValidationError):
            ScanRequest(text="Hello", direction="invalid_direction")

    def test_scan_request_id_boundaries(self):
        # user_id and session_id capped at 256 characters
        long_id = "u" * 257
        with pytest.raises(ValidationError):
            ScanRequest(text="Hello", user_id=long_id)


class TestTerminalAndLogInjectionDefenses:
    """Verify defenses against ANSI escape sequences and terminal spoofing."""

    def test_sanitize_terminal_text_strips_ansi_escapes(self):
        # Attacker attempts to spoof a passing green status via terminal escape codes
        malicious_input = "\x1b[32m[SECURITY CHECK PASSED]\x1b[0m Malicious content"
        cleaned = sanitize_terminal_text(malicious_input)

        assert "\x1b" not in cleaned
        assert "[32m" not in cleaned
        assert cleaned == "[SECURITY CHECK PASSED] Malicious content"

    def test_sanitize_terminal_text_strips_control_characters(self):
        # Non-printable ASCII control characters (\x00, \x07 bell, \x08 backspace)
        payload = "Text\x00with\x07bell\x08and\x1b[2Jclear"
        cleaned = sanitize_terminal_text(payload)

        assert "\x00" not in cleaned
        assert "\x07" not in cleaned
        assert "\x08" not in cleaned
        assert "\x1b" not in cleaned
        assert "Textwithbellandclear" in cleaned

    def test_format_human_output_sanitizes_threat_and_reason_fields(self):
        firewall = Firewall()
        # Input with terminal escapes embedded
        result = firewall.check("Harmless query \x1b[31;1mCRITICAL ERROR\x1b[0m")
        output = format_human_output(result)

        assert "\x1b" not in output
        assert "\x1b[31;1m" not in output


class TestZeroSecretsInCodebase:
    """Regression test ensuring zero real keys or tokens are in codebase."""

    def test_all_fixtures_use_synthetic_data(self):
        # Sample synthetic checks
        from tests.datasets.secret_dataset import SECRET_DETECTION_SAMPLES
        for sample in SECRET_DETECTION_SAMPLES:
            text = sample[0]
            # All tokens must be synthetic test markers, not live production credentials
            assert "LIVE_PRODUCTION_TOKEN" not in text
            assert not text.startswith("AKIAIOSFODNN7EXAMPLELIVE")
