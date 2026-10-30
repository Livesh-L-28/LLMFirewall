import pytest
from examples.sample_apps.streaming_guard_service.app import stream_with_security_guard
from llmfirewall.integrations import SecurityViolation


def test_streaming_benign_tokens():
    """Benign token sequences pass through the sliding window unchanged."""
    tokens = ["The ", "quick ", "brown ", "fox ", "jumps ", "over."]
    result = list(stream_with_security_guard(tokens))
    assert "".join(result) == "The quick brown fox jumps over."


def test_streaming_split_token_credential_leak_blocked():
    """Split-token credential leakage across chunk boundaries triggers SecurityViolation."""
    tokens = [
        "Your AWS key is ",
        "AKIA",
        "IOSFODNN7EXAMPLE",
        " please store safely.",
    ]
    with pytest.raises(SecurityViolation) as exc_info:
        list(stream_with_security_guard(tokens))
    assert exc_info.value.status_code == 403


def test_streaming_pii_redacted_in_flight():
    """PII tokens in stream are redacted in-flight."""
    tokens = ["Please contact ", "alice@company.com ", "for support."]
    result = list(stream_with_security_guard(tokens))
    combined = "".join(result)
    assert "alice@company.com" not in combined
    assert "[REDACTED_EMAIL]" in combined
