"""Comprehensive integration tests for Output Firewall scanning and policy enforcement."""

import pytest
from llmfirewall.core.models import Action, Severity, ThreatType
from llmfirewall.firewall import Firewall
from llmfirewall.policy.config import PolicyConfig, PolicyRule
from llmfirewall.policy.redaction_config import RedactionConfig


# -------------------------------------------------------------------
# Test 1: Explicit check_prompt() vs check_output() API distinction
# -------------------------------------------------------------------
def test_explicit_api_distinction_prompt_vs_output():
    firewall = Firewall()

    prompt_res = firewall.check_prompt("How do I contact customer support?")
    assert prompt_res.metadata["direction"] == "input"
    assert prompt_res.is_allowed is True

    output_res = firewall.check_output("You can reach us at helpdesk@company.com.")
    assert output_res.metadata["direction"] == "output"
    # PII in output should trigger redaction
    assert output_res.decision.action == Action.REDACT
    assert output_res.text == "You can reach us at [REDACTED_EMAIL]."


# -------------------------------------------------------------------
# Test 2: Output Secret Detection & Block
# -------------------------------------------------------------------
def test_output_secret_leak_blocked():
    """When an LLM accidentally regurgitates an internal API key or secret in its response."""
    firewall = Firewall()

    llm_generation = (
        "Here is the database initialization script: "
        "export OPENAI_API_KEY='sk-proj-1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef'"
    )
    result = firewall.check_output(llm_generation)

    assert result.metadata["direction"] == "output"
    assert result.decision.action == Action.BLOCK
    assert result.is_blocked is True
    assert result.text == ""  # Blocked response must NOT reach the user
    assert any(f.threat_type == ThreatType.SECRET for f in result.findings)

    # Security check: Never expose raw secret in finding
    secret_f = [f for f in result.findings if f.threat_type == ThreatType.SECRET][0]
    assert secret_f.matched_text is None


# -------------------------------------------------------------------
# Test 3: Output PII Detection & Safe Redaction
# -------------------------------------------------------------------
def test_output_pii_sanitized_via_redaction():
    """When an LLM / RAG pipeline retrieves database rows containing customer PII."""
    firewall = Firewall()

    rag_answer = (
        "Based on our records, user John Doe has phone number +1-800-555-0199 "
        "and email jdoe@internal.org."
    )
    result = firewall.check_output(rag_answer)

    assert result.decision.action == Action.REDACT
    assert result.is_allowed is True
    assert "[REDACTED_PHONE]" in result.text
    assert "[REDACTED_EMAIL]" in result.text
    assert "+1-800-555-0199" not in result.text
    assert "jdoe@internal.org" not in result.text
    # Surrounding text preserved
    assert result.text.startswith("Based on our records, user John Doe has phone number [REDACTED_PHONE]")


# -------------------------------------------------------------------
# Test 4: Custom Output Policy Rule (e.g. Block PII in output instead of Redact)
# -------------------------------------------------------------------
def test_custom_output_specific_policy_enforcement():
    """Configure strict compliance policy: Redact PII in input, but BLOCK if PII appears in output."""
    strict_policy = PolicyConfig(
        rules=[
            # Input rule: Redact PII in input prompts
            PolicyRule(
                id="input_pii_redact",
                description="Redact PII in user inputs",
                threat_type=ThreatType.PII,
                direction="input",
                action=Action.REDACT,
            ),
            # Output rule: Strict zero-PII leak policy on LLM outputs -> BLOCK
            PolicyRule(
                id="output_pii_block",
                description="Strictly block any LLM output containing PII",
                threat_type=ThreatType.PII,
                direction="output",
                action=Action.BLOCK,
            ),
        ]
    )
    firewall = Firewall()
    from llmfirewall.policy.engine import PolicyEngine
    firewall._policy_engine = PolicyEngine(config=strict_policy)

    # Same PII string on input: REDACT
    res_input = firewall.check_prompt("My email is alice@test.com")
    assert res_input.decision.action == Action.REDACT
    assert res_input.is_allowed is True
    assert res_input.text == "My email is [REDACTED_EMAIL]"

    # Same PII string on output: BLOCK
    res_output = firewall.check_output("The customer email is alice@test.com")
    assert res_output.decision.action == Action.BLOCK
    assert res_output.is_blocked is True
    assert res_output.text == ""
    assert "output_pii_block" in res_output.decision.triggered_rules


# -------------------------------------------------------------------
# Test 5: End-to-End Dual Barrier Flow (Input + Output)
# -------------------------------------------------------------------
def test_end_to_end_dual_barrier_simulation():
    """Simulates a complete real-world application request-response lifecycle."""
    firewall = Firewall()

    # User Query
    user_prompt = "Can you look up customer records for alice@company.com?"
    input_scan = firewall.check_prompt(user_prompt)

    # Input firewall sanitizes email before prompt reaches LLM
    assert input_scan.is_allowed is True
    assert input_scan.text == "Can you look up customer records for [REDACTED_EMAIL]?"

    # Simulated LLM generation (e.g. LLM generates simulated phone number)
    simulated_llm_response = (
        "Found account for [REDACTED_EMAIL]. Customer contact phone is 555-678-1234."
    )
    output_scan = firewall.check_output(simulated_llm_response)

    # Output firewall redacts phone number before response reaches user app
    assert output_scan.is_allowed is True
    assert output_scan.text == "Found account for [REDACTED_EMAIL]. Customer contact phone is [REDACTED_PHONE]."
