"""LLMFirewall-Core — Advanced Developer Quickstart Example.

Demonstrates:
1. Built-in policy presets (e.g. 'strict' policy blocking PII instead of redacting).
2. StreamingTextGuard: sliding-window chunk inspection preventing token-boundary exfiltration.
3. AsyncLLMFirewallClient: non-blocking asynchronous scanning for high-throughput APIs.

Execution:
    python examples/quickstart/advanced_quickstart.py
"""

import asyncio
from llmfirewall import Action, Firewall
from llmfirewall.integrations import AsyncLLMFirewallClient, SecurityViolation, StreamingTextGuard


def test_strict_policy():
    print("=== 1. Strict Policy-as-Code Preset ===")
    fw_strict = Firewall(policy="strict")
    res_strict = fw_strict.scan("Contact me at user@internal.corp")
    print(f"Strict Policy Action on PII: {res_strict.action}")
    print(f"Is Blocked: {res_strict.is_blocked}")
    assert res_strict.is_blocked is True


def test_streaming_guard():
    print("\n=== 2. In-Flight StreamingTextGuard ===")
    guard = StreamingTextGuard()
    # Simulates tokens split across chunk boundaries
    chunks = ["Here ", "is ", "the ", "key: ", "AKIA", "IOSFODNN7", "EXAMPLE"]
    blocked = False
    try:
        for chunk in guard.protect_stream(chunks):
            pass
    except SecurityViolation as exc:
        blocked = True
        print(f"Streaming token leak intercepted: {exc.message}")
    assert blocked is True


async def test_async_client():
    print("\n=== 3. Asynchronous Non-Blocking Client ===")
    client = AsyncLLMFirewallClient(firewall=Firewall())
    res = await client.scan_prompt("Is quantum entanglement real?")
    print(f"Async scan result: {res.action} in {res.execution_time_ms:.2f}ms")
    assert res.is_allowed is True


def main():
    test_strict_policy()
    test_streaming_guard()
    asyncio.run(test_async_client())
    print("\n[SUCCESS] Advanced quickstart checks completed successfully!")


if __name__ == "__main__":
    main()
