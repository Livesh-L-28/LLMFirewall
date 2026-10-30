# Real-Time Streaming Text Guard Recipe

This recipe demonstrates securing real-time streaming LLM outputs using `StreamingTextGuard` to prevent split-token jailbreaks and data leakage across streaming chunk boundaries.

---

## 1. When to Use It

- Your application streams tokens in real-time from an LLM (e.g., OpenAI `stream=True`, Anthropic streaming, or vLLM Server-Sent Events).
- You need in-flight inspection that prevents adversarial split-token evasions (e.g., splitting a secret or jailbreak payload across consecutive 2-character chunks).
- You want seamless in-flight PII redaction without breaking SSE or WebSocket streams.

---

## 2. Prerequisites

Requires only the base `llmfirewall-core` package:

```bash
pip install llmfirewall-core
```

---

## 3. Minimal Complete Example

### Synchronous Streaming

```python
from typing import Iterable
from llmfirewall import Firewall
from llmfirewall.integrations import StreamingTextGuard, SecurityViolation

firewall = Firewall()
guard = StreamingTextGuard(
    firewall=firewall,
    window_size=512,  # Buffer threshold before triggering window scan
    overlap_size=128, # Sliding overlap to detect tokens split across chunk boundaries
    fail_closed=True, # Raise SecurityViolation on block
)

def secure_token_stream(raw_chunks: Iterable[str]):
    try:
        # Wrap raw chunk generator with sliding-window protection
        for safe_chunk in guard.protect_stream(raw_chunks):
            yield safe_chunk
    except SecurityViolation as err:
        yield f"\n[STREAM TERMINATED BY SECURITY POLICY: {err.message}]"
```

### Asynchronous Streaming

```python
from typing import AsyncIterable
from llmfirewall.integrations import StreamingTextGuard, SecurityViolation

guard = StreamingTextGuard()

async def secure_async_stream(raw_async_chunks: AsyncIterable[str]):
    try:
        async for safe_chunk in guard.protect_async_stream(raw_async_chunks):
            yield safe_chunk
    except SecurityViolation as err:
        yield f"\n[STREAM TERMINATED BY SECURITY POLICY: {err.message}]"
```

---

## 4. Security Boundary & Sliding-Window Mechanics

Traditional chunk-by-chunk scanners fail against split-token attacks. For example, if an LLM emits:
- Chunk 1: `"sk-proj-"`
- Chunk 2: `"9876543210ABCDEF"`

Scanning each chunk independently misses the credential.

`StreamingTextGuard` maintains an accumulated buffer:
1. Chunks accumulate until `window_size` (default 512 characters) is reached or stream terminates.
2. The window is scanned against the Firewall's output detectors.
3. If `Action.BLOCK` is triggered, the stream terminates immediately, raising `SecurityViolation`.
4. If `Action.REDACT` is triggered, sanitized text is emitted.
5. `overlap_size` (default 128 characters) is retained in the buffer to guarantee detection across subsequent window boundaries.

---

## 5. Automated Verification Test

Save as `test_streaming_recipe.py` and run with `pytest`:

```python
import pytest
from llmfirewall import Firewall
from llmfirewall.integrations import StreamingTextGuard, SecurityViolation

@pytest.fixture
def guard():
    fw = Firewall()
    return StreamingTextGuard(firewall=fw, window_size=64, overlap_size=16)

def test_streaming_benign_chunks(guard):
    chunks = ["The capital ", "of France ", "is Paris."]
    output = list(guard.protect_stream(chunks))
    assert "".join(output) == "The capital of France is Paris."

def test_streaming_blocks_adversarial_completion(guard):
    # Simulated model output leaking credentials
    chunks = [
        "Sure, here is your API key: ",
        "AKIA",
        "IOSFODNN7EXAMPLE",
        " please store it safely."
    ]
    with pytest.raises(SecurityViolation) as exc_info:
        list(guard.protect_stream(chunks))
    assert exc_info.value.status_code == 403

def test_streaming_redacts_pii_in_flight(guard):
    chunks = ["Please contact ", "alice@example.com ", "for support."]
    output = list(guard.protect_stream(chunks))
    combined = "".join(output)
    assert "alice@example.com" not in combined
    assert "[REDACTED_EMAIL]" in combined
```

---

## 6. Troubleshooting

- **Issue**: Stream latency feels delayed on the first word.
  - **Fix**: Adjust `window_size` down to `128` or `256` for more frequent emissions, or use client adapters (`client.protect_stream`).
- **Issue**: How to handle violations gracefully without raising exceptions.
  - **Fix**: Provide `on_violation=callback` and set `fail_closed=False`:
    ```python
    guard = StreamingTextGuard(fail_closed=False)
    for safe_chunk in guard.protect_stream(chunks, on_violation=my_alert_handler):
        yield safe_chunk
    ```
