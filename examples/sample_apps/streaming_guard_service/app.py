"""Isolated Streaming Text Guard sample application with LLMFirewall."""

from typing import Iterable, List
from llmfirewall import Firewall
from llmfirewall.integrations import SecurityViolation, StreamingTextGuard


class LocalStreamingModelStub:
    """Deterministic local streaming model stub emitting chunk tokens."""

    def stream(self, tokens: List[str]) -> Iterable[str]:
        for token in tokens:
            yield token


model_stub = LocalStreamingModelStub()
firewall = Firewall()
guard = StreamingTextGuard(
    firewall=firewall,
    window_size=64,
    overlap_size=16,
    fail_closed=True,
)


def stream_with_security_guard(raw_tokens: List[str]) -> Iterable[str]:
    """Wraps model stub output with real-time sliding-window protection."""
    raw_stream = model_stub.stream(raw_tokens)
    for safe_chunk in guard.protect_stream(raw_stream):
        yield safe_chunk
