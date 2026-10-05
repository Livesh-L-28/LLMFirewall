"""Streaming Chunk Inspection & In-Flight Protection for LLMFirewall v1.1.0 (Phase 51).

Provides boundary-aware streaming inspection with rolling sliding-window overlap
to prevent split-token evasions across streaming chunk boundaries.
"""

from typing import Any, AsyncGenerator, AsyncIterable, Callable, Dict, Generator, Iterable, List, Optional
from llmfirewall.core.exceptions import BlockedOutputError
from llmfirewall.core.models import Action, Finding, ScanResult, Severity
from llmfirewall.firewall import Firewall
from llmfirewall.integrations.base import SecurityViolation


class StreamingTextGuard:
    """Sliding-window stream protector for synchronous and asynchronous chunk streams."""

    def __init__(
        self,
        firewall: Optional[Firewall] = None,
        window_size: int = 512,
        overlap_size: int = 128,
        fail_closed: bool = True,
    ) -> None:
        self.firewall = firewall or Firewall()
        self.window_size = window_size
        self.overlap_size = overlap_size
        self.fail_closed = fail_closed

    def protect_stream(
        self,
        stream: Iterable[str],
        context: Optional[Dict[str, Any]] = None,
        on_violation: Optional[Callable[[ScanResult], None]] = None,
    ) -> Generator[str, None, None]:
        """Synchronously inspect and yield safe streaming text chunks."""
        buffer = ""
        ctx = context or {}

        for chunk in stream:
            if not chunk:
                continue

            buffer += chunk

            # When accumulated buffer exceeds window_size or contains complete tokens, scan window
            if len(buffer) >= self.window_size:
                scan_res = self.firewall.scan_output(buffer, context=ctx)
                if scan_res.action == Action.BLOCK:
                    if on_violation:
                        on_violation(scan_res)
                    if self.fail_closed:
                        raise SecurityViolation(
                            f"Streaming output blocked by policy: {scan_res.reason}",
                            scan_result=scan_res,
                            status_code=403,
                        )
                    return

                # If redacted, emit sanitized prefix
                to_emit = scan_res.sanitized_text if scan_res.action == Action.REDACT and scan_res.sanitized_text else buffer
                emit_len = len(to_emit) - self.overlap_size
                if emit_len > 0:
                    yield to_emit[:emit_len]
                    buffer = to_emit[emit_len:]
                else:
                    # Overlap is larger than text; retain buffer
                    pass

        # Final flush on stream termination
        if buffer:
            scan_res = self.firewall.scan_output(buffer, context=ctx)
            if scan_res.action == Action.BLOCK:
                if on_violation:
                    on_violation(scan_res)
                if self.fail_closed:
                    raise SecurityViolation(
                        f"Streaming output blocked on terminal chunk: {scan_res.reason}",
                        scan_result=scan_res,
                        status_code=403,
                    )
                return

            final_text = scan_res.sanitized_text if scan_res.action == Action.REDACT and scan_res.sanitized_text else buffer
            yield final_text

    async def protect_async_stream(
        self,
        stream: AsyncIterable[str],
        context: Optional[Dict[str, Any]] = None,
        on_violation: Optional[Callable[[ScanResult], None]] = None,
    ) -> AsyncGenerator[str, None]:
        """Asynchronously inspect and yield safe streaming text chunks."""
        buffer = ""
        ctx = context or {}

        async for chunk in stream:
            if not chunk:
                continue

            buffer += chunk

            if len(buffer) >= self.window_size:
                scan_res = self.firewall.scan_output(buffer, context=ctx)
                if scan_res.action == Action.BLOCK:
                    if on_violation:
                        on_violation(scan_res)
                    if self.fail_closed:
                        raise SecurityViolation(
                            f"Streaming output blocked by policy: {scan_res.reason}",
                            scan_result=scan_res,
                            status_code=403,
                        )
                    return

                to_emit = scan_res.sanitized_text if scan_res.action == Action.REDACT and scan_res.sanitized_text else buffer
                emit_len = len(to_emit) - self.overlap_size
                if emit_len > 0:
                    yield to_emit[:emit_len]
                    buffer = to_emit[emit_len:]

        # Final flush
        if buffer:
            scan_res = self.firewall.scan_output(buffer, context=ctx)
            if scan_res.action == Action.BLOCK:
                if on_violation:
                    on_violation(scan_res)
                if self.fail_closed:
                    raise SecurityViolation(
                        f"Streaming output blocked on terminal chunk: {scan_res.reason}",
                        scan_result=scan_res,
                        status_code=403,
                    )
                return

            final_text = scan_res.sanitized_text if scan_res.action == Action.REDACT and scan_res.sanitized_text else buffer
            yield final_text
