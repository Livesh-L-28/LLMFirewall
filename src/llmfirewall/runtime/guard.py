"""Agent Loop Guard: Iteration limits, tool budgets, repetition & loop detection, timeouts.

Phase 26: LLM & Agent Runtime Protection.
Guarantees:
- Enforces strict upper bounds on agent iterations, tool calls, and execution timeouts
- Detects repetitive or looping tool invocations (identical tool + arguments)
- Bounded in-memory sliding history to eliminate resource exhaustion
"""

from __future__ import annotations

import collections
import hashlib
import json
import time
from typing import Any, Dict, List, Optional

from llmfirewall.runtime.models import RuntimeLimitExceeded
from llmfirewall.tools.models import ToolCall


class LoopGuard:
    """Monitors and enforces operational safety limits for agent loops."""

    def __init__(
        self,
        max_iterations: int = 25,
        max_tool_calls: int = 30,
        max_runtime_seconds: float = 120.0,
        max_repeated_tool_calls: int = 3,
        max_tokens: Optional[int] = None,
        max_cost: Optional[float] = None,
        block_on_loop: bool = True,
        runtime_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> None:
        self.max_iterations = max_iterations
        self.max_tool_calls = max_tool_calls
        self.max_runtime_seconds = max_runtime_seconds
        self.max_repeated_tool_calls = max_repeated_tool_calls
        self.max_tokens = max_tokens
        self.max_cost = max_cost
        self.block_on_loop = block_on_loop
        self.runtime_id = runtime_id
        self.trace_id = trace_id

        self._start_time = time.monotonic()
        self._iteration_count = 0
        self._tool_call_count = 0
        self._tool_counts_by_name: Dict[str, int] = collections.defaultdict(int)
        self._total_tokens = 0
        self._estimated_cost = 0.0
        # Rolling window of recent call hashes to detect identical loops
        self._recent_call_hashes: collections.deque[str] = collections.deque(maxlen=20)

    @property
    def iteration_count(self) -> int:
        return self._iteration_count

    @property
    def tool_call_count(self) -> int:
        return self._tool_call_count

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self._start_time

    @property
    def total_tokens(self) -> int:
        return self._total_tokens

    @property
    def estimated_cost(self) -> float:
        return self._estimated_cost

    def check_iteration(self) -> None:
        """Call at the beginning of each agent reasoning loop step."""
        self._check_timeout()
        self._iteration_count += 1
        if self._iteration_count > self.max_iterations:
            raise RuntimeLimitExceeded(
                limit_name="max_iterations",
                configured_limit=self.max_iterations,
                observed_value=self._iteration_count,
                runtime_id=self.runtime_id,
                trace_id=self.trace_id,
            )

    def check_tool_call(self, tool_call: ToolCall) -> Optional[str]:
        """Call prior to tool authorization to enforce count budgets and repetition limits.
        
        Returns warning string if a loop pattern is observed without hard blocking,
        or raises RuntimeLimitExceeded if limits are reached.
        """
        self._check_timeout()
        self._tool_call_count += 1

        if self._tool_call_count > self.max_tool_calls:
            raise RuntimeLimitExceeded(
                limit_name="max_tool_calls",
                configured_limit=self.max_tool_calls,
                observed_value=self._tool_call_count,
                runtime_id=self.runtime_id,
                trace_id=self.trace_id,
            )

        self._tool_counts_by_name[tool_call.tool_name] += 1

        # Calculate deterministic signature of tool call (name + args)
        sig = f"{tool_call.tool_name}:{tool_call.serialize_arguments()}"
        call_hash = hashlib.sha256(sig.encode("utf-8")).hexdigest()

        # Count consecutive or recent occurrences of identical call
        recent_matches = sum(1 for h in self._recent_call_hashes if h == call_hash)
        self._recent_call_hashes.append(call_hash)

        if recent_matches >= self.max_repeated_tool_calls:
            msg = (
                f"Agent loop repetition detected: tool '{tool_call.tool_name}' invoked with "
                f"identical arguments {recent_matches + 1} times."
            )
            if self.block_on_loop:
                raise RuntimeLimitExceeded(
                    limit_name="max_repeated_tool_calls",
                    configured_limit=self.max_repeated_tool_calls,
                    observed_value=recent_matches + 1,
                    runtime_id=self.runtime_id,
                    trace_id=self.trace_id,
                )
            return msg

        return None

    def record_usage(self, prompt_tokens: int = 0, completion_tokens: int = 0, cost_estimate: float = 0.0) -> None:
        """Accumulate token and cost usage."""
        self._total_tokens += (prompt_tokens + completion_tokens)
        self._estimated_cost += cost_estimate

        if self.max_tokens is not None and self._total_tokens > self.max_tokens:
            raise RuntimeLimitExceeded(
                limit_name="max_tokens",
                configured_limit=self.max_tokens,
                observed_value=self._total_tokens,
                runtime_id=self.runtime_id,
                trace_id=self.trace_id,
            )

        if self.max_cost is not None and self._estimated_cost > self.max_cost:
            raise RuntimeLimitExceeded(
                limit_name="max_cost",
                configured_limit=self.max_cost,
                observed_value=self._estimated_cost,
                runtime_id=self.runtime_id,
                trace_id=self.trace_id,
            )

    def _check_timeout(self) -> None:
        elapsed = self.elapsed_seconds
        if elapsed > self.max_runtime_seconds:
            raise RuntimeLimitExceeded(
                limit_name="max_runtime_seconds",
                configured_limit=self.max_runtime_seconds,
                observed_value=round(elapsed, 2),
                runtime_id=self.runtime_id,
                trace_id=self.trace_id,
            )
