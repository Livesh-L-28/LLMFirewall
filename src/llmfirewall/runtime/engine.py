"""LLM & Agent Runtime Security Engine, Decorators, and Session Factory.

Phase 26: LLM & Agent Runtime Protection.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import inspect
from typing import TYPE_CHECKING, Any, AsyncIterator, Callable, Dict, Iterator, List, Optional, TypeVar

if TYPE_CHECKING:
    from llmfirewall.firewall import Firewall

from llmfirewall.runtime.guard import LoopGuard
from llmfirewall.runtime.hooks import RuntimeHook
from llmfirewall.runtime.models import (
    ContentItem,
    LLMMessage,
    LLMRequest,
    LLMResponse,
    RuntimeBoundary,
    RuntimeContext,
    RuntimeDecision,
    RuntimeEventType,
    RuntimeLimitExceeded,
    RuntimeSecurityError,
    RuntimeSecurityState,
    TrustLevel,
)
from llmfirewall.runtime.session import RuntimeSession

F = TypeVar("F", bound=Callable[..., Any])


class RuntimeEngine:
    """Factory and manager for creating and orchestrating guarded runtime sessions."""

    def __init__(self, firewall: Optional["Firewall"] = None) -> None:
        if firewall is None:
            from llmfirewall.firewall import Firewall
            self.firewall = Firewall()
        else:
            self.firewall = firewall

    def create_session(
        self,
        context: Optional[RuntimeContext] = None,
        max_iterations: int = 25,
        max_tool_calls: int = 30,
        max_runtime_seconds: float = 120.0,
        max_repeated_tool_calls: int = 3,
        max_tokens: Optional[int] = None,
        max_cost: Optional[float] = None,
        block_on_loop: bool = True,
        raise_on_block: bool = True,
        hooks: Optional[List[RuntimeHook]] = None,
    ) -> RuntimeSession:
        """Create a new stateful RuntimeSession."""
        return RuntimeSession(
            firewall=self.firewall,
            context=context,
            max_iterations=max_iterations,
            max_tool_calls=max_tool_calls,
            max_runtime_seconds=max_runtime_seconds,
            max_repeated_tool_calls=max_repeated_tool_calls,
            max_tokens=max_tokens,
            max_cost=max_cost,
            block_on_loop=block_on_loop,
            raise_on_block=raise_on_block,
            hooks=hooks,
        )

    @contextlib.contextmanager
    def session(
        self,
        context: Optional[RuntimeContext] = None,
        max_iterations: int = 25,
        max_tool_calls: int = 30,
        max_runtime_seconds: float = 120.0,
        max_repeated_tool_calls: int = 3,
        max_tokens: Optional[int] = None,
        max_cost: Optional[float] = None,
        block_on_loop: bool = True,
        raise_on_block: bool = True,
        hooks: Optional[List[RuntimeHook]] = None,
    ) -> Iterator[RuntimeSession]:
        """Synchronous context manager yielding an active RuntimeSession and automatically finalizing it."""
        sess = self.create_session(
            context=context,
            max_iterations=max_iterations,
            max_tool_calls=max_tool_calls,
            max_runtime_seconds=max_runtime_seconds,
            max_repeated_tool_calls=max_repeated_tool_calls,
            max_tokens=max_tokens,
            max_cost=max_cost,
            block_on_loop=block_on_loop,
            raise_on_block=raise_on_block,
            hooks=hooks,
        )
        try:
            yield sess
        finally:
            sess.finalize()

    @contextlib.asynccontextmanager
    async def async_session(
        self,
        context: Optional[RuntimeContext] = None,
        max_iterations: int = 25,
        max_tool_calls: int = 30,
        max_runtime_seconds: float = 120.0,
        max_repeated_tool_calls: int = 3,
        max_tokens: Optional[int] = None,
        max_cost: Optional[float] = None,
        block_on_loop: bool = True,
        raise_on_block: bool = True,
        hooks: Optional[List[RuntimeHook]] = None,
    ) -> AsyncIterator[RuntimeSession]:
        """Asynchronous context manager yielding an active RuntimeSession and automatically finalizing it."""
        sess = self.create_session(
            context=context,
            max_iterations=max_iterations,
            max_tool_calls=max_tool_calls,
            max_runtime_seconds=max_runtime_seconds,
            max_repeated_tool_calls=max_repeated_tool_calls,
            max_tokens=max_tokens,
            max_cost=max_cost,
            block_on_loop=block_on_loop,
            raise_on_block=raise_on_block,
            hooks=hooks,
        )
        try:
            yield sess
        finally:
            sess.finalize()

    def protect_agent(
        self,
        max_iterations: int = 25,
        max_tool_calls: int = 30,
        max_runtime_seconds: float = 120.0,
        raise_on_block: bool = True,
    ) -> Callable[[F], F]:
        """Decorator wrapping a sync or async agent function with a monitored RuntimeSession."""
        def decorator(func: F) -> F:
            is_coro = inspect.iscoroutinefunction(func)

            if is_coro:
                @functools.wraps(func)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    sess = self.create_session(
                        max_iterations=max_iterations,
                        max_tool_calls=max_tool_calls,
                        max_runtime_seconds=max_runtime_seconds,
                        raise_on_block=raise_on_block,
                    )
                    # Extract prompt text from first arg if string
                    if args and isinstance(args[0], str):
                        sess.check_user_input(args[0])
                    try:
                        res = await func(*args, session=sess, **kwargs)
                        if isinstance(res, str):
                            sess.check_llm_response(res)
                        return res
                    finally:
                        sess.finalize()
                return async_wrapper  # type: ignore[return-value]
            else:
                @functools.wraps(func)
                def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                    sess = self.create_session(
                        max_iterations=max_iterations,
                        max_tool_calls=max_tool_calls,
                        max_runtime_seconds=max_runtime_seconds,
                        raise_on_block=raise_on_block,
                    )
                    if args and isinstance(args[0], str):
                        sess.check_user_input(args[0])
                    try:
                        res = func(*args, session=sess, **kwargs)
                        if isinstance(res, str):
                            sess.check_llm_response(res)
                        return res
                    finally:
                        sess.finalize()
                return sync_wrapper  # type: ignore[return-value]

        return decorator
