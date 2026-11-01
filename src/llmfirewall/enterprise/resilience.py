"""Enterprise resilience, failure policies, circuit breaker, and retry utilities."""

from __future__ import annotations

from enum import Enum
import functools
import logging
import random
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Type, TypeVar

logger = logging.getLogger("llmfirewall.enterprise.resilience")

F = TypeVar("F", bound=Callable[..., Any])


class FailurePolicy(str, Enum):
    """Failure policy governing behavior when external enterprise infrastructure fails."""
    FAIL_OPEN = "FAIL_OPEN"          # Allow request, log warning, record degraded metric
    FAIL_CLOSED = "FAIL_CLOSED"      # Reject request with security error / HTTP 503
    REJECT_TEMPORARILY = "REJECT_TEMPORARILY"  # Return temporary rate limit / retry-after


class CircuitState(str, Enum):
    """Operational states of a circuit breaker."""
    CLOSED = "CLOSED"        # Normal operation: requests pass through
    OPEN = "OPEN"            # Tripped: requests fail immediately without calling backend
    HALF_OPEN = "HALF_OPEN"  # Testing recovery: single probe requests allowed


class CircuitBreakerOpenError(Exception):
    """Raised when an operation is attempted while the circuit breaker is OPEN."""
    def __init__(self, name: str, reset_timeout: float) -> None:
        super().__init__(f"Circuit breaker '{name}' is OPEN. Retry after {reset_timeout:.1f}s")
        self.name = name
        self.reset_timeout = reset_timeout


class CircuitBreaker:
    """Thread-safe circuit breaker protecting downstream dependencies from cascading failures.

    State Transitions:
      CLOSED --(failure_threshold reached)--> OPEN
      OPEN   --(recovery_timeout elapsed)--> HALF_OPEN
      HALF_OPEN --(probe succeeds)----------> CLOSED
      HALF_OPEN --(probe fails)-------------> OPEN
    """

    def __init__(
        self,
        name: str = "default",
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        expected_exceptions: Optional[Tuple[Type[Exception], ...]] = None,
    ) -> None:
        self.name = name
        self.failure_threshold = max(1, failure_threshold)
        self.recovery_timeout = max(0.1, recovery_timeout)
        self.expected_exceptions = expected_exceptions or (Exception,)

        self._state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._last_state_change = time.time()
        self._last_failure_time = 0.0

    @property
    def state(self) -> CircuitState:
        now = time.time()
        if self._state == CircuitState.OPEN:
            if now - self._last_state_change >= self.recovery_timeout:
                self._state = CircuitState.HALF_OPEN
                self._last_state_change = now
                logger.info("Circuit breaker '%s' transitioned to HALF_OPEN (probing)", self.name)
        return self._state

    def can_execute(self) -> bool:
        """Evaluate if calls are currently permitted through the circuit."""
        return self.state != CircuitState.OPEN

    def record_success(self) -> None:
        if self._state != CircuitState.CLOSED:
            logger.info("Circuit breaker '%s' recovered and transitioned to CLOSED", self.name)
        self._state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._last_state_change = time.time()

    def record_failure(self, exc: Optional[Exception] = None) -> None:
        self._last_failure_time = time.time()
        self._consecutive_failures += 1

        if self._state == CircuitState.HALF_OPEN:
            # Probe failed, trip open again
            self._state = CircuitState.OPEN
            self._last_state_change = self._last_failure_time
            logger.warning("Circuit breaker '%s' probe failed: returning to OPEN", self.name)
        elif self._state == CircuitState.CLOSED and self._consecutive_failures >= self.failure_threshold:
            self._state = CircuitState.OPEN
            self._last_state_change = self._last_failure_time
            logger.warning(
                "Circuit breaker '%s' tripped OPEN after %d consecutive failures",
                self.name,
                self._consecutive_failures,
            )

    def __enter__(self) -> "CircuitBreaker":
        if not self.can_execute():
            raise CircuitBreakerOpenError(self.name, self.recovery_timeout)
        return self

    def __exit__(self, exc_type: Optional[Type[BaseException]], exc_val: Optional[BaseException], exc_tb: Any) -> bool:
        if exc_type is not None:
            if issubclass(exc_type, self.expected_exceptions):
                self.record_failure(exc_val if isinstance(exc_val, Exception) else None)
            return False
        else:
            self.record_success()
            return False

    def __call__(self, func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            state = self.state
            if state == CircuitState.OPEN:
                raise CircuitBreakerOpenError(self.name, self.recovery_timeout)

            try:
                result = func(*args, **kwargs)
                self.record_success()
                return result
            except self.expected_exceptions as exc:
                self.record_failure(exc)
                raise
        return wrapper  # type: ignore


def retry_with_backoff(
    max_retries: int = 3,
    base_delay: float = 0.05,
    max_delay: float = 2.0,
    exponential_base: float = 2.0,
    jitter: bool = True,
    retryable_exceptions: Optional[Tuple[Type[Exception], ...]] = None,
    is_idempotent: bool = True,
) -> Callable[[F], F]:
    """Decorator providing bounded exponential backoff with full jitter.

    Safety Invariant:
    If is_idempotent=False, automatic retries are disallowed to prevent duplicating non-idempotent operations.
    """
    exceptions = retryable_exceptions or (Exception,)

    def decorator(func: F) -> F:
        if not is_idempotent:
            # Safety guard: do not retry non-idempotent calls
            return func

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            attempt = 0
            while True:
                try:
                    return func(*args, **kwargs)
                except exceptions as exc:
                    attempt += 1
                    if attempt > max_retries:
                        raise

                    # Exponential delay with full jitter
                    delay = min(max_delay, base_delay * (exponential_base ** (attempt - 1)))
                    if jitter:
                        delay = random.uniform(0, delay)

                    logger.debug(
                        "Operation '%s' failed (attempt %d/%d). Retrying in %.3fs: %s",
                        func.__name__,
                        attempt,
                        max_retries,
                        delay,
                        exc,
                    )
                    time.sleep(delay)
        return wrapper  # type: ignore
    return decorator
