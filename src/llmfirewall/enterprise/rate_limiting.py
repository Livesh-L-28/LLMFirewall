"""Distributed, tenant-aware rate limiting subsystem with Redis and In-Memory backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import logging
import threading
import time
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple, Union

from llmfirewall.enterprise.resilience import CircuitBreaker, FailurePolicy

logger = logging.getLogger("llmfirewall.enterprise.rate_limiting")


class RateLimitDimension(str, Enum):
    """Dimensions across which request quotas can be enforced."""
    TENANT = "tenant"
    USER = "user"
    API_KEY = "api_key"
    APP = "app"
    ENDPOINT = "endpoint"
    GLOBAL = "global"


@dataclass(frozen=True)
class RateLimitResult:
    """Outcome of a rate-limit check."""
    allowed: bool
    limit: int
    remaining: int
    reset_after_seconds: float
    retry_after_seconds: float = 0.0
    dimension: str = "global"
    key_fingerprint: str = ""
    failure_policy_applied: Optional[FailurePolicy] = None

    def to_headers(self) -> Dict[str, str]:
        """RFC 6585 and draft IETF RateLimit HTTP headers."""
        headers = {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(max(0, self.remaining)),
            "X-RateLimit-Reset": str(int(time.time() + self.reset_after_seconds)),
        }
        if not self.allowed and self.retry_after_seconds > 0:
            headers["Retry-After"] = str(int(self.retry_after_seconds) + 1)
        return headers


class BaseRateLimiter(ABC):
    """Abstract interface for provider-independent rate limiters."""

    @abstractmethod
    def acquire(
        self,
        key: str,
        limit: int,
        window_seconds: float = 60.0,
        dimension: RateLimitDimension = RateLimitDimension.TENANT,
    ) -> RateLimitResult:
        """Evaluate if an action is permitted under the rate limit."""
        pass

    @abstractmethod
    def reset(self, key: Optional[str] = None) -> None:
        """Reset rate limit history for a key or all keys."""
        pass


class InMemoryRateLimiter(BaseRateLimiter):
    """Thread-safe, sliding-window in-memory rate limiter with zero external dependencies."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._history: Dict[str, Deque[float]] = {}

    def acquire(
        self,
        key: str,
        limit: int,
        window_seconds: float = 60.0,
        dimension: RateLimitDimension = RateLimitDimension.TENANT,
    ) -> RateLimitResult:
        now = time.time()
        cutoff = now - window_seconds
        fingerprint = self._hash_identifier(key)

        with self._lock:
            if key not in self._history:
                self._history[key] = deque(maxlen=max(limit * 2, 100))

            q = self._history[key]
            while q and q[0] <= cutoff:
                q.popleft()

            current = len(q)
            if current >= limit:
                oldest = q[0] if q else now
                retry_after = max(0.1, (oldest + window_seconds) - now)
                return RateLimitResult(
                    allowed=False,
                    limit=limit,
                    remaining=0,
                    reset_after_seconds=retry_after,
                    retry_after_seconds=retry_after,
                    dimension=dimension.value,
                    key_fingerprint=fingerprint,
                )

            q.append(now)
            remaining = limit - current - 1
            return RateLimitResult(
                allowed=True,
                limit=limit,
                remaining=remaining,
                reset_after_seconds=window_seconds,
                dimension=dimension.value,
                key_fingerprint=fingerprint,
            )

    def reset(self, key: Optional[str] = None) -> None:
        with self._lock:
            if key:
                self._history.pop(key, None)
            else:
                self._history.clear()

    @staticmethod
    def _hash_identifier(ident: str) -> str:
        if not ident:
            return "anonymous"
        return hashlib.sha256(ident.encode("utf-8")).hexdigest()[:12]


# Redis Sliding Window Atomic Lua Script
# ARGV[1]: current timestamp (float)
# ARGV[2]: window duration in seconds (float)
# ARGV[3]: limit (integer)
# ARGV[4]: unique request ID (string)
REDIS_SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
local cutoff = now - window

-- 1. Remove expired timestamps outside the sliding window
redis.call('ZREMRANGEBYSCORE', key, 0, cutoff)

-- 2. Count active events in current window
local current_count = redis.call('ZCARD', key)

if current_count < limit then
    -- Record this request with score = timestamp
    redis.call('ZADD', key, now, member)
    redis.call('EXPIRE', key, math.ceil(window * 2))
    return {1, limit - current_count - 1, 0}
else
    -- Fetch the oldest entry to calculate precise retry-after
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local retry_after = 0
    if #oldest > 1 then
        retry_after = math.max(0.001, (tonumber(oldest[2]) + window) - now)
    else
        retry_after = window
    end
    return {0, 0, retry_after}
end
"""


class RedisRateLimiter(BaseRateLimiter):
    """Production distributed sliding-window rate limiter backed by Redis.

    Guarantees:
    - Atomicity: Uses Redis sorted sets via server-side Lua scripts (eliminates read-modify-write race conditions).
    - Namespace Isolation: Keys partition by namespace and tenant ID.
    - Zero Hard Dependency: Works with redis-py or duck-typed mock clients.
    - Failure Resilience: Protected by a CircuitBreaker and configurable FailurePolicy.
    """

    def __init__(
        self,
        redis_client: Optional[Any] = None,
        client: Optional[Any] = None,
        namespace: str = "llmfirewall:ratelimit",
        failure_policy: FailurePolicy = FailurePolicy.FAIL_OPEN,
        circuit_breaker: Optional[CircuitBreaker] = None,
    ) -> None:
        actual_client = redis_client if redis_client is not None else client
        if actual_client is None:
            raise ValueError("A redis_client instance must be provided")
        self.client = actual_client
        self.namespace = namespace
        self.failure_policy = failure_policy
        self.breaker = circuit_breaker or CircuitBreaker(
            name="redis_ratelimiter",
            failure_threshold=3,
            recovery_timeout=15.0,
        )
        self._sha: Optional[str] = None

    def _get_redis_key(self, dimension: str, key: str) -> str:
        # Hash key if it might contain sensitive material (e.g. API keys)
        safe_key = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
        return f"{self.namespace}:{dimension}:{safe_key}"

    def acquire(
        self,
        key: str,
        limit: int,
        window_seconds: float = 60.0,
        dimension: RateLimitDimension = RateLimitDimension.TENANT,
    ) -> RateLimitResult:
        now = time.time()
        redis_key = self._get_redis_key(dimension.value, key)
        fingerprint = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
        member_id = f"{now}:{time.perf_counter_ns()}"

        try:
            # Check circuit breaker
            res = self.breaker(self._eval_lua)(
                redis_key=redis_key,
                now=now,
                window=window_seconds,
                limit=limit,
                member=member_id,
            )
            allowed_flag, remaining, retry_after = res[0], res[1], float(res[2])
            return RateLimitResult(
                allowed=(allowed_flag == 1),
                limit=limit,
                remaining=int(remaining),
                reset_after_seconds=window_seconds,
                retry_after_seconds=retry_after,
                dimension=dimension.value,
                key_fingerprint=fingerprint,
            )
        except Exception as exc:
            logger.warning(
                "Redis rate limiter failure on key '%s' (%s): %s. Applying policy %s",
                fingerprint,
                dimension.value,
                exc,
                self.failure_policy.value,
            )
            return self._handle_failure(limit, window_seconds, dimension.value, fingerprint)

    def _eval_lua(self, redis_key: str, now: float, window: float, limit: int, member: str) -> List[Any]:
        # Handle either redis-py or duck-typed client
        if hasattr(self.client, "eval"):
            return self.client.eval(REDIS_SLIDING_WINDOW_LUA, 1, redis_key, str(now), str(window), str(limit), member)
        raise RuntimeError("Redis client does not support eval()")

    def _handle_failure(self, limit: int, window: float, dimension: str, fingerprint: str) -> RateLimitResult:
        if self.failure_policy == FailurePolicy.FAIL_OPEN:
            return RateLimitResult(
                allowed=True,
                limit=limit,
                remaining=limit,
                reset_after_seconds=window,
                dimension=dimension,
                key_fingerprint=fingerprint,
                failure_policy_applied=FailurePolicy.FAIL_OPEN,
            )
        else:  # FAIL_CLOSED or REJECT_TEMPORARILY
            return RateLimitResult(
                allowed=False,
                limit=limit,
                remaining=0,
                reset_after_seconds=window,
                retry_after_seconds=window / 2,
                dimension=dimension,
                key_fingerprint=fingerprint,
                failure_policy_applied=self.failure_policy,
            )

    def reset(self, key: Optional[str] = None) -> None:
        try:
            if key and hasattr(self.client, "delete"):
                redis_key = self._get_redis_key("tenant", key)
                self.client.delete(redis_key)
        except Exception as exc:
            logger.warning("Failed to reset Redis rate limiter key: %s", exc)


class DistributedRateLimiter:
    """Multi-dimensional rate limiting coordinator enforcing hierarchical quotas."""

    def __init__(
        self,
        backend: Optional[BaseRateLimiter] = None,
        default_rpm: int = 120,
    ) -> None:
        self.backend = backend or InMemoryRateLimiter()
        self.default_rpm = default_rpm
        self._tenant_quotas: Dict[str, int] = {}

    def set_tenant_quota(self, tenant_id: str, rpm: int) -> None:
        self._tenant_quotas[tenant_id] = max(1, rpm)

    def check(
        self,
        tenant_id: Optional[str] = None,
        api_key: Optional[str] = None,
        user_id: Optional[str] = None,
        window_seconds: float = 60.0,
    ) -> RateLimitResult:
        """Check multi-dimensional limits in priority sequence: tenant -> user -> api_key."""
        # 1. Tenant Dimension Check
        if tenant_id:
            quota = self._tenant_quotas.get(tenant_id, self.default_rpm)
            res = self.backend.acquire(
                key=tenant_id,
                limit=quota,
                window_seconds=window_seconds,
                dimension=RateLimitDimension.TENANT,
            )
            if not res.allowed:
                return res

        # 2. User Dimension Check
        if user_id:
            res = self.backend.acquire(
                key=f"{tenant_id or 'anon'}:{user_id}",
                limit=self.default_rpm * 2,
                window_seconds=window_seconds,
                dimension=RateLimitDimension.USER,
            )
            if not res.allowed:
                return res

        # 3. API Key Fingerprint Check
        if api_key:
            # Mask and hash API key
            key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
            res = self.backend.acquire(
                key=key_hash,
                limit=self.default_rpm * 5,
                window_seconds=window_seconds,
                dimension=RateLimitDimension.API_KEY,
            )
            if not res.allowed:
                return res

        return RateLimitResult(
            allowed=True,
            limit=self.default_rpm,
            remaining=self.default_rpm,
            reset_after_seconds=window_seconds,
            dimension=RateLimitDimension.GLOBAL.value,
        )
