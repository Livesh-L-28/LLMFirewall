"""Distributed cache adapter and multi-tier caching abstractions for LLMFirewall."""

import json
import logging
from typing import Any, Dict, Optional, Protocol, runtime_checkable

from llmfirewall.cache.scan_cache import ScanCache, ScanCacheMetrics
from llmfirewall.core.models import ScanResult

logger = logging.getLogger("llmfirewall.cache.distributed")


@runtime_checkable
class DistributedCacheClient(Protocol):
    """Protocol for external distributed cache backends (e.g. Redis, KeyDB, Memcached)."""

    def get(self, key: str) -> Optional[str]:
        ...

    def set(self, key: str, value: str, ex: Optional[int] = None) -> None:
        ...

    def delete(self, key: str) -> None:
        ...

    def flushdb(self) -> None:
        ...


class DistributedCacheAdapter(ScanCache):
    """Two-tier distributed cache adapter supporting L1 (local memory) + L2 (remote distributed store).
    
    Guarantees:
    - Partition isolation: keys bind tenant_id, security context, and policy version.
    - Zero external dependency requirement: works with any object fulfilling DistributedCacheClient.
    - Safe failover: network or remote deserialization errors fail-open to cache miss without crashing scans.
    """

    def __init__(
        self,
        client: DistributedCacheClient,
        max_size: int = 1000,
        ttl_seconds: float = 1800.0,
        enable_l1_cache: bool = True,
    ) -> None:
        super().__init__(max_size=max_size, ttl_seconds=ttl_seconds)
        self._client = client
        self._enable_l1 = enable_l1_cache
        self._l2_hits = 0
        self._l2_misses = 0

    @property
    def l2_hits(self) -> int:
        return self._l2_hits

    @property
    def l2_misses(self) -> int:
        return self._l2_misses

    def get(self, key: str) -> Optional[ScanResult]:
        """Lookup in L1 local memory first, then fall back to L2 distributed cache."""
        # 1. Check L1 local cache
        if self._enable_l1:
            l1_hit = super().get(key)
            if l1_hit is not None:
                return l1_hit

        # 2. Check L2 distributed cache
        try:
            raw_data = self._client.get(key)
            if raw_data:
                parsed = json.loads(raw_data)
                result = ScanResult.model_validate(parsed)
                self._l2_hits += 1
                self._hits += 1
                # Populate L1 for subsequent reads
                if self._enable_l1:
                    super().put(key, result)
                return result
        except Exception as exc:
            logger.warning("Distributed cache read failure on key '%s': %s", key, exc)

        self._l2_misses += 1
        self._misses += 1
        return None

    def put(self, key: str, result: ScanResult) -> None:
        """Store in L1 local memory and persist to L2 distributed store."""
        if self._enable_l1:
            super().put(key, result)

        try:
            serialized = result.model_dump_json()
            ttl_int = int(self.ttl_seconds) if self.ttl_seconds > 0 else None
            self._client.set(key, serialized, ex=ttl_int)
        except Exception as exc:
            logger.warning("Distributed cache write failure on key '%s': %s", key, exc)

    def invalidate(self, prefix: Optional[str] = None) -> int:
        """Invalidate L1 and clear remote keys."""
        count = super().invalidate(prefix=prefix)
        try:
            if hasattr(self._client, "flushdb"):
                self._client.flushdb()
        except Exception as exc:
            logger.warning("Distributed cache flush failure: %s", exc)
        return count

    def clear(self) -> None:
        """Reset both L1 and L2 caches."""
        super().clear()
        try:
            if hasattr(self._client, "flushdb"):
                self._client.flushdb()
        except Exception as exc:
            logger.warning("Distributed cache clear failure: %s", exc)
