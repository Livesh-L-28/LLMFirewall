"""High-Performance Bounded LRU Scan Cache for LLMFirewall v1.1.0 (Phase 52).

Guarantees:
- Cryptographically sound deterministic cache key computation.
- Isolation of ephemeral dynamic context (nonces, request IDs) to prevent cache poisoning.
- Thread-safe bounded LRU eviction with monotonic TTL expiration.
- Detailed cache operational metrics (hits, misses, evictions, expirations, hit ratio).
"""

from collections import OrderedDict
from datetime import datetime, timezone
import hashlib
import json
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.core.models import ScanResult


class ScanCacheMetrics(BaseModel):
    """Operational telemetry metrics for the Scan Cache."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    hits: int = Field(default=0)
    misses: int = Field(default=0)
    evictions: int = Field(default=0)
    expirations: int = Field(default=0)
    size: int = Field(default=0)
    max_size: int = Field(default=5000)
    ttl_seconds: float = Field(default=1800.0)

    @property
    def total_lookups(self) -> int:
        return self.hits + self.misses

    @property
    def hit_ratio(self) -> float:
        if self.total_lookups == 0:
            return 0.0
        return round(self.hits / self.total_lookups, 4)


class ScanCache:
    """Thread-safe, bounded LRU cache for prompt and output scan results."""

    # Ephemeral context keys that must NEVER be bound to cache keys
    EPHEMERAL_CONTEXT_KEYS: Set[str] = {
        "request_id",
        "trace_id",
        "timestamp",
        "turn",
        "nonce",
        "span_id",
        "session_turn",
        "start_time",
        "duration",
        "no_cache",
    }

    def __init__(self, max_size: int = 5000, ttl_seconds: float = 1800.0) -> None:
        self.max_size = max(1, max_size)
        self.ttl_seconds = max(0.1, ttl_seconds)
        self._lock = threading.RLock()
        # Mapping: cache_key -> (ScanResult, expire_monotonic)
        self._store: OrderedDict[str, Tuple[ScanResult, float]] = OrderedDict()
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._expirations = 0

    def compute_key(
        self,
        text: str,
        direction: str = "input",
        policy_checksum: str = "default",
        detector_suite_id: str = "default",
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Compute deterministic SHA-256 cache key binding content, direction, and security state."""
        # Sanitize context by filtering out ephemeral keys
        safe_ctx: Dict[str, Any] = {}
        if context:
            for k, v in sorted(context.items()):
                if k.lower() not in self.EPHEMERAL_CONTEXT_KEYS and isinstance(v, (str, int, float, bool)):
                    safe_ctx[k] = v

        ctx_json = json.dumps(safe_ctx, sort_keys=True, separators=(",", ":"))
        canonical_content = f"{direction}:{policy_checksum}:{detector_suite_id}:{ctx_json}:{text.strip()}"
        return hashlib.sha256(canonical_content.encode("utf-8")).hexdigest()

    def get(self, key: str) -> Optional[ScanResult]:
        """Retrieve cached ScanResult if present and unexpired."""
        with self._lock:
            if key not in self._store:
                self._misses += 1
                return None

            result, expires_at = self._store[key]
            now = time.monotonic()
            if now > expires_at:
                del self._store[key]
                self._expirations += 1
                self._misses += 1
                return None

            # Mark recently accessed (LRU)
            self._store.move_to_end(key)
            self._hits += 1
            return result

    def put(self, key: str, result: ScanResult) -> None:
        """Store ScanResult with configured TTL, evicting oldest if max_size is reached."""
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
            elif len(self._store) >= self.max_size:
                self._store.popitem(last=False)
                self._evictions += 1

            self._store[key] = (result, time.monotonic() + self.ttl_seconds)

    def invalidate(self, prefix: Optional[str] = None) -> int:
        """Invalidate entries matching prefix, or all entries if prefix is None."""
        with self._lock:
            if prefix is None:
                count = len(self._store)
                self._store.clear()
                return count

            keys_to_del = [k for k in self._store.keys() if k.startswith(prefix)]
            for k in keys_to_del:
                del self._store[k]
            return len(keys_to_del)

    def clear(self) -> None:
        """Clear all entries and reset operational metrics."""
        with self._lock:
            self._store.clear()
            self._hits = 0
            self._misses = 0
            self._evictions = 0
            self._expirations = 0

    @property
    def hits(self) -> int:
        return self._hits

    @property
    def misses(self) -> int:
        return self._misses

    @property
    def size(self) -> int:
        return len(self._store)

    def get_metrics(self) -> ScanCacheMetrics:
        """Return operational cache telemetry metrics."""
        with self._lock:
            return ScanCacheMetrics(
                hits=self._hits,
                misses=self._misses,
                evictions=self._evictions,
                expirations=self._expirations,
                size=len(self._store),
                max_size=self.max_size,
                ttl_seconds=self.ttl_seconds,
            )
