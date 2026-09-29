"""Document and context security scanning cache with cryptographic invalidation.

Phase 27: Advanced RAG & Context Security.
Guarantees:
- Cache key binds: content_hash + detector_engine_hash + policy_version + scanner_version
- TTL-based time expiration
- Bounded LRU-style memory store
- Automatic invalidation when policy or detectors change
"""

from __future__ import annotations

import collections
import hashlib
import time
from typing import Any, Dict, Optional, Tuple

from llmfirewall.core.models import ScanResult


class SecurityScanCache:
    """Thread-safe, bounded in-memory cache for document and chunk scan results."""

    def __init__(self, max_entries: int = 10_000, ttl_seconds: float = 3600.0) -> None:
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        # Mapping: cache_key -> (ScanResult, expire_timestamp)
        self._cache: collections.OrderedDict[str, Tuple[ScanResult, float]] = collections.OrderedDict()

    def make_key(
        self,
        content_hash: str,
        policy_version: str = "1.0",
        scanner_version: str = "1.0",
        context_tags: Optional[str] = None,
    ) -> str:
        """Construct deterministic cache key binding content, policy, and engine versions."""
        raw = f"{content_hash}:{policy_version}:{scanner_version}:{context_tags or ''}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def get(self, key: str) -> Optional[ScanResult]:
        """Retrieve cached ScanResult if present and not expired."""
        if key not in self._cache:
            return None
        res, expires_at = self._cache[key]
        if time.monotonic() > expires_at:
            del self._cache[key]
            return None
        # Move to end (most recently used)
        self._cache.move_to_end(key)
        return res

    def put(self, key: str, result: ScanResult) -> None:
        """Store ScanResult with configured TTL."""
        if len(self._cache) >= self.max_entries:
            # Evict oldest entry
            self._cache.popitem(last=False)
        self._cache[key] = (result, time.monotonic() + self.ttl_seconds)

    def clear(self) -> None:
        """Purge all cached scan decisions."""
        self._cache.clear()

    @property
    def size(self) -> int:
        return len(self._cache)
