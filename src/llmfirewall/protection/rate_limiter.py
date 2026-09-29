"""Sliding window in-memory rate limiter for Phase 39: AI Security Runtime Protection."""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import hashlib
import threading
import time
from typing import Dict, Optional, Tuple


class RateLimiter:
    """Thread-safe sliding window rate limiter.
    
    Hashes sensitive identifiers (e.g. IPs, user IDs) to prevent storing unnecessary personal data.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # Key: (hashed_identifier, window_seconds) -> deque of timestamps
        self._windows: Dict[Tuple[str, int], deque[float]] = {}

    def _hash_key(self, key_type: str, raw_val: str) -> str:
        """Hashes raw user or IP identifiers for privacy preservation."""
        if key_type in ("ip", "user", "api_key"):
            return f"{key_type}:{hashlib.sha256(raw_val.encode('utf-8')).hexdigest()[:16]}"
        return f"{key_type}:{raw_val}"

    def check_rate_limit(
        self,
        key_type: str,
        key_val: str,
        max_requests: int,
        window_seconds: int,
    ) -> Tuple[bool, int, float]:
        """Evaluates whether the request is within rate limits.
        
        Returns:
            (is_allowed: bool, current_count: int, retry_after_seconds: float)
        """
        now = time.time()
        safe_key = self._hash_key(key_type, key_val)
        dict_key = (safe_key, window_seconds)

        with self._lock:
            q = self._windows.setdefault(dict_key, deque())

            # Prune timestamps older than window
            cutoff = now - window_seconds
            while q and q[0] < cutoff:
                q.popleft()

            if len(q) >= max_requests:
                # Exceeded
                earliest = q[0]
                retry_after = max(0.0, (earliest + window_seconds) - now)
                return False, len(q), retry_after

            # Allowed, record timestamp
            q.append(now)
            return True, len(q), 0.0

    def reset(self) -> None:
        """Clears all active rate limit state."""
        with self._lock:
            self._windows.clear()
