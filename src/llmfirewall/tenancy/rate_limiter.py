"""Phase 63 — Tenant-Aware Rate Limiting and Isolation."""

from collections import deque
import threading
import time
from typing import Deque, Dict, Optional


class TenantRateLimiter:
    """Thread-safe, tenant-partitioned rate limiter preventing cross-tenant exhaustion."""

    def __init__(self, default_rpm: int = 120, window_seconds: float = 60.0) -> None:
        self.default_rpm = max(1, default_rpm)
        self.window_seconds = max(1.0, window_seconds)
        self._lock = threading.Lock()
        # tenant_id -> deque of timestamps
        self._history: Dict[str, Deque[float]] = {}
        self._tenant_limits: Dict[str, int] = {}

    def set_tenant_limit(self, tenant_id: str, rpm: int) -> None:
        """Configure explicit requests-per-minute limit for a tenant."""
        with self._lock:
            self._tenant_limits[tenant_id] = max(1, rpm)

    def allow_request(self, tenant_id: str, now: Optional[float] = None) -> bool:
        """Evaluate whether request is permitted under tenant quota; records timestamp if allowed."""
        if not tenant_id:
            tenant_id = "global"

        current_time = now or time.time()
        cutoff = current_time - self.window_seconds

        with self._lock:
            limit = self._tenant_limits.get(tenant_id, self.default_rpm)
            if tenant_id not in self._history:
                self._history[tenant_id] = deque(maxlen=limit * 2)

            q = self._history[tenant_id]
            # Evict timestamps older than sliding window
            while q and q[0] <= cutoff:
                q.popleft()

            if len(q) >= limit:
                return False

            q.append(current_time)
            return True

    def get_current_count(self, tenant_id: str) -> int:
        """Get current active requests in window for tenant."""
        cutoff = time.time() - self.window_seconds
        with self._lock:
            if tenant_id not in self._history:
                return 0
            q = self._history[tenant_id]
            while q and q[0] <= cutoff:
                q.popleft()
            return len(q)
