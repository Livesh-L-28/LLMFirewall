"""Precompiled Regular Expression Cache for LLMFirewall v1.1.0 (Phase 52).

Provides thread-safe, bounded LRU compilation of regex patterns across detectors.
"""

from collections import OrderedDict
import re
import threading
from typing import Pattern


class RegexCache:
    """Thread-safe bounded cache for precompiled regular expressions."""

    def __init__(self, max_size: int = 2048) -> None:
        self.max_size = max_size
        self._lock = threading.RLock()
        self._cache: OrderedDict[tuple[str, int], Pattern] = OrderedDict()

    def get_or_compile(self, pattern: str, flags: int = 0) -> Pattern:
        """Retrieve precompiled regex pattern or compile and cache it."""
        key = (pattern, flags)
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                return self._cache[key]

            compiled = re.compile(pattern, flags)
            if len(self._cache) >= self.max_size:
                self._cache.popitem(last=False)
            self._cache[key] = compiled
            return compiled

    def clear(self) -> None:
        """Clear cached compiled regex patterns."""
        with self._lock:
            self._cache.clear()

    def size(self) -> int:
        """Return number of cached compiled patterns."""
        with self._lock:
            return len(self._cache)


# Global singleton regex cache
global_regex_cache = RegexCache()


def compile_regex(pattern: str, flags: int = 0) -> Pattern:
    """Convenience helper to retrieve or compile regex pattern via global cache."""
    return global_regex_cache.get_or_compile(pattern, flags)
