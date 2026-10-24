"""In-memory persistence adapter for testing, development, and zero-infra runtime."""

from collections import OrderedDict
import threading
from typing import List, Optional

from llmfirewall.persistence.base import BasePersistenceAdapter
from llmfirewall.persistence.models import PersistenceRecord, StorageFilter


class InMemoryPersistenceAdapter(BasePersistenceAdapter):
    """Thread-safe bounded in-memory persistence adapter."""

    def __init__(self, max_records: int = 10000) -> None:
        self._max_records = max(1, max_records)
        self._lock = threading.Lock()
        self._storage: OrderedDict[str, PersistenceRecord] = OrderedDict()

    def save(self, record: PersistenceRecord) -> str:
        with self._lock:
            if len(self._storage) >= self._max_records:
                self._storage.popitem(last=False)  # Evict oldest FIFO
            self._storage[record.id] = record
            return record.id

    def get(self, record_id: str) -> Optional[PersistenceRecord]:
        with self._lock:
            return self._storage.get(record_id)

    def query(self, filter_params: Optional[StorageFilter] = None) -> List[PersistenceRecord]:
        filt = filter_params or StorageFilter()
        results: List[PersistenceRecord] = []

        with self._lock:
            candidates = list(self._storage.values())

        for r in reversed(candidates):  # newest first
            if filt.tenant_id is not None and r.tenant_id != filt.tenant_id:
                continue
            if filt.record_type is not None and r.record_type != filt.record_type:
                continue
            if filt.start_time is not None and r.timestamp < filt.start_time:
                continue
            if filt.end_time is not None and r.timestamp > filt.end_time:
                continue
            results.append(r)

        # Pagination
        start = filt.offset
        end = start + filt.limit
        return results[start:end]

    def count(self, tenant_id: Optional[str] = None) -> int:
        with self._lock:
            if tenant_id is None:
                return len(self._storage)
            return sum(1 for r in self._storage.values() if r.tenant_id == tenant_id)

    def clear(self) -> None:
        with self._lock:
            self._storage.clear()
