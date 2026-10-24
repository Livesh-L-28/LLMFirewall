"""Base abstraction for security data persistence adapters."""

from abc import ABC, abstractmethod
from typing import List, Optional

from llmfirewall.persistence.models import PersistenceRecord, StorageFilter


class BasePersistenceAdapter(ABC):
    """Abstract contract for security record persistence adapters.
    
    Implementations must maintain:
    - Tamper-evident checksum validation.
    - Tenant isolation: queries with tenant_id must strictly filter by tenant.
    - Safe error handling: persistence failures must not crash inline scanning by default.
    """

    @abstractmethod
    def save(self, record: PersistenceRecord) -> str:
        """Persist a single record and return its ID."""
        pass

    def save_batch(self, records: List[PersistenceRecord]) -> List[str]:
        """Persist a batch of records. Default implementation calls save iteratively."""
        return [self.save(r) for r in records]

    @abstractmethod
    def get(self, record_id: str) -> Optional[PersistenceRecord]:
        """Retrieve a record by unique ID."""
        pass

    @abstractmethod
    def query(self, filter_params: Optional[StorageFilter] = None) -> List[PersistenceRecord]:
        """Query records matching filter criteria."""
        pass

    @abstractmethod
    def count(self, tenant_id: Optional[str] = None) -> int:
        """Count total stored records, optionally partitioned by tenant."""
        pass

    def close(self) -> None:
        """Release underlying resources (connections, file descriptors, etc.)."""
        pass
