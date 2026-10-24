"""File-based JSON Lines persistence adapter for local storage without external databases."""

import json
from pathlib import Path
import threading
from typing import List, Optional

from llmfirewall.persistence.base import BasePersistenceAdapter
from llmfirewall.persistence.models import PersistenceRecord, StorageFilter


class JSONLPersistenceAdapter(BasePersistenceAdapter):
    """Append-only JSON Lines persistence adapter for lightweight local logging and durability."""

    def __init__(self, file_path: str, auto_flush: bool = True) -> None:
        self._path = Path(file_path)
        self._auto_flush = auto_flush
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.touch()

    def save(self, record: PersistenceRecord) -> str:
        line = record.model_dump_json() + "\n"
        with self._lock:
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(line)
                if self._auto_flush:
                    f.flush()
        return record.id

    def get(self, record_id: str) -> Optional[PersistenceRecord]:
        with self._lock:
            if not self._path.exists():
                return None
            with open(self._path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        if data.get("id") == record_id:
                            return PersistenceRecord.model_validate(data)
                    except Exception:
                        continue
        return None

    def query(self, filter_params: Optional[StorageFilter] = None) -> List[PersistenceRecord]:
        filt = filter_params or StorageFilter()
        matches: List[PersistenceRecord] = []

        with self._lock:
            if not self._path.exists():
                return []
            with open(self._path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        r = PersistenceRecord.model_validate(data)
                        if filt.tenant_id is not None and r.tenant_id != filt.tenant_id:
                            continue
                        if filt.record_type is not None and r.record_type != filt.record_type:
                            continue
                        if filt.start_time is not None and r.timestamp < filt.start_time:
                            continue
                        if filt.end_time is not None and r.timestamp > filt.end_time:
                            continue
                        matches.append(r)
                    except Exception:
                        continue

        # Reverse for newest first, then paginate
        matches.reverse()
        return matches[filt.offset : filt.offset + filt.limit]

    def count(self, tenant_id: Optional[str] = None) -> int:
        c = 0
        with self._lock:
            if not self._path.exists():
                return 0
            with open(self._path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if tenant_id is None:
                        c += 1
                    else:
                        try:
                            data = json.loads(line)
                            if data.get("tenant_id") == tenant_id:
                                c += 1
                        except Exception:
                            continue
        return c
