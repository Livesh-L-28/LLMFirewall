"""SQLite persistence adapter using Python standard library sqlite3."""

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import threading
from typing import List, Optional

from llmfirewall.persistence.base import BasePersistenceAdapter
from llmfirewall.persistence.models import PersistenceRecord, StorageFilter


class SQLitePersistenceAdapter(BasePersistenceAdapter):
    """Embedded SQLite persistence adapter with zero external dependencies."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self._db_path = db_path
        self._lock = threading.Lock()

        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(
            self._db_path,
            check_same_thread=False,
            isolation_level=None,  # autocommit
        )
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS security_records (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT,
                    record_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    checksum TEXT NOT NULL
                )
                """
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_records_tenant ON security_records(tenant_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_records_type ON security_records(record_type)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_records_ts ON security_records(timestamp)")

    def save(self, record: PersistenceRecord) -> str:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                INSERT OR REPLACE INTO security_records (id, tenant_id, record_type, timestamp, payload, checksum)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    record.id,
                    record.tenant_id,
                    record.record_type,
                    record.timestamp.isoformat(),
                    json.dumps(record.payload),
                    record.checksum,
                ),
            )
            return record.id

    def get(self, record_id: str) -> Optional[PersistenceRecord]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT id, tenant_id, record_type, timestamp, payload, checksum FROM security_records WHERE id = ?",
                (record_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return PersistenceRecord(
                id=row[0],
                tenant_id=row[1],
                record_type=row[2],
                timestamp=datetime.fromisoformat(row[3]),
                payload=json.loads(row[4]),
                checksum=row[5],
            )

    def query(self, filter_params: Optional[StorageFilter] = None) -> List[PersistenceRecord]:
        filt = filter_params or StorageFilter()
        clauses = []
        params = []

        if filt.tenant_id is not None:
            clauses.append("tenant_id = ?")
            params.append(filt.tenant_id)
        if filt.record_type is not None:
            clauses.append("record_type = ?")
            params.append(filt.record_type)
        if filt.start_time is not None:
            clauses.append("timestamp >= ?")
            params.append(filt.start_time.isoformat())
        if filt.end_time is not None:
            clauses.append("timestamp <= ?")
            params.append(filt.end_time.isoformat())

        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        query_sql = f"""
            SELECT id, tenant_id, record_type, timestamp, payload, checksum
            FROM security_records
            {where_sql}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """
        params.extend([filt.limit, filt.offset])

        results: List[PersistenceRecord] = []
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(query_sql, params)
            for row in cur.fetchall():
                results.append(
                    PersistenceRecord(
                        id=row[0],
                        tenant_id=row[1],
                        record_type=row[2],
                        timestamp=datetime.fromisoformat(row[3]),
                        payload=json.loads(row[4]),
                        checksum=row[5],
                    )
                )
        return results

    def count(self, tenant_id: Optional[str] = None) -> int:
        with self._lock:
            cur = self._conn.cursor()
            if tenant_id is not None:
                cur.execute("SELECT COUNT(*) FROM security_records WHERE tenant_id = ?", (tenant_id,))
            else:
                cur.execute("SELECT COUNT(*) FROM security_records")
            row = cur.fetchone()
            return int(row[0]) if row else 0

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass
