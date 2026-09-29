"""Pluggable, lightweight storage backends for SecurityEvents.

Backends:
- InMemoryEventStore (default, zero dependencies, bounded buffer)
- JSONLEventStore (append-only file storage, human-readable, rotation friendly)
- SQLiteEventStore (indexed local database, structured query & aggregation)

Features:
- Thread-safe writes
- Query filtering (by time, action, risk, detector, tool, severity)
- Retention cleanup
- Export friendly
"""

from __future__ import annotations

import abc
import json
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from llmfirewall.core.models import Action, Severity
from llmfirewall.observability.models import EventSeverity, SecurityEvent, SecurityEventType


class EventFilter:
    """Filter criteria for querying stored security events."""

    def __init__(
        self,
        event_types: Optional[List[SecurityEventType]] = None,
        actions: Optional[List[Action]] = None,
        severities: Optional[List[EventSeverity]] = None,
        detector_name: Optional[str] = None,
        tool_name: Optional[str] = None,
        policy_id: Optional[str] = None,
        min_risk_score: Optional[float] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> None:
        self.event_types = event_types
        self.actions = actions
        self.severities = severities
        self.detector_name = detector_name
        self.tool_name = tool_name
        self.policy_id = policy_id
        self.min_risk_score = min_risk_score
        self.since = since
        self.until = until
        self.limit = limit
        self.offset = offset

    def matches(self, event: SecurityEvent) -> bool:
        """Check if an in-memory event matches this filter."""
        if self.event_types and event.event_type not in self.event_types:
            return False
        if self.actions and event.action not in self.actions:
            return False
        if self.severities and event.severity not in self.severities:
            return False
        if self.detector_name and event.detector_name != self.detector_name:
            return False
        if self.tool_name and event.tool_name != self.tool_name:
            return False
        if self.policy_id and event.policy_id != self.policy_id:
            return False
        if self.min_risk_score is not None:
            if event.risk_score is None or event.risk_score < self.min_risk_score:
                return False
        if self.since is not None and event.timestamp < self.since:
            return False
        if self.until is not None and event.timestamp > self.until:
            return False
        return True


class EventStore(abc.ABC):
    """Abstract interface for storing and querying SecurityEvents."""

    @abc.abstractmethod
    def write(self, event: SecurityEvent) -> None:
        """Persist a single security event."""
        pass

    @abc.abstractmethod
    def query(self, filter_criteria: Optional[EventFilter] = None) -> List[SecurityEvent]:
        """Query security events matching criteria."""
        pass

    @abc.abstractmethod
    def count(self, filter_criteria: Optional[EventFilter] = None) -> int:
        """Count events matching criteria."""
        pass

    @abc.abstractmethod
    def cleanup(self, retention_days: int) -> int:
        """Prune events older than retention_days. Returns count of deleted records."""
        pass

    @abc.abstractmethod
    def clear(self) -> None:
        """Clear all events (for testing or reset)."""
        pass


class InMemoryEventStore(EventStore):
    """Thread-safe, in-memory bounded event store."""

    def __init__(self, max_events: int = 10000) -> None:
        self._max_events = max_events
        self._events: List[SecurityEvent] = []
        self._lock = threading.Lock()

    def write(self, event: SecurityEvent) -> None:
        with self._lock:
            if len(self._events) >= self._max_events:
                # Evict oldest event to prevent unbounded memory growth
                self._events.pop(0)
            self._events.append(event)

    def query(self, filter_criteria: Optional[EventFilter] = None) -> List[SecurityEvent]:
        with self._lock:
            events = list(self._events)

        if filter_criteria is None:
            return events[-100:]

        filtered = [e for e in events if filter_criteria.matches(e)]
        # Sort descending by timestamp
        filtered.sort(key=lambda e: e.timestamp, reverse=True)
        start = filter_criteria.offset
        end = start + filter_criteria.limit
        return filtered[start:end]

    def count(self, filter_criteria: Optional[EventFilter] = None) -> int:
        if filter_criteria is None:
            with self._lock:
                return len(self._events)
        with self._lock:
            return sum(1 for e in self._events if filter_criteria.matches(e))

    def cleanup(self, retention_days: int) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        with self._lock:
            initial = len(self._events)
            self._events = [e for e in self._events if e.timestamp >= cutoff]
            return initial - len(self._events)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


class JSONLEventStore(EventStore):
    """Append-only JSON Lines event store."""

    def __init__(self, file_path: str) -> None:
        self._file_path = Path(file_path)
        self._file_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, event: SecurityEvent) -> None:
        data = event.model_dump(mode="json")
        line = json.dumps(data) + "\n"
        with self._lock:
            with open(self._file_path, "a", encoding="utf-8") as f:
                f.write(line)

    def _read_all(self) -> List[SecurityEvent]:
        if not self._file_path.exists():
            return []
        events: List[SecurityEvent] = []
        with open(self._file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    events.append(SecurityEvent.model_validate(data))
                except Exception:
                    continue
        return events

    def query(self, filter_criteria: Optional[EventFilter] = None) -> List[SecurityEvent]:
        with self._lock:
            events = self._read_all()

        if filter_criteria is None:
            return events[-100:]

        filtered = [e for e in events if filter_criteria.matches(e)]
        filtered.sort(key=lambda e: e.timestamp, reverse=True)
        start = filter_criteria.offset
        end = start + filter_criteria.limit
        return filtered[start:end]

    def count(self, filter_criteria: Optional[EventFilter] = None) -> int:
        with self._lock:
            events = self._read_all()
        if filter_criteria is None:
            return len(events)
        return sum(1 for e in events if filter_criteria.matches(e))

    def cleanup(self, retention_days: int) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        with self._lock:
            events = self._read_all()
            retained = [e for e in events if e.timestamp >= cutoff]
            deleted = len(events) - len(retained)
            if deleted > 0:
                with open(self._file_path, "w", encoding="utf-8") as f:
                    for ev in retained:
                        f.write(json.dumps(ev.model_dump(mode="json")) + "\n")
            return deleted

    def clear(self) -> None:
        with self._lock:
            if self._file_path.exists():
                self._file_path.write_text("", encoding="utf-8")


class SQLiteEventStore(EventStore):
    """Indexed local SQLite event store for structured querying and aggregation."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self._db_path = db_path
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS security_events (
                            event_id TEXT PRIMARY KEY,
                            schema_version INTEGER,
                            timestamp TEXT NOT NULL,
                            event_type TEXT NOT NULL,
                            severity TEXT NOT NULL,
                            trace_id TEXT NOT NULL,
                            request_id TEXT NOT NULL,
                            component TEXT NOT NULL,
                            action TEXT,
                            risk_level TEXT,
                            risk_score REAL,
                            threat_types TEXT,
                            detector_name TEXT,
                            policy_id TEXT,
                            policy_version TEXT,
                            tool_name TEXT,
                            duration_ms REAL,
                            payload_hash TEXT,
                            payload_length INTEGER,
                            application_id TEXT,
                            environment TEXT,
                            metadata_json TEXT
                        )
                    """)
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp)")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON security_events(event_type)")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_action ON security_events(action)")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity)")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_detector ON security_events(detector_name)")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_tool ON security_events(tool_name)")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_trace ON security_events(trace_id)")
            finally:
                conn.close()

    def write(self, event: SecurityEvent) -> None:
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO security_events (
                            event_id, schema_version, timestamp, event_type, severity,
                            trace_id, request_id, component, action, risk_level,
                            risk_score, threat_types, detector_name, policy_id, policy_version,
                            tool_name, duration_ms, payload_hash, payload_length,
                            application_id, environment, metadata_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            event.event_id,
                            event.schema_version,
                            event.timestamp.isoformat(),
                            event.event_type.value,
                            event.severity.value,
                            event.trace_id,
                            event.request_id,
                            event.component,
                            event.action.value if event.action else None,
                            event.risk_level.value if event.risk_level else None,
                            event.risk_score,
                            json.dumps(event.threat_types),
                            event.detector_name,
                            event.policy_id,
                            event.policy_version,
                            event.tool_name,
                            event.duration_ms,
                            event.payload_hash,
                            event.payload_length,
                            event.application_id,
                            event.environment,
                            json.dumps(event.metadata),
                        ),
                    )
            finally:
                conn.close()

    def _row_to_event(self, row: sqlite3.Row) -> SecurityEvent:
        threat_types = json.loads(row["threat_types"]) if row["threat_types"] else []
        metadata = json.loads(row["metadata_json"]) if row["metadata_json"] else {}
        ts = datetime.fromisoformat(row["timestamp"])
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        return SecurityEvent(
            schema_version=row["schema_version"],
            event_id=row["event_id"],
            timestamp=ts,
            event_type=SecurityEventType(row["event_type"]),
            severity=EventSeverity(row["severity"]),
            trace_id=row["trace_id"],
            request_id=row["request_id"],
            component=row["component"],
            action=Action(row["action"]) if row["action"] else None,
            risk_level=Severity(row["risk_level"]) if row["risk_level"] else None,
            risk_score=row["risk_score"],
            threat_types=threat_types,
            detector_name=row["detector_name"],
            policy_id=row["policy_id"],
            policy_version=row["policy_version"],
            tool_name=row["tool_name"],
            duration_ms=row["duration_ms"] or 0.0,
            payload_hash=row["payload_hash"],
            payload_length=row["payload_length"] or 0,
            application_id=row["application_id"],
            environment=row["environment"] or "production",
            metadata=metadata,
        )

    def query(self, filter_criteria: Optional[EventFilter] = None) -> List[SecurityEvent]:
        query_sql = "SELECT * FROM security_events"
        params: List[Any] = []
        clauses: List[str] = []

        if filter_criteria:
            if filter_criteria.event_types:
                placeholders = ",".join("?" for _ in filter_criteria.event_types)
                clauses.append(f"event_type IN ({placeholders})")
                params.extend([e.value for e in filter_criteria.event_types])
            if filter_criteria.actions:
                placeholders = ",".join("?" for _ in filter_criteria.actions)
                clauses.append(f"action IN ({placeholders})")
                params.extend([a.value for a in filter_criteria.actions])
            if filter_criteria.severities:
                placeholders = ",".join("?" for _ in filter_criteria.severities)
                clauses.append(f"severity IN ({placeholders})")
                params.extend([s.value for s in filter_criteria.severities])
            if filter_criteria.detector_name:
                clauses.append("detector_name = ?")
                params.append(filter_criteria.detector_name)
            if filter_criteria.tool_name:
                clauses.append("tool_name = ?")
                params.append(filter_criteria.tool_name)
            if filter_criteria.policy_id:
                clauses.append("policy_id = ?")
                params.append(filter_criteria.policy_id)
            if filter_criteria.min_risk_score is not None:
                clauses.append("risk_score >= ?")
                params.append(filter_criteria.min_risk_score)
            if filter_criteria.since:
                clauses.append("timestamp >= ?")
                params.append(filter_criteria.since.isoformat())
            if filter_criteria.until:
                clauses.append("timestamp <= ?")
                params.append(filter_criteria.until.isoformat())

        if clauses:
            query_sql += " WHERE " + " AND ".join(clauses)

        query_sql += " ORDER BY timestamp DESC"

        limit = filter_criteria.limit if filter_criteria else 100
        offset = filter_criteria.offset if filter_criteria else 0
        query_sql += f" LIMIT {limit} OFFSET {offset}"

        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.execute(query_sql, params)
                rows = cursor.fetchall()
                return [self._row_to_event(r) for r in rows]
            finally:
                conn.close()

    def count(self, filter_criteria: Optional[EventFilter] = None) -> int:
        query_sql = "SELECT COUNT(*) FROM security_events"
        params: List[Any] = []
        clauses: List[str] = []

        if filter_criteria:
            if filter_criteria.event_types:
                placeholders = ",".join("?" for _ in filter_criteria.event_types)
                clauses.append(f"event_type IN ({placeholders})")
                params.extend([e.value for e in filter_criteria.event_types])
            if filter_criteria.actions:
                placeholders = ",".join("?" for _ in filter_criteria.actions)
                clauses.append(f"action IN ({placeholders})")
                params.extend([a.value for a in filter_criteria.actions])
            if filter_criteria.since:
                clauses.append("timestamp >= ?")
                params.append(filter_criteria.since.isoformat())
            if filter_criteria.until:
                clauses.append("timestamp <= ?")
                params.append(filter_criteria.until.isoformat())

        if clauses:
            query_sql += " WHERE " + " AND ".join(clauses)

        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.execute(query_sql, params)
                return cursor.fetchone()[0]
            finally:
                conn.close()

    def cleanup(self, retention_days: int) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    cursor = conn.execute("DELETE FROM security_events WHERE timestamp < ?", (cutoff,))
                    return cursor.rowcount
            finally:
                conn.close()

    def clear(self) -> None:
        with self._lock:
            conn = self._get_connection()
            try:
                with conn:
                    conn.execute("DELETE FROM security_events")
            finally:
                conn.close()
