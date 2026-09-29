"""Thread-safe SQLite persistent graph store using standard-library sqlite3."""

import json
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Set

from llmfirewall.graph.models import Node, Relationship
from llmfirewall.graph.stores.base import GraphStore


class SQLiteGraphStore(GraphStore):
    """Zero-dependency persistent local graph storage backed by SQLite."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS nodes (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    properties TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS relationships (
                    source TEXT NOT NULL,
                    type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    properties TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (source, type, target),
                    FOREIGN KEY (source) REFERENCES nodes(id) ON DELETE CASCADE,
                    FOREIGN KEY (target) REFERENCES nodes(id) ON DELETE CASCADE
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(type)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_rel_source ON relationships(source)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_rel_target ON relationships(target)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_rel_type ON relationships(type)")
            self._conn.commit()

    def add_node(self, node: Node) -> Node:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT properties, created_at FROM nodes WHERE id = ?", (node.id,))
            row = cur.fetchone()
            if row:
                existing_props = json.loads(row[0])
                created_at = row[1]
                merged_props = {**existing_props, **node.properties}
                updated_at = time.time()
                cur.execute(
                    "UPDATE nodes SET type = ?, properties = ?, updated_at = ? WHERE id = ?",
                    (node.type, json.dumps(merged_props, sort_keys=True), updated_at, node.id),
                )
                self._conn.commit()
                return Node(
                    id=node.id,
                    type=node.type,
                    properties=merged_props,
                    created_at=created_at,
                    updated_at=updated_at,
                )
            else:
                cur.execute(
                    "INSERT INTO nodes (id, type, properties, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                    (node.id, node.type, json.dumps(node.properties, sort_keys=True), node.created_at, node.updated_at),
                )
                self._conn.commit()
                return node

    def get_node(self, node_id: str) -> Optional[Node]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT id, type, properties, created_at, updated_at FROM nodes WHERE id = ?", (node_id,))
            row = cur.fetchone()
            if not row:
                return None
            return Node(
                id=row[0],
                type=row[1],
                properties=json.loads(row[2]),
                created_at=row[3],
                updated_at=row[4],
            )

    def remove_node(self, node_id: str, cascade: bool = True) -> bool:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT id FROM nodes WHERE id = ?", (node_id,))
            if not cur.fetchone():
                return False

            if cascade:
                cur.execute("DELETE FROM relationships WHERE source = ? OR target = ?", (node_id, node_id))
            cur.execute("DELETE FROM nodes WHERE id = ?", (node_id,))
            self._conn.commit()
            return True

    def get_all_nodes(self, node_type: Optional[str] = None) -> List[Node]:
        with self._lock:
            cur = self._conn.cursor()
            if node_type is not None:
                cur.execute(
                    "SELECT id, type, properties, created_at, updated_at FROM nodes WHERE type = ? ORDER BY id",
                    (node_type.strip().lower(),),
                )
            else:
                cur.execute("SELECT id, type, properties, created_at, updated_at FROM nodes ORDER BY id")
            rows = cur.fetchall()
            return [
                Node(
                    id=r[0],
                    type=r[1],
                    properties=json.loads(r[2]),
                    created_at=r[3],
                    updated_at=r[4],
                )
                for r in rows
            ]

    def node_count(self) -> int:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT COUNT(*) FROM nodes")
            return cur.fetchone()[0]

    def add_relationship(self, relationship: Relationship) -> Relationship:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT id FROM nodes WHERE id = ?", (relationship.source,))
            if not cur.fetchone():
                raise ValueError(f"Source node '{relationship.source}' does not exist in graph.")
            cur.execute("SELECT id FROM nodes WHERE id = ?", (relationship.target,))
            if not cur.fetchone():
                raise ValueError(f"Target node '{relationship.target}' does not exist in graph.")

            cur.execute(
                """
                INSERT INTO relationships (source, type, target, properties, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(source, type, target) DO UPDATE SET
                    properties = excluded.properties
                """,
                (
                    relationship.source,
                    relationship.type,
                    relationship.target,
                    json.dumps(relationship.properties, sort_keys=True),
                    relationship.created_at,
                ),
            )
            self._conn.commit()
            return relationship

    def get_relationship(self, source: str, type: str, target: str) -> Optional[Relationship]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "SELECT source, type, target, properties, created_at FROM relationships WHERE source = ? AND type = ? AND target = ?",
                (source, type.strip().upper(), target),
            )
            row = cur.fetchone()
            if not row:
                return None
            return Relationship(
                source=row[0],
                type=row[1],
                target=row[2],
                properties=json.loads(row[3]),
                created_at=row[4],
            )

    def remove_relationship(self, source: str, type: str, target: str) -> bool:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "DELETE FROM relationships WHERE source = ? AND type = ? AND target = ?",
                (source, type.strip().upper(), target),
            )
            deleted = cur.rowcount > 0
            self._conn.commit()
            return deleted

    def get_all_relationships(self, rel_type: Optional[str] = None) -> List[Relationship]:
        with self._lock:
            cur = self._conn.cursor()
            if rel_type is not None:
                cur.execute(
                    "SELECT source, type, target, properties, created_at FROM relationships WHERE type = ? ORDER BY source, target",
                    (rel_type.strip().upper(),),
                )
            else:
                cur.execute("SELECT source, type, target, properties, created_at FROM relationships ORDER BY source, target")
            rows = cur.fetchall()
            return [
                Relationship(
                    source=r[0],
                    type=r[1],
                    target=r[2],
                    properties=json.loads(r[3]),
                    created_at=r[4],
                )
                for r in rows
            ]

    def relationship_count(self) -> int:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT COUNT(*) FROM relationships")
            return cur.fetchone()[0]

    def get_out_edges(self, node_id: str, rel_type: Optional[str] = None) -> List[Relationship]:
        with self._lock:
            cur = self._conn.cursor()
            if rel_type is not None:
                cur.execute(
                    "SELECT source, type, target, properties, created_at FROM relationships WHERE source = ? AND type = ?",
                    (node_id, rel_type.strip().upper()),
                )
            else:
                cur.execute(
                    "SELECT source, type, target, properties, created_at FROM relationships WHERE source = ?",
                    (node_id,),
                )
            rows = cur.fetchall()
            return [
                Relationship(
                    source=r[0],
                    type=r[1],
                    target=r[2],
                    properties=json.loads(r[3]),
                    created_at=r[4],
                )
                for r in rows
            ]

    def get_in_edges(self, node_id: str, rel_type: Optional[str] = None) -> List[Relationship]:
        with self._lock:
            cur = self._conn.cursor()
            if rel_type is not None:
                cur.execute(
                    "SELECT source, type, target, properties, created_at FROM relationships WHERE target = ? AND type = ?",
                    (node_id, rel_type.strip().upper()),
                )
            else:
                cur.execute(
                    "SELECT source, type, target, properties, created_at FROM relationships WHERE target = ?",
                    (node_id,),
                )
            rows = cur.fetchall()
            return [
                Relationship(
                    source=r[0],
                    type=r[1],
                    target=r[2],
                    properties=json.loads(r[3]),
                    created_at=r[4],
                )
                for r in rows
            ]

    def get_neighbors(
        self,
        node_id: str,
        direction: str = "both",
        rel_type: Optional[str] = None,
    ) -> List[Node]:
        with self._lock:
            neighbor_ids: Set[str] = set()

            if direction in ("out", "both"):
                for edge in self.get_out_edges(node_id, rel_type=rel_type):
                    neighbor_ids.add(edge.target)

            if direction in ("in", "both"):
                for edge in self.get_in_edges(node_id, rel_type=rel_type):
                    neighbor_ids.add(edge.source)

            neighbor_ids.discard(node_id)
            nodes: List[Node] = []
            for nid in neighbor_ids:
                node = self.get_node(nid)
                if node:
                    nodes.append(node)
            return nodes

    def clear(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("DELETE FROM relationships")
            cur.execute("DELETE FROM nodes")
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
