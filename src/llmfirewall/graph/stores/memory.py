"""Thread-safe, in-memory graph storage implementation for AI Security Knowledge Graph."""

from collections import defaultdict
import threading
import time
from typing import Any, Dict, List, Optional, Set

from llmfirewall.graph.models import Node, Relationship
from llmfirewall.graph.stores.base import GraphStore


class InMemoryGraphStore(GraphStore):
    """High-performance, in-process, thread-safe memory store for graph nodes and directed relationships."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._nodes: Dict[str, Node] = {}
        self._type_index: Dict[str, Set[str]] = defaultdict(set)

        # Adjacency indexes: node_id -> {edge_key: Relationship}
        self._out_edges: Dict[str, Dict[str, Relationship]] = defaultdict(dict)
        self._in_edges: Dict[str, Dict[str, Relationship]] = defaultdict(dict)
        self._edges: Dict[str, Relationship] = {}

    def add_node(self, node: Node) -> Node:
        with self._lock:
            if node.id in self._nodes:
                existing = self._nodes[node.id]
                # If properties or type changed, update
                if existing.properties != node.properties or existing.type != node.type:
                    self._type_index[existing.type].discard(node.id)
                    updated = Node(
                        id=node.id,
                        type=node.type,
                        properties={**existing.properties, **node.properties},
                        created_at=existing.created_at,
                        updated_at=time.time(),
                    )
                    self._nodes[node.id] = updated
                    self._type_index[node.type].add(node.id)
                    return updated
                return existing

            self._nodes[node.id] = node
            self._type_index[node.type].add(node.id)
            return node

    def get_node(self, node_id: str) -> Optional[Node]:
        with self._lock:
            return self._nodes.get(node_id)

    def remove_node(self, node_id: str, cascade: bool = True) -> bool:
        with self._lock:
            if node_id not in self._nodes:
                return False

            node = self._nodes.pop(node_id)
            self._type_index[node.type].discard(node_id)

            if cascade:
                # Remove all outgoing edges
                out_edges = list(self._out_edges.get(node_id, {}).values())
                for edge in out_edges:
                    self.remove_relationship(edge.source, edge.type, edge.target)

                # Remove all incoming edges
                in_edges = list(self._in_edges.get(node_id, {}).values())
                for edge in in_edges:
                    self.remove_relationship(edge.source, edge.type, edge.target)

            self._out_edges.pop(node_id, None)
            self._in_edges.pop(node_id, None)
            return True

    def get_all_nodes(self, node_type: Optional[str] = None) -> List[Node]:
        with self._lock:
            if node_type is not None:
                norm_type = node_type.strip().lower()
                ids = self._type_index.get(norm_type, set())
                return [self._nodes[nid] for nid in ids if nid in self._nodes]
            return list(self._nodes.values())

    def node_count(self) -> int:
        with self._lock:
            return len(self._nodes)

    def add_relationship(self, relationship: Relationship) -> Relationship:
        with self._lock:
            if relationship.source not in self._nodes:
                raise ValueError(f"Source node '{relationship.source}' does not exist in graph.")
            if relationship.target not in self._nodes:
                raise ValueError(f"Target node '{relationship.target}' does not exist in graph.")

            key = relationship.edge_key
            if key in self._edges:
                existing = self._edges[key]
                if existing.properties != relationship.properties:
                    updated = Relationship(
                        source=relationship.source,
                        type=relationship.type,
                        target=relationship.target,
                        properties={**existing.properties, **relationship.properties},
                        created_at=existing.created_at,
                    )
                    self._edges[key] = updated
                    self._out_edges[relationship.source][key] = updated
                    self._in_edges[relationship.target][key] = updated
                    return updated
                return existing

            self._edges[key] = relationship
            self._out_edges[relationship.source][key] = relationship
            self._in_edges[relationship.target][key] = relationship
            return relationship

    def get_relationship(self, source: str, type: str, target: str) -> Optional[Relationship]:
        with self._lock:
            key = f"{source}|{type.strip().upper()}|{target}"
            return self._edges.get(key)

    def remove_relationship(self, source: str, type: str, target: str) -> bool:
        with self._lock:
            key = f"{source}|{type.strip().upper()}|{target}"
            if key not in self._edges:
                return False

            self._edges.pop(key, None)
            if source in self._out_edges:
                self._out_edges[source].pop(key, None)
            if target in self._in_edges:
                self._in_edges[target].pop(key, None)
            return True

    def get_all_relationships(self, rel_type: Optional[str] = None) -> List[Relationship]:
        with self._lock:
            if rel_type is not None:
                norm_type = rel_type.strip().upper()
                return [r for r in self._edges.values() if r.type == norm_type]
            return list(self._edges.values())

    def relationship_count(self) -> int:
        with self._lock:
            return len(self._edges)

    def get_out_edges(self, node_id: str, rel_type: Optional[str] = None) -> List[Relationship]:
        with self._lock:
            edges = list(self._out_edges.get(node_id, {}).values())
            if rel_type is not None:
                norm_type = rel_type.strip().upper()
                return [e for e in edges if e.type == norm_type]
            return edges

    def get_in_edges(self, node_id: str, rel_type: Optional[str] = None) -> List[Relationship]:
        with self._lock:
            edges = list(self._in_edges.get(node_id, {}).values())
            if rel_type is not None:
                norm_type = rel_type.strip().upper()
                return [e for e in edges if e.type == norm_type]
            return edges

    def get_neighbors(
        self,
        node_id: str,
        direction: str = "both",
        rel_type: Optional[str] = None,
    ) -> List[Node]:
        with self._lock:
            neighbor_ids: Set[str] = set()

            if direction in ("out", "outgoing", "both"):
                for edge in self.get_out_edges(node_id, rel_type=rel_type):
                    neighbor_ids.add(edge.target)

            if direction in ("in", "incoming", "both"):
                for edge in self.get_in_edges(node_id, rel_type=rel_type):
                    neighbor_ids.add(edge.source)

            # Exclude self if self-referential
            neighbor_ids.discard(node_id)
            return [self._nodes[nid] for nid in neighbor_ids if nid in self._nodes]

    def clear(self) -> None:
        with self._lock:
            self._nodes.clear()
            self._type_index.clear()
            self._out_edges.clear()
            self._in_edges.clear()
            self._edges.clear()
