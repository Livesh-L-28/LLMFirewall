"""Abstract base class interface for security knowledge graph storage backends."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set

from llmfirewall.graph.models import Node, Relationship


class GraphStore(ABC):
    """Abstract interface defining required storage operations for knowledge graph nodes and edges."""

    @abstractmethod
    def add_node(self, node: Node) -> Node:
        """Add or update a node in the graph store."""
        pass

    @abstractmethod
    def get_node(self, node_id: str) -> Optional[Node]:
        """Retrieve a node by its unique identifier."""
        pass

    @abstractmethod
    def remove_node(self, node_id: str, cascade: bool = True) -> bool:
        """Remove a node and optionally clean up connected relationships."""
        pass

    @abstractmethod
    def get_all_nodes(self, node_type: Optional[str] = None) -> List[Node]:
        """Retrieve all nodes, optionally filtered by node type."""
        pass

    @abstractmethod
    def node_count(self) -> int:
        """Total number of nodes currently stored."""
        pass

    @abstractmethod
    def add_relationship(self, relationship: Relationship) -> Relationship:
        """Add a directed relationship between two existing nodes."""
        pass

    @abstractmethod
    def get_relationship(self, source: str, type: str, target: str) -> Optional[Relationship]:
        """Retrieve a specific relationship between two nodes."""
        pass

    @abstractmethod
    def remove_relationship(self, source: str, type: str, target: str) -> bool:
        """Remove a specific relationship between two nodes."""
        pass

    @abstractmethod
    def get_all_relationships(self, rel_type: Optional[str] = None) -> List[Relationship]:
        """Retrieve all relationships, optionally filtered by type."""
        pass

    @abstractmethod
    def relationship_count(self) -> int:
        """Total number of relationships currently stored."""
        pass

    @abstractmethod
    def get_out_edges(self, node_id: str, rel_type: Optional[str] = None) -> List[Relationship]:
        """Retrieve outgoing directed edges from node_id."""
        pass

    @abstractmethod
    def get_in_edges(self, node_id: str, rel_type: Optional[str] = None) -> List[Relationship]:
        """Retrieve incoming directed edges to node_id."""
        pass

    @abstractmethod
    def get_neighbors(
        self,
        node_id: str,
        direction: str = "both",
        rel_type: Optional[str] = None,
    ) -> List[Node]:
        """Retrieve adjacent neighbor nodes in the specified direction ('out', 'in', 'both')."""
        pass

    @abstractmethod
    def clear(self) -> None:
        """Purge all nodes and relationships from the store."""
        pass
