# Security Knowledge Graph

For comprehensive documentation on the Security Knowledge Graph schema, multi-hop traversals, and blast-radius analysis, see [security-knowledge-graph.md](security-knowledge-graph.md).

---

## Quick Reference

The Security Knowledge Graph unifies AI assets, permissions, attack paths, and controls into a connected graph:

```python
from llmfirewall import Firewall
from llmfirewall.graph import Node, NodeType, Relationship, RelationshipType

fw = Firewall()

# Add Nodes
fw.knowledge_graph.add_node(Node(id="agent:support", type=NodeType.AGENT.value))
fw.knowledge_graph.add_node(Node(id="tool:db_query", type=NodeType.TOOL.value))

# Add Relationship
fw.knowledge_graph.add_relationship(
    Relationship(
        source="agent:support",
        target="tool:db_query",
        type=RelationshipType.CALLS.value,
    )
)

# Traverse Blast Radius
impact = fw.knowledge_graph.get_blast_radius("agent:support")
print(f"Impacted assets: {impact}")
```

CLI commands:
```bash
llmfirewall graph nodes
llmfirewall graph path --source agent:support --target tool:db_query
llmfirewall graph impact agent:support
```
