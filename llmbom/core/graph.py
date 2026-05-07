from .node import LLMBOMNode
from .edge import LLMBOMEdge
from .registry import NodeRegistry


class LLMBOMGraph:

    def __init__(self):
        self.nodes = {}
        self.edges = []
        # keep a set for fast duplicate detection
        self._edge_set = set()
        self.registry = NodeRegistry()

    def _create_node(self, node_type, name, metadata=None):
        # deterministic id using sha256 of type and name
        from hashlib import sha256

        token = f"{node_type}:{name}".encode("utf-8")
        nid = sha256(token).hexdigest()
        # ensure metadata is either None or non-empty
        if metadata:
            node = LLMBOMNode(node_type, name, metadata)
        else:
            node = LLMBOMNode(node_type, name, None)
        node.id = nid
        self.nodes[node.id] = node
        return node.id

    def add_node(self, node_type, name, metadata=None):
        return self.registry.get_or_create(self, node_type, name, metadata)

    def add_edge(self, source_id, target_id, edge_type):
        # validate existence
        if source_id not in self.nodes or target_id not in self.nodes:
            raise ValueError("Cannot create edge with unknown node")
        key = (source_id, target_id, edge_type)
        if key in self._edge_set:
            return
        edge = LLMBOMEdge(source_id, target_id, edge_type)
        self.edges.append(edge)
        self._edge_set.add(key)

    def to_dict(self):
        # sort nodes and edges deterministically
        nodes_list = sorted(
            (node.to_dict() for node in self.nodes.values()),
            key=lambda n: (n["type"], n["name"]),
        )
        edges_list = sorted(
            (edge.to_dict() for edge in self.edges),
            key=lambda e: (e["source"], e["target"], e["type"]),
        )
        return {"nodes": nodes_list, "edges": edges_list}
