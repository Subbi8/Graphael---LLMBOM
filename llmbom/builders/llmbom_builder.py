from llmbom.core.graph import LLMBOMGraph
from llmbom.core.schema import NodeType, EdgeType
from llmbom.core.lineage import LineageEngine


class LLMBOMBuilder:
    """Graph-oriented builder used by extractors to record nodes and edges.

    Provides convenient methods corresponding to the defined node/edge types
    in ``schema.py``.  It delegates actual storage to ``LLMBOMGraph`` and
    uses ``LineageEngine`` for relationships like fine-tuning/quantization.
    Also tracks file paths for metadata enrichment.
    """

    def __init__(self, project_root=None):
        self.graph = LLMBOMGraph()
        self.lineage = LineageEngine(self.graph)
        self.script_file_map = {}  # script_node_id -> original file_path
        self.project_root = project_root
        self.unresolved_model_refs = 0
        self.unresolved_dataset_refs = 0

    # ---- node creation helpers ------------------------------------------
    def add_model(self, name, metadata=None):
        # represent models as CONFIG artifacts (structural only)
        meta = {} if metadata is None else dict(metadata)
        meta.setdefault("artifact_type", "model")
        return self.graph.add_node(NodeType.CONFIG, name, meta)

    def add_dataset(self, name, metadata=None):
        # represent datasets as CONFIG artifacts (structural only)
        meta = {} if metadata is None else dict(metadata)
        meta.setdefault("artifact_type", "dataset")
        return self.graph.add_node(NodeType.CONFIG, name, meta)

    def add_framework(self, name, metadata=None):
        # previously a semantic label; collapse to LIBRARY
        return self.graph.add_node(NodeType.LIBRARY, name, metadata)

    def add_library(self, name, metadata=None):
        return self.graph.add_node(NodeType.LIBRARY, name, metadata)

    def add_script(self, name, metadata=None):
        # Accept either a file path or already-normalized name. Normalize
        # paths relative to project_root when available so SCRIPT node names
        # are deterministic and portable.
        from llmbom.utils.file_utils import normalize_path
        node_name = name
        if self.project_root and isinstance(name, str):
            try:
                node_name = normalize_path(name, self.project_root)
            except Exception:
                node_name = name
        nid = self.graph.add_node(NodeType.SCRIPT, node_name, metadata)
        # record mapping to original file path for later enrichment
        self.script_file_map[nid] = name
        return nid

    def add_config(self, name, metadata=None):
        return self.graph.add_node(NodeType.CONFIG, name, metadata)

    # ---- edge helpers -----------------------------------------------------
    # ---- edge helpers (structural only) --------------------------------
    def link_depends_on(self, source_id, lib_id):
        self.graph.add_edge(source_id, lib_id, EdgeType.DEPENDS_ON)

    def link_configures(self, source_id, config_id):
        self.graph.add_edge(source_id, config_id, EdgeType.CONFIGURES)

    def link_saves(self, source_id, target_id):
        self.graph.add_edge(source_id, target_id, EdgeType.SAVES)

    def link_loads(self, source_id, target_id):
        self.graph.add_edge(source_id, target_id, EdgeType.LOADS)

    def link_contains(self, parent_id, child_id):
        """Create a CONTAINS edge (parent→child)."""
        self.graph.add_edge(parent_id, child_id, EdgeType.CONTAINS)

    # ---- final serialization --------------------------------------------
    def build(self, hide_internal=False):
        """Return a serialisable representation of the current graph."""
        # Preserve all nodes in the graph; internal status should be
        # represented as metadata only, not by removing nodes.
        return self.graph.to_dict()
