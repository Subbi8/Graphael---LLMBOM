"""Metadata enrichment layer for script and library tracking."""

from llmbom.core.schema import NodeType, EdgeType
from llmbom.utils.file_utils import normalize_path, script_metadata
from llmbom.utils.stdlib import is_stdlib_module


class MetadataEnricher:
    """Enriches nodes with static, deterministic metadata."""

    def __init__(self, project_root):
        self.project_root = project_root

    def enrich_script(self, graph, script_node_id, file_path):
        """Enrich a SCRIPT node with file metadata."""
        script = graph.nodes.get(script_node_id)
        if not script or script.type != NodeType.SCRIPT:
            return

        meta = script.metadata or {}

        # add static file metadata
        sdata = script_metadata(file_path)
        for key in ("file_size_bytes", "line_count", "sha256", "language"):
            if key in sdata:
                meta[key] = sdata[key]

        # store normalized path
        normalized = normalize_path(file_path, self.project_root)
        meta["file_path_normalized"] = normalized

        script.metadata = meta

    def enrich_script_batch(self, graph, script_paths):
        """Enrich all supplied script paths.

        *script_paths* is a dict mapping file_path -> script_node_id.
        """
        for fpath, sid in script_paths.items():
            self.enrich_script(graph, sid, fpath)

    def enrich_library_nodes(self, graph):
        """Add is_stdlib and import_count metadata to all LIBRARY nodes."""
        # first pass: count imports per library
        import_counts = {}
        for edge in graph.edges:
            if edge.type == EdgeType.DEPENDS_ON:
                target = graph.nodes.get(edge.target)
                if target and target.type == NodeType.LIBRARY:
                    import_counts[edge.target] = import_counts.get(edge.target, 0) + 1

        # second pass: enrich library nodes
        for nid, node in graph.nodes.items():
            if node.type != NodeType.LIBRARY:
                continue
            meta = node.metadata or {}
            meta["is_stdlib"] = is_stdlib_module(node.name)
            meta["import_count"] = import_counts.get(nid, 0)
            node.metadata = meta
