"""AI component inventory derived from static graph relationships."""

from collections import defaultdict, deque
from llmbom.core.schema import NodeType, EdgeType


def _build_adj(graph):
    out = defaultdict(set)
    for e in graph.edges:
        out[e.source].add((e.target, e.type))
    return out


def nodes_by_type(graph, ntype):
    return [nid for nid, n in graph.nodes.items() if n.type == ntype]


def reachable_to_type(graph, target_type):
    """Return set of node ids that have a directed path to any node of given type."""
    out_adj = _build_adj(graph)
    target_ids = set(nodes_by_type(graph, target_type))
    reachable = set()
    # for each node do BFS until hitting a target
    for nid in graph.nodes:
        visited = set()
        q = deque([nid])
        while q:
            u = q.popleft()
            if u in target_ids:
                reachable.add(nid)
                break
            for v, _ in out_adj.get(u, []):
                if v not in visited:
                    visited.add(v)
                    q.append(v)
    return reachable


def inventory(graph):
    """Compute the AI inventory according to design spec."""
    out_adj = _build_adj(graph)
    result = {
        "framework_nodes": [],
        "vector_db_nodes": [],
        "fine_tune_scripts": [],
        "embedding_pipelines": [],
        "model_clusters": [],
    }

    # identify frameworks and group by metadata
    for nid in nodes_by_type(graph, NodeType.FRAMEWORK):
        result["framework_nodes"].append(nid)
        node = graph.nodes[nid]
        cat = node.metadata.get("category")
        if cat == "vector_db":
            result["vector_db_nodes"].append(nid)

    # direct connectivity to AI frameworks
    result["framework_connected"] = list(reachable_to_type(graph, NodeType.FRAMEWORK))

    # fine-tuning patterns: scripts whose path name hints at training
    for nid in nodes_by_type(graph, NodeType.SCRIPT):
        name = graph.nodes[nid].name.lower()
        if any(tok in name for tok in ("train", "fine", "tune", "fit")):
            # also require it depends on a dataset or model
            for tgt, etype in out_adj.get(nid, []):
                if graph.nodes[tgt].type in (NodeType.DATASET, NodeType.MODEL):
                    result["fine_tune_scripts"].append(nid)
                    break

    # embedding pipelines: find script->framework->vector_db
    for sid in nodes_by_type(graph, NodeType.SCRIPT):
        for fid, etype in out_adj.get(sid, []):
            if etype == EdgeType.USES_FRAMEWORK:
                fw = graph.nodes[fid]
                name = fw.name.lower()
                cat = fw.metadata.get("category", "")
                if "embed" in name or cat == "embedding":
                    # look for downstream vector DB from script
                    for vid, etype2 in out_adj.get(sid, []):
                        if vid in result["vector_db_nodes"]:
                            result["embedding_pipelines"].append(
                                {"script": sid, "framework": fid, "vector_db": vid}
                            )
    # model usage clusters via centrality will be added later by external caller
    # here we just compute centrality and assign
    # we leave placeholder; scoring engine can compute actual clusters
    return result
