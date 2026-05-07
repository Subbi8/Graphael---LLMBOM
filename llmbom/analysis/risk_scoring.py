"""Compute risk scores based purely on graph structure and metrics."""

from collections import Counter
from llmbom.core.schema import NodeType


def node_risks(graph, metrics):
    """Return per-node risk values and intermediate contributors."""
    betw = metrics.get("betweenness", {})
    depths = metrics.get("depths", {})
    in_deg = metrics.get("in_degrees", {})

    # avoid division by zero: ensure at least 1
    max_b = max(max(betw.values()) if betw else 0, 1)
    max_d = max(max(depths.values()) if depths else 0, 1)
    risks = {}
    for nid in graph.nodes:
        c = betw.get(nid, 0) / max_b
        d = depths.get(nid, 0) / max_d
        ext = 1.0 if graph.nodes[nid].type == NodeType.LIBRARY else 0.0
        # normalized weighted sum; weights taken from graph size
        alpha = 0.4
        beta = 0.4
        gamma = 0.2
        risk = alpha * c + beta * d + gamma * ext
        contributors = []
        if c > 0:
            contributors.append("centrality")
        if d > 0:
            contributors.append("chain_depth")
        if ext:
            contributors.append("external")
        risks[nid] = {"risk": risk, "contributors": contributors}
    return risks


def project_risk(graph, metrics):
    """Aggregate project-level risk score and supporting terms."""
    n = len(graph.nodes)
    external_nodes = [nid for nid, node in graph.nodes.items() if node.type == NodeType.LIBRARY]
    ratio_ext = len(external_nodes) / n if n else 0

    # transitive vendor ratio: count of distinct library names reachable
    # compute vendors by library name
    out_adj = {e.source: [] for e in graph.edges}
    for e in graph.edges:
        out_adj.setdefault(e.source, []).append(e.target)
    vendor_paths = set()
    for nid in graph.nodes:
        visited = set()
        stack = [nid]
        while stack:
            u = stack.pop()
            if u in visited:
                continue
            visited.add(u)
            if graph.nodes[u].type == NodeType.LIBRARY:
                vendor_paths.add(graph.nodes[u].name)
            for v in out_adj.get(u, []):
                if v not in visited:
                    stack.append(v)
    trans_ratio = len(vendor_paths) / n if n else 0

    # duplicate vendor paths: count repeated library names across different paths
    # simplistic: number of libraries with in-degree>1
    from collections import Counter
    lib_in_deg = Counter()
    for e in graph.edges:
        if graph.nodes[e.target].type == NodeType.LIBRARY:
            lib_in_deg[graph.nodes[e.target].name] += 1
    dup_vendor = sum(1 for count in lib_in_deg.values() if count > 1)

    # largest disconnected AI cluster size
    # consider subgraph of framework-connected nodes
    from llmbom.analysis.graph_metrics import weak_components
    frameworks = [nid for nid, node in graph.nodes.items() if node.type == NodeType.FRAMEWORK]
    # get components of full graph and pick max intersection with frameworks
    comps = weak_components(graph)
    max_cluster = 0
    for comp in comps:
        size = len(comp.intersection(set(frameworks)))
        if size > max_cluster:
            max_cluster = size

    # compute max node risk
    node_r = node_risks(graph, metrics)
    max_node_risk = max((item["risk"] for item in node_r.values()), default=0)

    # combine using Euclidean norm
    import math
    R = math.sqrt(
        ratio_ext ** 2 + max_node_risk ** 2 + trans_ratio ** 2 + (dup_vendor / n if n else 0) ** 2 + (max_cluster / n if n else 0) ** 2
    )
    return {
        "project_risk_score": R,
        "terms": {
            "external_ratio": ratio_ext,
            "max_node_risk": max_node_risk,
            "transitive_vendor_ratio": trans_ratio,
            "dup_vendor_paths": dup_vendor,
            "largest_ai_cluster_size": max_cluster,
        },
        "node_risks": node_r,
    }
