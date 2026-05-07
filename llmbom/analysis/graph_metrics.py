"""Utilities for computing graph topology metrics.

All computations operate on the raw LLMBOMGraph instance and return
primitive dicts so they are easy to incorporate into the report.
"""

from collections import defaultdict, deque


def build_adj_lists(graph):
    """Return (out_adj, in_adj) as dicts mapping node_id -> set(node_id)."""
    out_adj = defaultdict(set)
    in_adj = defaultdict(set)
    for edge in graph.edges:
        out_adj[edge.source].add(edge.target)
        in_adj[edge.target].add(edge.source)
    # ensure every node appears
    for nid in graph.nodes.keys():
        out_adj.setdefault(nid, set())
        in_adj.setdefault(nid, set())
    return out_adj, in_adj


def in_degree(graph):
    _, in_adj = build_adj_lists(graph)
    return {nid: len(sources) for nid, sources in in_adj.items()}


def out_degree(graph):
    out_adj, _ = build_adj_lists(graph)
    return {nid: len(targets) for nid, targets in out_adj.items()}


def _bfs_shortest_paths(out_adj, start):
    """Return dict dist[node] = distance from start via directed edges."""
    dist = {start: 0}
    q = deque([start])
    while q:
        u = q.popleft()
        for v in out_adj.get(u, []):
            if v not in dist:
                dist[v] = dist[u] + 1
                q.append(v)
    return dist


def betweenness_centrality(graph):
    # Brandes algorithm simplified for unweighted directed graph
    out_adj, _ = build_adj_lists(graph)
    nodes = list(graph.nodes.keys())
    centrality = dict.fromkeys(nodes, 0.0)
    for s in nodes:
        # single-source shortest paths
        stack = []
        preds = {w: [] for w in nodes}
        sigma = dict.fromkeys(nodes, 0)
        dist = dict.fromkeys(nodes, -1)
        sigma[s] = 1
        dist[s] = 0
        q = deque([s])
        while q:
            v = q.popleft()
            stack.append(v)
            for w in out_adj.get(v, []):
                if dist[w] < 0:
                    dist[w] = dist[v] + 1
                    q.append(w)
                if dist[w] == dist[v] + 1:
                    sigma[w] += sigma[v]
                    preds[w].append(v)
        delta = dict.fromkeys(nodes, 0)
        while stack:
            w = stack.pop()
            for v in preds[w]:
                delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w])
            if w != s:
                centrality[w] += delta[w]
    return centrality


def _dfs(node, out_adj, visited, stack, result):
    visited.add(node)
    stack.add(node)
    for nbr in out_adj.get(node, []):
        if nbr not in visited:
            _dfs(nbr, out_adj, visited, stack, result)
        elif nbr in stack:
            # cycle detected; ignore for depth calculation
            pass
    stack.remove(node)
    # post-order, compute depth
    max_child = 0
    for nbr in out_adj.get(node, []):
        max_child = max(max_child, result.get(nbr, 0))
    result[node] = max_child + 1


def depths(graph):
    """Longest path length from any root (zero in-degree) to each node."""
    out_adj, in_adj = build_adj_lists(graph)
    roots = [nid for nid, sources in in_adj.items() if not sources]
    result = {}
    visited = set()
    # we compute depth by starting from each root via DFS
    for r in roots:
        if r not in visited:
            _dfs(r, out_adj, visited, set(), result)
    # nodes unreachable from roots get depth=0
    for nid in graph.nodes:
        result.setdefault(nid, 0)
    return result


def weak_components(graph):
    """Return list of sets of node_ids for each weakly connected component."""
    out_adj, in_adj = build_adj_lists(graph)
    undirected = defaultdict(set)
    for u, targets in out_adj.items():
        for v in targets:
            undirected[u].add(v)
            undirected[v].add(u)
    visited = set()
    comps = []
    for nid in graph.nodes:
        if nid not in visited:
            comp = set()
            stack = [nid]
            while stack:
                v = stack.pop()
                if v in visited:
                    continue
                visited.add(v)
                comp.add(v)
                for w in undirected.get(v, []):
                    if w not in visited:
                        stack.append(w)
            comps.append(comp)
    return comps


def strong_components(graph):
    """Tarjan's strongly connected components."""
    out_adj, _ = build_adj_lists(graph)
    index = 0
    indices = {}
    lowlink = {}
    stack = []
    onstack = set()
    result = []

    def strongconnect(v):
        nonlocal index
        indices[v] = index
        lowlink[v] = index
        index += 1
        stack.append(v)
        onstack.add(v)
        for w in out_adj.get(v, []):
            if w not in indices:
                strongconnect(w)
                lowlink[v] = min(lowlink[v], lowlink[w])
            elif w in onstack:
                lowlink[v] = min(lowlink[v], indices[w])
        if lowlink[v] == indices[v]:
            comp = set()
            while True:
                w = stack.pop()
                onstack.remove(w)
                comp.add(w)
                if w == v:
                    break
            result.append(comp)
    for v in graph.nodes:
        if v not in indices:
            strongconnect(v)
    return result


def compute_all(graph):
    """Convenience wrapper returning all metrics in a dict."""
    return {
        "in_degrees": in_degree(graph),
        "out_degrees": out_degree(graph),
        "betweenness": betweenness_centrality(graph),
        "depths": depths(graph),
        "weak_components": weak_components(graph),
        "strong_components": strong_components(graph),
    }
