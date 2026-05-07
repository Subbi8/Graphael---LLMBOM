"""Transparency score derived solely from graph evidence completeness."""

from llmbom.core.schema import NodeType, EdgeType


def compute_transparency(graph):
    """Return score and detailed items with confidence and penalties."""
    items = []
    penalties = 0.0
    max_pen = 0.0

    # model version
    mv_nodes = [nid for nid, node in graph.nodes.items() if node.type == NodeType.MODEL]
    has_version = False
    for nid in mv_nodes:
        if graph.nodes[nid].metadata.get("version"):
            has_version = True
            items.append({
                "category": "model_version",
                "status": "present",
                "confidence": 1.0,
                "evidence": [nid],
            })
            break
    if not has_version:
        items.append({
            "category": "model_version",
            "status": "missing",
            "confidence": 0.0,
            "evidence": mv_nodes,
        })
        penalties += 1.0
    max_pen += 1.0

    # fine-tune dataset
    # find scripts marked as training that have DEPENDS_ON -> DATASET
    out_adj = {}
    for e in graph.edges:
        out_adj.setdefault(e.source, []).append((e.target, e.type))
    fine_scripts = []
    for nid in graph.nodes:
        if graph.nodes[nid].type == NodeType.SCRIPT and any(tok in graph.nodes[nid].name.lower() for tok in ("train", "fine", "tune", "fit")):
            fine_scripts.append(nid)
    dataset_evidence = []
    has_dataset = False
    for s in fine_scripts:
        for tgt, et in out_adj.get(s, []):
            if et == EdgeType.DEPENDS_ON and graph.nodes[tgt].type == NodeType.DATASET:
                has_dataset = True
                dataset_evidence.append(tgt)
    if has_dataset:
        items.append({
            "category": "fine_tune_dataset",
            "status": "present",
            "confidence": 1.0,
            "evidence": dataset_evidence,
        })
    else:
        items.append({
            "category": "fine_tune_dataset",
            "status": "missing",
            "confidence": 0.0,
            "evidence": fine_scripts,
        })
        penalties += 0.5
    max_pen += 0.5

    # vector DB config
    vec_nodes = [nid for nid, node in graph.nodes.items() if node.type == NodeType.FRAMEWORK and node.metadata.get("category") == "vector_db"]
    if vec_nodes:
        items.append({
            "category": "vector_db_config",
            "status": "present",
            "confidence": 1.0,
            "evidence": vec_nodes,
        })
    else:
        items.append({
            "category": "vector_db_config",
            "status": "missing",
            "confidence": 0.0,
            "evidence": [],
        })
        penalties += 0.5
    max_pen += 0.5

    # external API isolation: look for LIBRARY nodes with metadata maybe environment config
    # treat missing as penalty
    external_libs = [nid for nid,node in graph.nodes.items() if node.type == NodeType.LIBRARY and node.metadata.get("category") == "external_api"]
    isolation_evidence = []
    for n in external_libs:
        # check if any CONFIG node connected by CONFIGURES
        for e in graph.edges:
            if e.source == n and graph.nodes[e.target].type == NodeType.CONFIG:
                isolation_evidence.append(e.target)
    if isolation_evidence:
        items.append({
            "category": "external_api_isolation",
            "status": "present",
            "confidence": 1.0,
            "evidence": isolation_evidence,
        })
    else:
        items.append({
            "category": "external_api_isolation",
            "status": "missing",
            "confidence": 0.0,
            "evidence": external_libs,
        })
        penalties += 0.5
    max_pen += 0.5

    score = 1.0 - (penalties / max_pen) if max_pen > 0 else 1.0
    return {"score": score, "items": items, "penalties": penalties, "max_penalties": max_pen}
