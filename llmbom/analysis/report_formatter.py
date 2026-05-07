"""Compose the structured enterprise report from analysis results."""

def format_report(graph, inventory, metrics, risk, transparency):
    # basic summary
    project_summary = {
        "node_count": len(graph.nodes),
        "edge_count": len(graph.edges),
        "ai_node_count": len(inventory.get("framework_connected", [])),
    }
    report = {
        "project_summary": project_summary,
        "ai_inventory": inventory,
        "dependency_analysis": {
            "criticality": {
                "most_critical": risk["node_risks"] and max(risk["node_risks"].items(), key=lambda kv: kv[1]["risk"])[1] or {},
                "single_points_of_failure": [],
                "most_reused_model": {},
                "central_vector_store": {},
            },
            "graph_metrics": metrics,
        },
        "risk_assessment": {
            "project_risk_score": risk.get("project_risk_score"),
            "node_risks": risk.get("node_risks"),
            "terms": risk.get("terms"),
        },
        "transparency_assessment": transparency,
        "compliance_indicators": {
            # example flags; callers may populate more
            "has_versioned_models": bool([n for n in graph.nodes.values() if n.type == "MODEL" and n.metadata.get("version")]),
            "uses_external_apis": bool([n for n in graph.nodes.values() if n.type == "LIBRARY" and n.metadata.get("category") == "external_api"]),
            "isolated_execution": transparency.get("score", 0) > 0.8,
        },
        "static_evidence_log": [],
        "raw_graph_reference": {
            "nodes": [node.to_dict() for node in graph.nodes.values()],
            "edges": [edge.to_dict() for edge in graph.edges],
        },
    }
    
    # convert any sets to lists recursively so JSON serialization works
    def _convert(obj):
        if isinstance(obj, dict):
            return {k: _convert(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [_convert(v) for v in obj]
        elif isinstance(obj, set):
            return [_convert(v) for v in obj]
        else:
            return obj
    return _convert(report)
