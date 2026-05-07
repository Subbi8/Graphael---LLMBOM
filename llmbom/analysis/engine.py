"""Top-level analysis engine that drives all analytic modules and produces the final report."""

from llmbom.analysis import graph_metrics, ai_inventory, risk_scoring, transparency, report_formatter


def run_analysis(graph):
    """Return structured report for given LLMBOMGraph instance."""
    metrics = graph_metrics.compute_all(graph)
    inventory = ai_inventory.inventory(graph)
    risk = risk_scoring.project_risk(graph, metrics)
    trans = transparency.compute_transparency(graph)
    report = report_formatter.format_report(graph, inventory, metrics, risk, trans)
    return report
