import os
from llmbom.engine.orchestrator import LLMBOMOrchestrator


def test_orchestrator_produces_analysis(tmp_path, monkeypatch):
    # create a minimal temporary project with a single python file
    proj = tmp_path / "proj"
    proj.mkdir()
    file = proj / "script.py"
    file.write_text("import os\n")
    orch = LLMBOMOrchestrator(str(proj))
    result = orch.run()
    assert isinstance(result, dict)
    # should have graph and analysis keys
    assert "graph" in result
    assert "analysis" in result
    analysis = result["analysis"]
    assert "project_summary" in analysis
    assert "graph_metrics" in analysis["dependency_analysis"]
