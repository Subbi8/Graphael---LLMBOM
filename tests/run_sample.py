import sys
import json
from llmbom.engine.orchestrator import LLMBOMOrchestrator


def main():
    proj = "tests/sample_project"
    orch = LLMBOMOrchestrator(proj)
    result = orch.run()
    # if analysis present, pretty-print both
    if isinstance(result, dict) and "analysis" in result:
        print("GRAPH:\n", json.dumps(result.get("graph"), indent=2))
        print("\nANALYSIS:\n", json.dumps(result.get("analysis"), indent=2))
    else:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
