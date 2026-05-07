from llmbom.engine.orchestrator import LLMBOMOrchestrator
from llmbom.analysis.engine import run_analysis

proj = r"C:\Users\shubham\Downloads\llm-code-examples-main\llm-code-examples-main"
orch = LLMBOMOrchestrator(proj)
res = orch.run()
print("result type", type(res))
if isinstance(res, dict):
    print("keys", list(res.keys()))

if isinstance(res, dict) and "analysis" not in res:
    print("manual analyze: invoking run_analysis")
    try:
        analysis = run_analysis(orch.builder.graph)
        print("analysis generated, keys", list(analysis.keys()))
    except Exception as exc:
        import traceback
        print("analysis threw", exc)
        traceback.print_exc()
