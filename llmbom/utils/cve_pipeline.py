import os
import sys
from pathlib import Path
from typing import Any

from llmbom.utils.cve_enricher import enrich_cve_input


def _ensure_cve_import_path(cve_dir: str) -> None:
    cve_dir = os.path.abspath(cve_dir)
    if cve_dir not in sys.path:
        sys.path.insert(0, cve_dir)


def _load_cve_modules(cve_dir: str):
    _ensure_cve_import_path(cve_dir)
    try:
        import first_optimal_july
        import recursive_july
        return first_optimal_july, recursive_july
    except Exception as exc:
        raise ImportError(
            f"Unable to import CVE modules from '{cve_dir}': {exc}"
        ) from exc


def run_cve_pipeline(
    input_file: str,
    output_file: str,
    cve_dir: str | None = None,
    allow_recursive: bool = True,
) -> dict[str, str]:
    """Run the CVE pipeline against a normalized SBOM input file."""
    if cve_dir is None:
        this_dir = Path(__file__).resolve().parent
        cve_dir = Path(this_dir, "..", "..", "CVE").resolve()
    else:
        cve_dir = Path(cve_dir).resolve()

    first_optimal_july, recursive_july = _load_cve_modules(str(cve_dir))

    output_file = Path(output_file).resolve()

    output_dir = output_file.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    enriched_input = output_dir / f"{output_file.stem}_enriched_input.json"
    enrichment_stats = output_dir / f"{output_file.stem}_enrichment_stats.json"
    exploit_output = output_dir / f"{output_file.stem}_with_exploits.json"
    first_optimal_output = output_dir / f"{output_file.stem}_first_optimal.json"

    enrichment_summary = enrich_cve_input(
        input_file,
        str(enriched_input),
        stats_file=str(enrichment_stats),
    )

    tool = first_optimal_july.VulnerabilityAnalysisTool()
    tool.run_analysis(
        original_input_file=str(enriched_input),
        exploit_enhanced_file=str(exploit_output),
        final_output_file=str(first_optimal_output),
        output_prefix=output_file.stem,
    )

    result = {
        "enriched_input": str(enriched_input),
        "enrichment_stats": str(enrichment_stats),
        "enrichment_summary": enrichment_summary,
        "first_optimal": str(first_optimal_output),
        "exploit_enhanced": str(exploit_output),
    }

    if allow_recursive:
        optimizer = recursive_july.RecursiveCveOptimizer()
        exit_code = optimizer.main(
            input_file=str(exploit_output),
            first_optimal_file=str(first_optimal_output),
            output_file=str(output_file),
        )
        if exit_code != 0:
            raise RuntimeError(f"Recursive CVE pipeline failed with exit code {exit_code}")
        result["output_file"] = str(output_file)
    else:
        result["output_file"] = str(first_optimal_output)

    return result
