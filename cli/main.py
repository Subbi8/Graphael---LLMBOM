# llmbom/cli/main.py

import sys
import os
import argparse
import json
import subprocess
from datetime import datetime

# Ensure the project root (parent of cli/) is on sys.path so `llmbom`
# package is importable when running this script directly:
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from llmbom.engine.orchestrator import LLMBOMOrchestrator
from llmbom.exporters.graph_exporter import GraphExporter
from llmbom.exporters.diff_exporter import DiffExporter
from llmbom.utils.sbom_adapter import normalize_sbom_for_cve, save_json
from llmbom.utils.cve_pipeline import run_cve_pipeline


def _detect_language_from_repo(repo_path: str) -> str:
    """Detect the primary language of the repository by examining dependency files."""
    repo_path = os.path.abspath(repo_path)
    
    # Check for language-specific dependency files
    language_indicators = {
        ".csproj": "dotnet",
        ".fsproj": "dotnet", 
        ".nuspec": "dotnet",
        "composer.json": "php",
        "composer.lock": "php",
        "package.json": "javascript",
        "package-lock.json": "javascript",
        "yarn.lock": "javascript",
        "pnpm-lock.yaml": "javascript",
        "requirements.txt": "python",
        "setup.py": "python",
        "pyproject.toml": "python",
        "Pipfile": "python",
        "Pipfile.lock": "python",
        "CMakeLists.txt": "cpp",
        "Makefile": "cpp",
    }
    
    # Walk the repository to find indicators
    detected_languages = {}
    for root, dirs, files in os.walk(repo_path):
        # Skip hidden and common non-source directories
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__', 'venv', '.venv', 'dist', 'build']]
        
        for file in files:
            for indicator, language in language_indicators.items():
                if file == indicator:
                    detected_languages[language] = detected_languages.get(language, 0) + 1
    
    if not detected_languages:
        # Check for source code files if no dependency files found
        detected_languages_by_ext = {}
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__', 'venv', '.venv']]
            for file in files:
                if file.endswith('.py'):
                    detected_languages_by_ext['python'] = detected_languages_by_ext.get('python', 0) + 1
                elif file.endswith(('.js', '.ts', '.jsx', '.tsx')):
                    detected_languages_by_ext['javascript'] = detected_languages_by_ext.get('javascript', 0) + 1
                elif file.endswith(('.cs', '.fs')):
                    detected_languages_by_ext['dotnet'] = detected_languages_by_ext.get('dotnet', 0) + 1
                elif file.endswith(('.cpp', '.cc', '.cxx', '.c++', '.h', '.hpp')):
                    detected_languages_by_ext['cpp'] = detected_languages_by_ext.get('cpp', 0) + 1
                elif file.endswith('.php'):
                    detected_languages_by_ext['php'] = detected_languages_by_ext.get('php', 0) + 1
        
        if detected_languages_by_ext:
            detected_languages = detected_languages_by_ext
    
    if not detected_languages:
        # Default to Python if nothing is detected
        return "python"
    
    # Return the most frequently detected language
    return max(detected_languages, key=detected_languages.get)


def _detect_gauntlet_path(gauntlet_path: str | None = None) -> str:
    """Detect or use provided gauntlet SBOM generator path."""
    if gauntlet_path:
        gauntlet_path = os.path.abspath(gauntlet_path)
    else:
        # Look for gauntlet in common locations
        for candidate_path in [
            os.path.join(os.path.dirname(__file__), "..", "gauntlet-sbom-universal-generator"),
            os.path.abspath("gauntlet-sbom-universal-generator"),
            os.path.expanduser("~/gauntlet-sbom-universal-generator"),
        ]:
            if os.path.exists(os.path.join(candidate_path, "main.py")):
                gauntlet_path = candidate_path
                break
    
    main_script = os.path.join(gauntlet_path, "main.py") if gauntlet_path else None
    if not main_script or not os.path.exists(main_script):
        raise FileNotFoundError(
            f"Gauntlet SBOM generator not found at {gauntlet_path}. "
            f"Expected main.py at {main_script}. "
            f"Use --gauntlet-path to specify the gauntlet-sbom-universal-generator location."
        )
    return gauntlet_path


def _load_json_file(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _merge_gauntlet_sbom_files(sbom_paths: list[str]) -> dict:
    """Merge all Gauntlet category SBOM files into one component list."""
    components = []
    seen = set()

    for sbom_path in sorted(sbom_paths):
        data = _load_json_file(sbom_path)
        source_category = os.path.basename(sbom_path).removesuffix("_sbom.json")

        for component in data.get("components", []):
            if not isinstance(component, dict):
                continue

            merged = dict(component)
            merged.setdefault("source_sbom", source_category)

            key = (
                str(merged.get("name", "")).lower(),
                str(merged.get("version", "")),
                str(merged.get("publisher", "")),
                str(merged.get("type", "")),
                str(merged.get("file", "")),
            )
            if key in seen:
                continue

            seen.add(key)
            components.append(merged)

    return {"components": components}


def _run_gauntlet_sbom_generator(repo_path: str, gauntlet_path: str, output_dir: str, language: str | None = None, sbom_out: str | None = None) -> str:
    """Run gauntlet SBOM generator on the repository and return path to normalized SBOM."""
    repo_path = os.path.abspath(repo_path)
    gauntlet_path = os.path.abspath(gauntlet_path)
    
    # Auto-detect language if not provided
    if not language:
        language = _detect_language_from_repo(repo_path)
        print(f"Auto-detected language: {language}")
    else:
        print(f"Using specified language: {language}")
    
    print(f"Running gauntlet SBOM generator from: {gauntlet_path}")
    print(f"Target repository: {repo_path}")
    print(f"Language: {language}")
    
    cmd = [sys.executable, os.path.join(gauntlet_path, "main.py"), repo_path, language]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=gauntlet_path)
    
    if result.returncode != 0:
        print(f"Gauntlet SBOM generator stderr:\n{result.stderr}", file=sys.stderr)
        raise RuntimeError(f"Gauntlet SBOM generator failed with exit code {result.returncode}")
    
    print(result.stdout)
    
    # Gauntlet outputs to result/ directory
    result_dir = os.path.join(gauntlet_path, "result")
    if not os.path.exists(result_dir):
        raise FileNotFoundError(f"Gauntlet result directory not found at {result_dir}")
    
    repo_name = os.path.basename(os.path.normpath(repo_path))
    gauntlet_sbom_dir = os.path.join(result_dir, repo_name)
    
    if not os.path.exists(gauntlet_sbom_dir):
        raise FileNotFoundError(f"Gauntlet output not found for repo {repo_name} at {gauntlet_sbom_dir}")
    
    # Find the main SBOM JSON file
    sbom_files = [f for f in os.listdir(gauntlet_sbom_dir) if f.endswith("_sbom.json")]
    if not sbom_files:
        raise FileNotFoundError(f"No SBOM JSON files found in {gauntlet_sbom_dir}")

    gauntlet_sbom_paths = [os.path.join(gauntlet_sbom_dir, f) for f in sbom_files]
    sbom_dest = sbom_out or os.path.join(output_dir, "sbom_output.json")
    merged_sbom = _merge_gauntlet_sbom_files(gauntlet_sbom_paths)
    save_json(merged_sbom, sbom_dest)
    print(f"SBOM generated by gauntlet at {sbom_dest}")
    return sbom_dest


def _make_repo_output_folder(repo_path: str, output_dir: str | None = None) -> str:
    if output_dir:
        workspace_dir = os.path.abspath(output_dir)
    else:
        repo_name = os.path.basename(os.path.normpath(repo_path)) or "repo"
        safe_repo_name = repo_name.replace(" ", "_").replace("/", "_").replace("\\", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        workspace_dir = os.path.abspath(f"{safe_repo_name}_outputs_{timestamp}")

    os.makedirs(workspace_dir, exist_ok=True)
    return workspace_dir


def _prepare_cve_input(sbom_path, cve_input_path):
    if isinstance(sbom_path, str):
        with open(sbom_path, "r", encoding="utf-8") as f:
            sbom_data = json.load(f)
    else:
        sbom_data = sbom_path

    normalized = normalize_sbom_for_cve(sbom_data)
    save_json(normalized, cve_input_path)
    print(f"CVE input file saved at {cve_input_path}")
    return cve_input_path


def cmd_generate(args):
    """Generate LLMBOM for a repository."""
    # enable_transitive defaults to True, unless --no-transitive is passed
    enable_transitive = not args.no_transitive
    # enable_notebook_cells defaults to True, unless --no-notebook-cells is passed
    enable_notebook_cells = not args.no_notebook_cells
    # hide_internal defaults to False, unless --hide-internal is passed
    hide_internal = args.hide_internal

    output_dir = _make_repo_output_folder(args.repo, args.output_dir)

    def _resolve_path(path: str) -> str:
        return os.path.abspath(path) if os.path.isabs(path) else os.path.abspath(os.path.join(output_dir, path))

    llmbom_out = _resolve_path(args.out)
    sbom_out = _resolve_path(args.sbom_out)
    cve_input_out = _resolve_path(args.cve_input)
    cve_out = _resolve_path(args.cve_out)

    orchestrator = LLMBOMOrchestrator(args.repo)
    graph_data = orchestrator.run(
        enable_transitive=enable_transitive,
        enable_notebook_cells=enable_notebook_cells,
        hide_internal=hide_internal
    )

    GraphExporter.export(graph_data, llmbom_out)
    print(f"LLMBOM generated at {llmbom_out}")
    print(f"All outputs are being written into: {output_dir}")

    if args.with_sbom or args.with_cve:
        try:
            gauntlet_path = _detect_gauntlet_path(args.gauntlet_path)
            sbom_path = _run_gauntlet_sbom_generator(args.repo, gauntlet_path, output_dir, args.language, sbom_out)
        except Exception as exc:
            print(f"SBOM generation failed: {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        sbom_path = None

    if args.with_cve:
        if sbom_path is None:
            try:
                gauntlet_path = _detect_gauntlet_path(args.gauntlet_path)
                sbom_path = _run_gauntlet_sbom_generator(args.repo, gauntlet_path, output_dir, args.language, sbom_out)
            except Exception as exc:
                print(f"SBOM generation failed: {exc}", file=sys.stderr)
                sys.exit(1)

        cve_input_path = _prepare_cve_input(sbom_path, cve_input_out)

        try:
            result = run_cve_pipeline(cve_input_path, cve_out)
            print(f"CVE pipeline completed. Final CVE JSON: {result['output_file']}")
            print(f"Intermediate first-optimal file: {result['first_optimal']}")
            print(f"Intermediate exploit-enhanced file: {result['exploit_enhanced']}")
        except Exception as exc:
            print(f"CVE pipeline failed: {exc}", file=sys.stderr)
            sys.exit(1)


def cmd_diff(args):
    """Compare two LLMBOM JSON files."""
    if not os.path.exists(args.old):
        print(f"Error: old file '{args.old}' not found", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(args.new):
        print(f"Error: new file '{args.new}' not found", file=sys.stderr)
        sys.exit(1)

    # Compute diff
    diff_result = DiffExporter.compare_files(args.old, args.new)

    # Export diff
    out_file = args.out or "llmbom_diff.json"
    DiffExporter.export(diff_result, out_file)

    # Print summary to console
    summary = diff_result.get('summary', {})
    print(f"Diff summary saved to {out_file}")
    print(f"\nSummary:")
    print(f"  Old graph:  {summary.get('old_graph_nodes')} nodes, {summary.get('old_graph_edges')} edges")
    print(f"  New graph:  {summary.get('new_graph_nodes')} nodes, {summary.get('new_graph_edges')} edges")
    print(f"  Node delta: {summary.get('node_delta'):+d}")
    print(f"  Edge delta: {summary.get('edge_delta'):+d}")
    print(f"\n  Added:   {summary.get('added_nodes_count')} nodes, {summary.get('added_edges_count')} edges")
    print(f"  Removed: {summary.get('removed_nodes_count')} nodes, {summary.get('removed_edges_count')} edges")
    print(f"  Changed: {summary.get('changed_nodes_count')} nodes, {summary.get('changed_edges_count')} edges")


def main():
    parser = argparse.ArgumentParser(
        description="LLMBOM: AI/ML Supply Chain Inventory Explorer"
    )
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Subcommand: generate (default)
    gen_parser = subparsers.add_parser(
        'generate',
        help='Generate LLMBOM for a repository (default if no command given)'
    )
    gen_parser.add_argument("--repo", required=True, help="Path to repository")
    gen_parser.add_argument(
        "--output-dir",
        default=None,
        help="Optional base output directory for generated files; defaults to a repo-specific folder"
    )
    gen_parser.add_argument("--out", default="llmbom_output.json", help="Output file name or path for LLMBOM JSON")
    gen_parser.add_argument(
        "--no-transitive",
        action="store_true",
        default=False,
        help="Disable transitive dependency resolution via lockfile parsing"
    )
    gen_parser.add_argument(
        "--no-notebook-cells",
        action="store_true",
        default=False,
        help="Disable per-cell extraction for Jupyter notebooks"
    )
    gen_parser.add_argument(
        "--hide-internal",
        action="store_true",
        default=False,
        help="Hide internal project modules from the output graph"
    )
    gen_parser.add_argument(
        "--with-sbom",
        action="store_true",
        default=False,
        help="Generate an SBOM file alongside the LLMBOM output"
    )
    gen_parser.add_argument(
        "--with-cve",
        action="store_true",
        default=False,
        help="Run the CVE pipeline against the generated SBOM"
    )
    gen_parser.add_argument(
        "--gauntlet-path",
        default=None,
        help="Path to gauntlet-sbom-universal-generator root directory; auto-detects if not provided"
    )
    gen_parser.add_argument(
        "--language",
        default=None,
        help="Programming language for gauntlet SBOM generator; auto-detects if not provided (python, javascript, c, c++, cpp, dotnet, csharp, c#, php, typescript, ts, nodejs)"
    )
    gen_parser.add_argument(
        "--sbom-out",
        default="sbom_output.json",
        help="Output path for the generated SBOM JSON file"
    )
    gen_parser.add_argument(
        "--cve-input",
        default="cve_input.json",
        help="Normalized CVE input JSON path"
    )
    gen_parser.add_argument(
        "--cve-out",
        default="cve_output.json",
        help="Output path for the final CVE results JSON file"
    )
    gen_parser.set_defaults(func=cmd_generate)

    # Subcommand: diff
    diff_parser = subparsers.add_parser(
        'diff',
        help='Compare two LLMBOM JSON files'
    )
    diff_parser.add_argument("old", help="Path to original LLMBOM JSON file")
    diff_parser.add_argument("new", help="Path to updated LLMBOM JSON file")
    diff_parser.add_argument(
        "--out",
        default="llmbom_diff.json",
        help="Output file for diff results"
    )
    diff_parser.set_defaults(func=cmd_diff)

    args = parser.parse_args()

    # If no command given, default to generate (for backward compatibility)
    if args.command is None:
        # Re-parse with --repo and --out as top-level args
        old_parser = argparse.ArgumentParser()
        old_parser.add_argument("--repo", required=True)
        old_parser.add_argument(
            "--output-dir",
            default=None,
            help="Optional base output directory for generated files; defaults to a repo-specific folder"
        )
        old_parser.add_argument("--out", default="llmbom_output.json")
        old_parser.add_argument(
            "--no-transitive",
            action="store_true",
            default=False,
            help="Disable transitive dependency resolution via lockfile parsing"
        )
        old_parser.add_argument(
            "--no-notebook-cells",
            action="store_true",
            default=False,
            help="Disable per-cell extraction for Jupyter notebooks"
        )
        old_parser.add_argument(
            "--hide-internal",
            action="store_true",
            default=False,
            help="Hide internal project modules from the output graph"
        )
        old_parser.add_argument(
            "--with-sbom",
            action="store_true",
            default=False,
            help="Generate an SBOM file alongside the LLMBOM output"
        )
        old_parser.add_argument(
            "--with-cve",
            action="store_true",
            default=False,
            help="Run the CVE pipeline against the generated SBOM"
        )
        old_parser.add_argument(
            "--gauntlet-path",
            default=None,
            help="Path to gauntlet-sbom-universal-generator root directory; auto-detects if not provided"
        )
        old_parser.add_argument(
            "--language",
            default=None,
            help="Programming language for gauntlet SBOM generator; auto-detects if not provided (python, javascript, c, c++, cpp, dotnet, csharp, c#, php, typescript, ts, nodejs)"
        )
        old_parser.add_argument(
            "--sbom-out",
            default="sbom_output.json",
            help="Output path for the generated SBOM JSON file"
        )
        old_parser.add_argument(
            "--cve-input",
            default="cve_input.json",
            help="Normalized CVE input JSON path"
        )
        old_parser.add_argument(
            "--cve-out",
            default="cve_output.json",
            help="Output path for the final CVE results JSON file"
        )
        old_args = old_parser.parse_args()
        old_args.func = cmd_generate
        cmd_generate(old_args)
    else:
        args.func(args)


if __name__ == "__main__":
    main()
