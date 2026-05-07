# CLI Entrypoint: `cli/main.py`

`cli/main.py` is the main orchestration file for the product. It owns command
parsing, output path setup, LLMBOM graph generation, optional SBOM generation,
optional CVE processing, and diff mode.

## Import Setup

The file starts by inserting the repository root into `sys.path`:

```python
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
```

This allows the script to be run directly as:

```bash
python cli/main.py ...
```

without requiring the package to be installed first.

## Commands

The CLI supports two top-level commands:

- `generate`: analyze a repository and produce LLMBOM output. This is the main
  product pipeline.
- `diff`: compare two LLMBOM graph JSON files and produce a delta report.

If no subcommand is supplied, the script preserves backward compatibility by
parsing the old top-level `--repo` style arguments and running `generate`.

## `generate` Arguments

Important arguments:

- `--repo`: target repository to analyze.
- `--output-dir`: optional output directory. If omitted, the CLI creates a
  timestamped folder named like `<repo>_outputs_<YYYYMMDD_HHMMSS>`.
- `--out`: LLMBOM JSON file name or path. Defaults to `llmbom_output.json`.
- `--no-transitive`: disables static lockfile/manifest dependency discovery.
- `--no-notebook-cells`: disables per-cell Jupyter notebook extraction.
- `--hide-internal`: currently passed through to the graph builder, while
  internal modules are represented as metadata rather than removed.
- `--with-sbom`: runs the Gauntlet SBOM integration after LLMBOM generation.
- `--with-cve`: runs SBOM generation and then the CVE pipeline.
- `--gauntlet-path`: manually points to `gauntlet-sbom-universal-generator`.
- `--language`: manually tells Gauntlet which language mode to use.
- `--sbom-out`: SBOM output file name or path.
- `--cve-input`: normalized CVE input file name or path.
- `--cve-out`: final CVE output file name or path.

## Output Directory Creation

`_make_repo_output_folder()` determines where generated files go.

If `--output-dir` is supplied:

```text
output_dir = absolute path of --output-dir
```

If not supplied:

```text
output_dir = <safe_repo_name>_outputs_<timestamp>
```

The folder is created before analysis begins.

## Relative vs Absolute Output Paths

Inside `cmd_generate()`, `_resolve_path()` converts output paths:

- absolute paths stay absolute.
- relative paths are interpreted relative to the generated output directory.

That means this command:

```bash
python cli/main.py generate --repo ./repo --out llmbom_output.json
```

writes:

```text
<repo>_outputs_<timestamp>/llmbom_output.json
```

## Main Generate Flow

`cmd_generate(args)` runs in this order:

1. Convert feature flags into booleans:
   - transitive extraction is enabled unless `--no-transitive` is used.
   - notebook cell extraction is enabled unless `--no-notebook-cells` is used.
2. Create or resolve the output directory.
3. Resolve LLMBOM, SBOM, CVE input, and CVE output paths.
4. Instantiate `LLMBOMOrchestrator(args.repo)`.
5. Call `orchestrator.run(...)`.
6. Export the returned graph using `GraphExporter.export(...)`.
7. If `--with-sbom` or `--with-cve` is present, run the Gauntlet SBOM pipeline.
8. If `--with-cve` is present, normalize the SBOM and run CVE processing.

## Error Behavior

The LLMBOM graph generation phase is tolerant internally: many extractors catch
exceptions and continue. The optional SBOM and CVE phases are stricter at the
CLI boundary:

- If Gauntlet cannot be found or fails, the CLI prints an error and exits with
  status `1`.
- If the CVE pipeline fails, the CLI prints an error and exits with status `1`.

This design keeps the base static graph generator resilient while making
optional pipeline failures visible.

## Diff Command

`cmd_diff(args)` compares two LLMBOM JSON files:

```bash
python cli/main.py diff old.json new.json --out changes.json
```

It validates both files exist, calls `DiffExporter.compare_files(...)`, writes
the diff JSON, and prints a summary of added, removed, and changed nodes/edges.

