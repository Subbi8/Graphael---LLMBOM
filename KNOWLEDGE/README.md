# LLMBOM Knowledge Base

This folder explains how the LLMBOM pipeline runs from the CLI entry point in
`cli/main.py` through graph generation, optional SBOM generation, optional CVE
analysis, and diffing.

The most important design decision is that the LLMBOM graph pipeline is static.
It reads repository evidence from files, source code, manifests, notebooks, and
configuration-like artifacts. It does not install dependencies, import target
project modules, run project code, or resolve a live runtime environment.

## Recommended Reading Order

1. `01_cli_entrypoint.md` explains how `cli/main.py` parses commands and
   chooses which pipeline to run.
2. `02_llmbom_graph_pipeline.md` explains the core LLMBOM scan, extraction,
   graph construction, and export path.
3. `03_static_extractors.md` explains what each extractor looks for and how it
   stays static.
4. `04_sbom_pipeline.md` explains the optional Gauntlet SBOM integration and
   how multiple SBOM category files are merged.
5. `05_cve_pipeline.md` explains CVE input normalization, enrichment, exploit
   enhancement, recursive optimization, and generated files.
6. `06_output_artifacts.md` explains the output directory and the meaning of
   each JSON artifact.
7. `07_design_tradeoffs.md` explains static-only behavior, what the tool can
   claim, and what it intentionally does not claim.
8. `08_demo_bitsandbytes.md` explains the demo output in
   `bitsandbytes-main_outputs_20260430_222857`.

## One-Command Mental Model

The full demo path is:

```bash
python cli/main.py generate --repo /path/to/repo --with-sbom --with-cve
```

At a high level this does:

```text
CLI args
  -> create output directory
  -> run LLMBOM static graph analysis
  -> write llmbom_output.json
  -> optionally run Gauntlet SBOM generator
  -> merge Gauntlet SBOM category files
  -> write sbom_output.json
  -> optionally normalize SBOM for CVE processing
  -> write cve_input.json
  -> enrich packages with OSV/NVD findings
  -> run CVE optimization modules
  -> write final and intermediate CVE JSON files
```

## Static Evidence Philosophy

LLMBOM should be described as an evidence-based static supply-chain
intelligence tool. The output is strongest when phrased as repository evidence:

- "This source file imports this package."
- "This manifest declares this dependency range."
- "This package range has known advisory exposure."
- "This version recommendation is derived from advisory metadata."

For version ranges, the CVE pipeline should be presented as possible exposure
from repository-declared ranges, not proof of the exact installed runtime state.

