# TOOL DOCUMENTATION

# Graphale: Static AI/ML Supply-Chain Intelligence Tool

## 1. Description

Graphael, is a static AI/ML supply-chain intelligence tool. It analyzes source repositories without executing target project code and produces structured evidence about scripts, libraries, notebooks, model references, dataset references, package metadata, and vulnerability exposure.

The tool is designed for security researchers, AppSec teams, DevSecOps teams,
AI platform teams, and compliance reviewers who need to inspect AI/ML
repositories safely. Graphael focuses on repository-visible evidence: source
imports, manifests, notebooks, configuration-like artifacts, build metadata,
and package declarations.

The user-facing command is launched through:

```text
cli/main.py
```

However, `cli/main.py` is only the command-line coordinator. The complete
product pipeline is much larger and combines three major subsystems:

1. The Graphael graph engine, which scans source files and forms the deterministic
   dependency graph.
2. The SBOM extraction subsystem, which extracts package-oriented component
   evidence from manifests, build files, and mixed-language repository
   metadata.
3. The CVE enrichment and recommendation subsystem, which normalizes SBOM
   components, queries advisory sources, enriches findings, and produces
   remediation recommendations.

In other words, the main script connects the subsystems into one workflow; it
is not the entire product by itself.

A full run can produce:

- a deterministic source-level Graphael graph
- an optional package SBOM
- normalized CVE input
- advisory-enriched CVE output
- remediation recommendations
- detailed intermediate CVE reports
- diff reports between two Graphael snapshots

Graphael is intentionally static. It does not install dependencies, import target project modules, run project code, build the target repository, or inspect a live runtime environment. This design allows the tool to be used on untrusted or unfamiliar repositories with lower execution risk.

## 2. Key Features

### 2.1 Static Analysis by Design

Graphael reads repository files and extracts evidence without executing the
target codebase. This helps reviewers analyze unknown repositories without
triggering arbitrary code execution, dependency installation, or runtime side
effects.

### 2.2 End-to-End Pipeline Architecture

Graphael should be understood as an end-to-end pipeline, not as a single script.
The CLI entry point launches and coordinates the workflow, but the actual work
is distributed across dedicated subsystems.

The full architecture is:

```text
CLI coordinator
  -> LLMBOM static graph engine
  -> SBOM extraction subsystem
  -> CVE enrichment and recommendation subsystem
  -> output artifacts
```

The LLMBOM graph engine is responsible for source-level repository analysis. It
is backed by:

- repository scanning code
- graph builder code
- deterministic graph storage
- node and edge schema definitions
- metadata enrichment code
- Python, JavaScript, TypeScript, notebook, manifest, and AI/ML extractors

The SBOM extraction subsystem is responsible for package-level component
evidence. It handles dependency/build metadata and can operate on repositories
that are not cleanly structured around one ecosystem.

The CVE subsystem is responsible for vulnerability intelligence. It normalizes
SBOM components, enriches them with advisory data, and runs recommendation logic
to produce final vulnerability and remediation outputs.

This layered architecture is one of the practical strengths of the tool:

- the graph layer explains source-level dependency relationships.
- the SBOM layer explains package declaration evidence.
- the CVE layer explains vulnerability exposure and remediation targets.

Together, these layers give a fuller supply-chain picture than a flat package
list alone.

### 2.3 Source-Level Dependency Graph

The core LLMBOM output is a graph with:

- `SCRIPT` nodes for source files and notebook cells
- `LIBRARY` nodes for imported or declared libraries
- `CONFIG` nodes for model, dataset, notebook, and configuration-like artifacts
- `DEPENDS_ON` edges from scripts to libraries
- `CONTAINS` edges from notebooks to notebook cells

The graph is exported as deterministic JSON. Node IDs are generated from the
node type and name using SHA256, and nodes/edges are sorted before export.

### 2.4 Python Import Analysis

Graphael uses Python's `ast` module to parse `.py` files and extract top-level
imports. For example:

```python
import torch.nn
from transformers import AutoModel
```

is represented as dependencies on:

```text
torch
transformers
```

### 2.5 JavaScript and TypeScript Import Analysis

Graphael supports static dependency extraction for:

- `.js`
- `.ts`
- `.mjs`
- `.cjs`
- `.jsx`
- `.tsx`

It detects:

- ES module imports
- CommonJS `require(...)`
- dynamic `import(...)`

It filters Node.js built-in modules and normalizes package names such as
scoped npm packages.

### 2.6 Jupyter Notebook Awareness

Graphael parses `.ipynb` notebooks as JSON. It creates notebook parent nodes and
per-cell script nodes for code cells. This is useful for AI/ML repositories,
where important training, inference, or experimentation logic may live inside
notebooks rather than normal source files.

### 2.7 Static Manifest and Lockfile Parsing

The transitive dependency extractor parses dependency evidence from files such
as:

- `requirements.txt`
- `requirements-dev.txt`
- `requirements/*.txt`
- `Pipfile.lock`
- `poetry.lock`
- `setup.cfg`
- `pyproject.toml`
- `pip-requirements.txt`

These files are parsed statically using Python standard library functionality
or text/regex logic. The tool does not install packages to resolve dependency
trees.

### 2.8 AI/ML-Specific Evidence

Graphael is built for AI/ML repositories and includes detectors for evidence such
as:

- model references
- dataset references
- fine-tuning signals
- quantization usage
- ML pipeline usage
- vector/API infrastructure hints
- notebooks and cell-level code structure

Models and datasets are represented structurally as `CONFIG` nodes with
metadata such as `artifact_type`.

### 2.9 Metadata Enrichment

Graphael enriches graph nodes with deterministic metadata.

For script nodes, metadata may include:

- file size
- line count
- SHA256 file hash
- language
- normalized file path

For library nodes, metadata may include:

- standard-library classification
- import count
- transitive/declaration status
- source lockfile
- internal-module hints

### 2.10 Optional SBOM Generation

When the `--with-sbom` flag is used, Graphael integrates with the bundled or
configured SBOM extraction engine. This stage extracts package-oriented SBOM
components from repository metadata, build files, manifests, and dependency
declarations.

The SBOM stage produces a merged output file:

```text
sbom_output.json
```

This SBOM view is package-oriented and complements the source-level Graphael
graph.

### 2.11 Optimized for Unstructured Repositories

Many real-world AI/ML and systems repositories are not clean single-language
projects. They may contain Python scripts, C/C++ extensions, JavaScript tooling,
PHP services, notebooks, build scripts, generated files, and multiple manifest
styles in the same repository.

Graphael is useful for these unstructured repositories because it does not depend
on one perfect project layout. It scans the repository for evidence and lets
each analysis layer extract what it understands.

Practical advantages:

- It can still produce useful output when the repository has no single standard
  package manager entry point.
- It can combine source-level imports with package metadata from manifests.
- It can handle mixed codebases where AI/ML code sits beside native extensions,
  scripts, notebooks, and service code.
- It avoids requiring a successful build before analysis.
- It avoids requiring a fully reproducible environment before generating
  supply-chain evidence.
- It can analyze third-party or unfamiliar repositories before they are trusted.

This makes Graphael especially useful for security review, vendor intake,
open-source project assessment, and AI/ML dependency audits.

### 2.12 Multi-Language SBOM Coverage

The optional SBOM stage is designed for repositories that include multiple
language ecosystems. Depending on the available repository evidence, it can
process language modes such as:

- Python
- JavaScript
- TypeScript
- C
- C++
- C#
- .NET
- PHP
- Node.js

This matters because AI/ML repositories are frequently hybrid systems. For
example, a Python ML project may include C/C++ kernels, CUDA-adjacent native
code, JavaScript dashboards, shell/build logic, and package metadata in the
same tree.

Graphael's practical value is that it brings these signals into one workflow:

```text
source graph -> package SBOM -> CVE exposure -> remediation guidance
```

Instead of forcing users to manually stitch together separate outputs, the tool
creates a single output folder with the major evidence artifacts needed for
review.

### 2.13 Optional CVE Enrichment

When the `--with-cve` flag is used, Graphael generates an SBOM, normalizes the
SBOM components into CVE input, and enriches packages with vulnerability
advisory data.

The CVE enrichment stage uses public advisory APIs:

- OSV API
- NVD API

The CVE pipeline can produce:

- `cve_input.json`
- `cve_output_enriched_input.json`
- `cve_output_enrichment_stats.json`
- `cve_output_with_exploits.json`
- `cve_output_first_optimal.json`
- `cve_output.json`
- `cve_output_detailed_report.json`
- `cve_output_stats.json`

Important interpretation: Graphael reports static vulnerability exposure based on
repository-declared package data. If a repository declares a version range such
as `torch >=2.3,<3`, Graphael should be understood as identifying possible
exposure from the declared range, not proving the exact installed runtime
version.

### 2.14 Diff Mode

Graphael can compare two generated graph files:

```bash
python cli/main.py diff old.json new.json --out Graphael_diff.json
```

The diff report includes:

- added nodes
- removed nodes
- changed nodes
- added edges
- removed edges
- changed edges
- summary statistics

This supports audit workflows and change tracking between repository versions.

## 3. License

The current workspace does not contain a root `LICENSE` file. Before public
release or conference submission, the project should add a clear license file.

Recommended options:

- Apache License 2.0 for permissive open-source use with explicit patent grant
- MIT License for a short permissive license

Until a license file is added, external users should treat the code as
unlicensed and should not assume redistribution rights.

## 4. Changelog

### Current Prototype Capabilities

- command-line coordinator for the full pipeline
- Graphael graph engine backed by scanner, builder, graph schema, extractors, and
  metadata enrichment modules
- SBOM extraction subsystem for package-level component evidence
- CVE enrichment and recommendation subsystem backed by CVE modules
- Static Graphael graph generation
- Python import extraction
- JavaScript/TypeScript import extraction
- Jupyter notebook structure extraction
- static manifest and lockfile parsing
- metadata enrichment for script and library nodes
- deterministic graph export
- optional SBOM generation
- optional CVE enrichment pipeline
- recursive CVE recommendation output
- Graphael graph diff mode

### Suggested Changelog for Public Release

Before submission or publication, the project should include a dedicated
`CHANGELOG.md` file. A suggested first entry:

```text
## 0.1.0 - Initial public prototype

- Added static Graphael graph generation.
- Added Python, JavaScript, TypeScript, and notebook extractors.
- Added static manifest parsing for Python dependency files.
- Added deterministic JSON export.
- Added optional SBOM generation for package-oriented repository evidence.
- Added optional CVE enrichment and recommendation pipeline.
- Added end-to-end CLI coordination across graph, SBOM, and CVE subsystems.
- Added diff mode for comparing two Graphael graph outputs.
```

## 5. Installation

### 5.1 Requirements

Graphael is a Python-based tool.

Recommended environment:

- Python 3.11 or newer
- Windows, Linux, or macOS
- network access when using CVE enrichment
- configured SBOM extraction support when using `--with-sbom` or `--with-cve`
- local `CVE/` module directory when using `--with-cve`

The base Graphael graph generation path is designed to use local static analysis.
The CVE enrichment stage requires network access to advisory APIs unless
advisory data is provided through a future offline cache.

### 5.2 Supported Platforms

The current development environment is Windows PowerShell. The code uses Python
standard library functionality for most core operations and should be portable
to Linux and macOS with normal Python path and shell adjustments.

Recommended supported platforms for the current prototype:

- Windows 10/11
- Linux
- macOS

### 5.3 Supported Languages and File Types

Current static extraction support includes:

- Python source files: `.py`
- JavaScript files: `.js`, `.mjs`, `.cjs`, `.jsx`
- TypeScript files: `.ts`, `.tsx`
- Jupyter notebooks: `.ipynb`
- Python dependency files:
  - `requirements.txt`
  - `requirements-dev.txt`
  - `requirements/*.txt`
  - `Pipfile.lock`
  - `poetry.lock`
  - `setup.cfg`
  - `pyproject.toml`
  - `pip-requirements.txt`

The optional SBOM stage can detect or accept language modes such as:

- `python`
- `javascript`
- `typescript`
- `c`
- `cpp`
- `c++`
- `csharp`
- `dotnet`
- `php`
- `nodejs`

Actual SBOM extraction depends on the available repository evidence and the
configured SBOM extraction capabilities for the target language.

### 5.4 Setup from Source

From the repository root:

```bash
python cli/main.py --help
```

If the help text appears, the CLI coordinator is available. This confirms that
the user-facing launcher can be invoked; the full pipeline still depends on the
Graphael graph modules and, when enabled, the SBOM and CVE subsystems.

For best public-release experience, the project should eventually provide:

```bash
pip install .
Graphael --help
```

At the current prototype stage, the direct source invocation is:

```bash
python cli/main.py <command> [options]
```

This command should be understood as the launcher for the integrated pipeline,
not as the only code involved in analysis.

## 6. Usage

## 6.1 Show Help

```bash
python cli/main.py --help
```

Expected command groups:

```text
generate
diff
```

## 6.2 Generate Graphael Graph

```bash
python cli/main.py generate --repo /path/to/repository
```

This creates a timestamped output folder and writes:

```text
Graphael_output.json
```

The output contains a graph:

```json
{
  "nodes": [],
  "edges": []
}
```

## 6.3 Generate Graphael Graph into a Specific Output Directory

```bash
python cli/main.py generate --repo /path/to/repository --output-dir output_folder
```

This writes outputs into:

```text
output_folder/
```

## 6.4 Generate Graphael with Custom Output File Name

```bash
python cli/main.py generate --repo /path/to/repository --out my_Graphael.json
```

If `my_Graphael.json` is a relative path, it is resolved inside the output
directory.

## 6.5 Disable Transitive Manifest Parsing

```bash
python cli/main.py generate --repo /path/to/repository --no-transitive
```

This skips project-level dependency discovery from lockfiles and manifest-like
files.

## 6.6 Disable Notebook Cell Extraction

```bash
python cli/main.py generate --repo /path/to/repository --no-notebook-cells
```

This prevents per-cell notebook nodes from being created.

## 6.7 Hide or Mark Internal Modules

```bash
python cli/main.py generate --repo /path/to/repository --hide-internal
```

The current graph builder preserves nodes and represents internal status as
metadata where detected.

## 6.8 Generate SBOM

```bash
python cli/main.py generate --repo /path/to/repository --with-sbom
```

This generates:

```text
Graphael_output.json
sbom_output.json
```

The SBOM output contains package components extracted from repository metadata.

## 6.9 Generate SBOM with Explicit Language

```bash
python cli/main.py generate --repo /path/to/repository --with-sbom --language python
```

This bypasses automatic language detection for the SBOM stage. It is useful
when a repository contains multiple languages and the user wants to force a
specific package ecosystem view.

## 6.10 Run Full Graphael + SBOM + CVE Pipeline

```bash
python cli/main.py generate --repo /path/to/repository --with-cve
```

This generates the Graphael graph, SBOM, normalized CVE input, advisory-enriched
intermediate files, and final CVE output.

Typical output files:

```text
Graphael_output.json
sbom_output.json
cve_input.json
cve_output_enriched_input.json
cve_output_enrichment_stats.json
cve_output_with_exploits.json
cve_output_first_optimal.json
cve_output.json
cve_output_detailed_report.json
cve_output_stats.json
```

## 6.11 Full Pipeline with Explicit Output Directory

```bash
python cli/main.py generate --repo /path/to/repository --output-dir demo_outputs --with-sbom --with-cve
```

This is the recommended demo form because all artifacts are written to a known
folder.

## 6.12 Compare Two Graphael Outputs

```bash
python cli/main.py diff old_Graphael.json new_Graphael.json --out Graphael_diff.json
```

This writes a JSON diff containing node and edge changes.

## 7. Parameters

### 7.1 `generate` Parameters

| Parameter | Required | Description |
| --- | --- | --- |
| `--repo` | yes | Path to the repository to analyze. |
| `--output-dir` | no | Directory for generated files. Defaults to timestamped repo output folder. |
| `--out` | no | Graphael graph output file. Defaults to `Graphael_output.json`. |
| `--no-transitive` | no | Disable static manifest/lockfile dependency extraction. |
| `--no-notebook-cells` | no | Disable per-cell notebook extraction. |
| `--hide-internal` | no | Marks or handles internal modules according to current builder behavior. |
| `--with-sbom` | no | Run SBOM generation after Graphael graph generation. |
| `--with-cve` | no | Run SBOM generation and CVE enrichment pipeline. |
| `--language` | no | Language mode for SBOM generation. |
| `--sbom-out` | no | SBOM output file. Defaults to `sbom_output.json`. |
| `--cve-input` | no | Normalized CVE input file. Defaults to `cve_input.json`. |
| `--cve-out` | no | Final CVE output file. Defaults to `cve_output.json`. |

### 7.2 `diff` Parameters

| Parameter | Required | Description |
| --- | --- | --- |
| `old` | yes | Original Graphael JSON file. |
| `new` | yes | New Graphael JSON file. |
| `--out` | no | Diff output file. Defaults to `Graphael_diff.json`. |

## 8. Example Demonstration

The repository contains a demo output folder:

```text
bitsandbytes-main_outputs_20260430_222857
```

This folder demonstrates the full pipeline on an AI/ML repository.

Observed output summary:

- 77 script nodes
- 71 library nodes
- 310 dependency edges
- 6 SBOM package components
- 3 packages with vulnerability findings
- 13 total CVE findings

Packages with findings in the demo include:

- `setuptools`
- `torch`
- `numpy`

Example remediation recommendations include:

- `setuptools -> 78.1.1`
- `torch -> 2.8.0`
- `numpy -> 1.22`

The demo should be described as static exposure analysis. For version ranges,
the tool identifies package ranges with known advisory exposure rather than
claiming a confirmed installed runtime version.

## 9. Security Model and Limitations

Graphael is static and evidence-based. This is a deliberate design decision.

### What Graphael Can Reliably Claim

- A repository file imports a package/module.
- A manifest declares a dependency or version range.
- A notebook contains code cells.
- A dependency appears in the static graph.
- A package component is present in static SBOM evidence.
- A package version or range maps to known advisory exposure.
- A remediation recommendation is derived from advisory metadata.

### What Graphael Does Not Claim

- It does not prove the exact production runtime environment.
- It does not prove optional dependencies are installed.
- It does not execute code to discover dynamic imports.
- It does not build or run the target repository.
- It does not guarantee exploitability in production.

This limitation is also a safety feature: Graphael can inspect untrusted
repositories without running their code.

## 10. Suggested Citation / Short Abstract

Graphael is a static AI/ML supply-chain intelligence tool that analyzes
repository-visible evidence to produce deterministic dependency graphs, package
SBOM output, and CVE exposure reports. It helps security teams inspect AI/ML
repositories without executing untrusted code, connecting source-level imports,
notebooks, manifests, package metadata, and vulnerability advisory data into
auditable JSON artifacts.
