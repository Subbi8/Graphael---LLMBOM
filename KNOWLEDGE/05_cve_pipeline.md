# Optional CVE Pipeline

The CVE stage is triggered by:

```bash
--with-cve
```

This stage consumes SBOM package components, normalizes them into the shape
expected by the CVE tooling, enriches packages with advisory data, runs exploit
enhancement, and then runs recursive version recommendation logic.

## Stage 1: Normalize SBOM for CVE Input

`cmd_generate()` calls:

```python
cve_input_path = _prepare_cve_input(sbom_path, cve_input_out)
```

`_prepare_cve_input()` loads the SBOM JSON and calls:

```python
normalize_sbom_for_cve(sbom_data)
```

from:

```text
llmbom/utils/sbom_adapter.py
```

The normalized CVE input is a list of package dictionaries:

```json
[
  {
    "package_name": "torch",
    "package_version": ">=2.3,<3",
    "vendor": "",
    "purl": "",
    "type": "requires",
    "repo_name": "",
    "project_type": "python",
    "file": "pyproject.toml",
    "source_sbom": "python",
    "vulnerabilities": [],
    "vulnerabilties": []
  }
]
```

The duplicated `vulnerabilties` field is preserved for compatibility with
existing CVE modules that use the misspelled key.

## Stage 2: Load CVE Modules

`run_cve_pipeline()` lives in:

```text
llmbom/utils/cve_pipeline.py
```

If no `cve_dir` is supplied, it resolves:

```text
CVE/
```

from the repository root and imports:

- `first_optimal_july`
- `recursive_july`

These modules perform the existing vulnerability analysis and recommendation
logic.

## Stage 3: Enrich Input with Advisory Data

Before the optimization modules run, `run_cve_pipeline()` calls:

```python
enrich_cve_input(input_file, enriched_input, stats_file=enrichment_stats)
```

from:

```text
llmbom/utils/cve_enricher.py
```

The enricher uses:

- OSV API for package ecosystem advisory lookups.
- NVD API as a fallback keyword lookup.

It detects the ecosystem from fields such as:

- `purl`
- `project_type`
- `source_category`
- `source_sbom`
- `type`
- `vendor`

For example:

```text
python -> PyPI
javascript -> npm
php -> Packagist
dotnet -> NuGet
```

## Version Cleaning

OSV expects a concrete version. `_clean_version()` strips leading operators
such as:

```text
>=
<=
~
^
!
```

This means a repository-declared range such as:

```text
>=2.3,<3
```

is approximated statically for lookup purposes. The original package version
string is still retained in the package object.

This is important for honest reporting: the result indicates possible exposure
from a declared range, not proof of the exact installed runtime version.

## Advisory Normalization

OSV findings are normalized into fields such as:

- `cve_id`
- `source_id`
- `severity`
- `score`
- `summary`
- `description`
- `fixed_location`
- `references`
- `source`

NVD findings are normalized into a similar shape.

Findings are deduplicated by CVE/source ID and sorted deterministically.

## Stage 4: First Optimal Analysis

After enrichment, `run_cve_pipeline()` instantiates:

```python
first_optimal_july.VulnerabilityAnalysisTool()
```

and calls:

```python
tool.run_analysis(...)
```

This creates:

- an exploit-enhanced file
- a first optimal recommendation file

The output file names are derived from the final CVE output stem. For default
`cve_output.json`, the intermediate files are:

```text
cve_output_enriched_input.json
cve_output_enrichment_stats.json
cve_output_with_exploits.json
cve_output_first_optimal.json
```

## Stage 5: Recursive Optimization

If `allow_recursive=True`, the pipeline instantiates:

```python
recursive_july.RecursiveCveOptimizer()
```

and calls:

```python
optimizer.main(
    input_file=exploit_output,
    first_optimal_file=first_optimal_output,
    output_file=final_cve_output,
)
```

If the optimizer exits non-zero, `run_cve_pipeline()` raises an error. The CLI
catches that error and exits with status `1`.

## Final Result Returned to CLI

`run_cve_pipeline()` returns a dictionary containing paths to:

- `enriched_input`
- `enrichment_stats`
- `first_optimal`
- `exploit_enhanced`
- `output_file`

The CLI prints the final output path and intermediate paths.

## Important Security Interpretation

The CVE stage is strongest when described as:

```text
static vulnerability exposure analysis over repository-declared package data
```

It should not be described as proving the exact runtime vulnerability state
unless the repository includes concrete lockfile versions and those versions are
used by the pipeline.

