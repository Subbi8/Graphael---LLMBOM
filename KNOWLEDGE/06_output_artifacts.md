# Output Artifacts

The full pipeline can generate several JSON files in the output directory.
The exact files depend on which flags are used.

## Base LLMBOM Output

Generated when running:

```bash
python cli/main.py generate --repo <repo>
```

Default file:

```text
llmbom_output.json
```

Shape:

```json
{
  "nodes": [],
  "edges": []
}
```

Node fields:

- `id`: deterministic SHA256 ID based on type and name.
- `type`: `SCRIPT`, `LIBRARY`, or `CONFIG`.
- `name`: normalized component name or path.
- `metadata`: optional static metadata.

Edge fields:

- `source`: source node ID.
- `target`: target node ID.
- `type`: relationship type such as `DEPENDS_ON` or `CONTAINS`.

## Common Node Types

`SCRIPT`:

- source file
- notebook cell
- code-bearing artifact

`LIBRARY`:

- imported package/module
- dependency from manifest/lockfile
- JavaScript/npm package

`CONFIG`:

- model reference
- dataset reference
- notebook parent
- configuration-like artifact

## Common Metadata Fields

For scripts:

- `file_size_bytes`
- `line_count`
- `sha256`
- `language`
- `file_path_normalized`
- notebook cell fields when applicable

For libraries:

- `is_stdlib`
- `import_count`
- `is_transitive`
- `source_lockfile`
- `is_internal`
- language/package-manager hints such as `is_npm_package`

## SBOM Output

Generated when using:

```bash
--with-sbom
```

or:

```bash
--with-cve
```

Default file:

```text
sbom_output.json
```

Shape:

```json
{
  "components": []
}
```

Each component may include:

- `name`
- `version`
- `publisher`
- `type`
- `file`
- `source_sbom`

This file represents package declaration evidence extracted by the SBOM stage.

## CVE Input

Generated when using:

```bash
--with-cve
```

Default file:

```text
cve_input.json
```

This is the normalized package list consumed by the CVE pipeline.

## CVE Enriched Input

Default file:

```text
cve_output_enriched_input.json
```

This file contains the original normalized packages plus advisory lookup
results from OSV/NVD enrichment.

## CVE Enrichment Stats

Default file:

```text
cve_output_enrichment_stats.json
```

This file summarizes lookup behavior, such as:

- packages skipped because of missing concrete versions
- OSV query count
- NVD query count
- packages enriched
- packages without findings
- total packages
- packages with vulnerabilities

## Exploit-Enhanced CVE Output

Default file:

```text
cve_output_with_exploits.json
```

This intermediate file is produced by the first CVE analysis module. It adds
exploit-related fields used by downstream recommendation logic.

## First Optimal CVE Output

Default file:

```text
cve_output_first_optimal.json
```

This intermediate file contains the first pass of version recommendations.

## Final CVE Output

Default file:

```text
cve_output.json
```

This is the final CVE result after recursive optimization. It contains each
package, advisory findings, exploitable flags, latest version information, and
recommended versions.

## Detailed CVE Report

Default file:

```text
cve_output_detailed_report.json
```

This report is produced by the recursive CVE optimizer. It records per-package
recommendations and optimization details.

## CVE Stats

Default file:

```text
cve_output_stats.json
```

This report summarizes recursive optimizer runtime behavior and configuration.

## Diff Output

Generated when running:

```bash
python cli/main.py diff old.json new.json --out llmbom_diff.json
```

It contains:

- added nodes
- removed nodes
- changed nodes
- added edges
- removed edges
- changed edges
- summary counts

