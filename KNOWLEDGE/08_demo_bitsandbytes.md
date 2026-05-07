# Demo Output: `bitsandbytes-main_outputs_20260430_222857`

This folder is a good end-to-end demo artifact because it shows all major
pipeline stages:

- LLMBOM source graph generation
- SBOM package extraction
- CVE input normalization
- advisory enrichment
- exploit-enhanced intermediate output
- first optimal recommendation output
- recursive final CVE output
- detailed and stats reports

## Files in the Demo Folder

```text
cve_input.json
cve_output.json
cve_output_detailed_report.json
cve_output_enriched_input.json
cve_output_enrichment_stats.json
cve_output_first_optimal.json
cve_output_stats.json
cve_output_with_exploits.json
llmbom_output.json
sbom_output.json
```

## LLMBOM Graph Summary

`llmbom_output.json` contains the static source graph.

Observed demo counts:

- 77 `SCRIPT` nodes
- 71 `LIBRARY` nodes
- 310 edges
- 35 stdlib library nodes
- 36 non-stdlib or internal library-like nodes

This demonstrates that LLMBOM can inspect a real AI/ML repository and produce a
source-level graph of scripts and library relationships.

Example script metadata includes:

- normalized source path
- line count
- SHA256 hash
- language

This is useful for auditability because findings can be tied back to exact
repository files.

## SBOM Summary

`sbom_output.json` contains 6 package components in the demo:

- `scikit-build-core`
- `setuptools`
- `trove-classifiers`
- `torch`
- `numpy`
- `packaging`

These are extracted from package/build metadata, not from import edges alone.

This is why the SBOM component count is smaller than the LLMBOM library node
count. They are different views:

- LLMBOM graph shows source-level imports and modules.
- SBOM output shows package metadata suitable for CVE processing.

## CVE Summary

`cve_output.json` processes all 6 SBOM packages.

Observed demo counts:

- 6 packages processed
- 3 packages with vulnerabilities
- 13 total vulnerability findings

Packages with findings:

- `setuptools`: 1 finding
- `torch`: 8 findings
- `numpy`: 4 findings

Packages without findings:

- `scikit-build-core`
- `trove-classifiers`
- `packaging`

## Recommendations in the Demo

The final output includes recommendation fields such as:

- `setuptools` -> `78.1.1`
- `torch` -> `2.8.0`
- `numpy` -> `1.22`

These recommendations are derived from advisory/fixed-version metadata and the
CVE optimizer.

## Enrichment Stats

`cve_output_enrichment_stats.json` records:

- 1 package skipped because of missing concrete version
- 5 OSV queries
- 2 NVD queries
- 3 packages enriched
- 2 packages without findings
- 6 total packages
- 3 packages with vulnerabilities

This file is important for demo credibility because it shows the lookup process
and not just the final result.

## How to Explain This Demo

A concise demo narration:

```text
This run analyzes bitsandbytes statically. First, LLMBOM builds a graph of 77
scripts, 71 library nodes, and 310 dependency edges from repository evidence.
Then the SBOM stage extracts declared package/build components from manifests.
Finally, the CVE pipeline enriches those package components with advisory data
and recommends remediation versions. The tool does not execute bitsandbytes;
all findings are tied to repository-visible evidence.
```

## Key Caveat to Say Out Loud

Some versions are ranges, such as:

```text
torch >=2.3,<3
numpy >=1.17
```

That means the demo should be described as static exposure analysis over
declared ranges. It is not proof that a specific runtime environment installed
one exact vulnerable version.

This caveat makes the tool more credible, not weaker.

