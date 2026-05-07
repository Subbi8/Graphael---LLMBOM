# Design Tradeoffs and Claims

LLMBOM's strongest design choice is that the graph pipeline is static and
evidence-based. This is a conscious product decision, not a limitation to hide.

## What Static Means Here

The LLMBOM graph pipeline:

- reads files from the repository
- parses source code
- parses manifests and lock/config files
- parses notebooks as JSON
- hashes files
- records graph relationships

It does not:

- execute target repository code
- import target repository modules
- install dependencies
- build containers
- resolve a virtual environment
- run package manager commands for the target project
- infer runtime-only behavior that is not present in repository evidence

## Why Static-Only Is Valuable

Static analysis is useful for security review because it is safe against
untrusted repositories. A reviewer can scan suspicious code without running it.

Static-only behavior also helps with:

- deterministic outputs
- reproducible audits
- offline-friendly analysis for the LLMBOM graph stage
- low setup friction
- CI/CD review before code is deployed
- evidence trails based on files that can be versioned

## What LLMBOM Can Claim

Strong claims:

- The repository contains this source file.
- This source file imports this top-level module.
- This manifest declares this dependency or version range.
- This notebook contains these code cells.
- This dependency node has this import count in the static graph.
- This package component was present in static SBOM evidence.
- This declared package version/range maps to known advisories.
- This recommendation is derived from advisory/fixed-version metadata.

These claims are tied to repository evidence.

## What LLMBOM Should Not Overclaim

Avoid saying:

- "This exact vulnerable version is installed" unless the repo contains a
  concrete lockfile version and that is what the pipeline used.
- "This vulnerability is exploitable in production" unless runtime context or
  exploitability analysis supports that.
- "All dependencies are discovered" for dynamic imports, generated manifests,
  or runtime plugin loading.
- "The runtime environment is safe" because LLMBOM does not inspect the live
  environment.

## How to Phrase Version Range Findings

For a dependency like:

```text
torch >=2.3,<3
```

prefer:

```text
Repository metadata allows a torch version range with known advisory exposure.
The static recommendation is to use a version at or above the advisory-derived
fixed version.
```

Avoid:

```text
The project is definitely running a vulnerable torch version.
```

## LLMBOM vs Traditional SBOM

Traditional SBOM tools usually focus on package inventory. LLMBOM adds a
source-level graph view:

- which scripts import which packages
- where dependency edges originate
- which AI artifacts are referenced
- which notebooks and cells exist
- what files are responsible for evidence

The optional SBOM/CVE stage complements this by producing package-oriented
vulnerability triage.

## Best Product Positioning

The most defensible positioning is:

```text
LLMBOM is a static AI/ML supply-chain intelligence tool that combines
source-level dependency graphing with package SBOM extraction and CVE
enrichment. It helps reviewers understand repository-declared and
source-observed dependency exposure without executing untrusted code.
```

