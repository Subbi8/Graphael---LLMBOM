# Optional SBOM Pipeline

The SBOM stage is optional and is triggered by either:

```bash
--with-sbom
```

or:

```bash
--with-cve
```

`--with-cve` implies SBOM generation because the CVE pipeline consumes a
package list derived from SBOM data.

## Why There Are Two Views

LLMBOM and SBOM output answer related but different questions.

LLMBOM graph:

- source-level imports
- scripts and notebooks
- config-like AI artifacts
- static dependency edges
- code evidence

SBOM output:

- package components from manifests/build metadata
- versions or version ranges when available
- package categories such as runtime requirements or build requirements
- file provenance for package declarations

The LLMBOM graph may contain many more library nodes than the SBOM because
source imports often include stdlib modules, internal modules, local modules,
and packages with no concrete version in manifests.

The SBOM may contain fewer but more package-manager-oriented components, which
are better suited for CVE enrichment.

## Gauntlet Path Detection

`_detect_gauntlet_path()` locates `gauntlet-sbom-universal-generator`.

It checks:

1. the user-provided `--gauntlet-path`
2. `../gauntlet-sbom-universal-generator` relative to `cli/main.py`
3. `gauntlet-sbom-universal-generator` under the current working directory
4. `~/gauntlet-sbom-universal-generator`

It expects to find:

```text
main.py
```

inside the Gauntlet directory.

If Gauntlet cannot be found, SBOM generation fails and the CLI exits.

## Language Detection

If `--language` is not supplied, `_detect_language_from_repo()` infers a
primary language from repository files.

Dependency/build file indicators include:

- `.csproj`, `.fsproj`, `.nuspec` -> `dotnet`
- `composer.json`, `composer.lock` -> `php`
- `package.json`, lockfiles -> `javascript`
- `requirements.txt`, `setup.py`, `pyproject.toml`, `Pipfile` -> `python`
- `CMakeLists.txt`, `Makefile` -> `cpp`

If no manifest indicators are found, it falls back to source extensions such
as `.py`, `.js`, `.ts`, `.cs`, `.cpp`, and `.php`.

If nothing can be detected, it defaults to:

```text
python
```

## Running Gauntlet

`_run_gauntlet_sbom_generator()` builds this subprocess command:

```text
python <gauntlet_path>/main.py <repo_path> <language>
```

The subprocess runs with:

```text
cwd = gauntlet_path
```

Gauntlet writes its own category outputs under:

```text
<gauntlet_path>/result/<repo_name>/
```

The LLMBOM CLI then reads these generated category files.

## Merging Gauntlet Category Files

Gauntlet can create multiple files ending in:

```text
_sbom.json
```

For example, a Python project may produce separate files for:

- runtime requirements
- build requirements

`_merge_gauntlet_sbom_files()` loads all discovered category SBOM files,
collects their `components`, and adds:

```json
{
  "source_sbom": "<category_name>"
}
```

when missing.

It deduplicates components by:

```text
lowercase name
version
publisher
type
file
```

The merged result has this shape:

```json
{
  "components": []
}
```

It is saved to `sbom_output.json` by default.

## SBOM Output Interpretation

The SBOM output is repository-declared package evidence. It should be described
as static package metadata, not as a resolved installed environment.

For version ranges such as:

```text
torch >=2.3,<3
```

the tool knows what the repository allows or declares. It does not prove the
exact version installed in a runtime environment.

