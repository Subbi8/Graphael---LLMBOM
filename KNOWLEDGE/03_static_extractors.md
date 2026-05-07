# Static Extractors

Extractors are the part of LLMBOM that turns repository files into graph
evidence. They do not execute target project code. They inspect text, ASTs,
JSON, TOML-like content, lockfiles, and import statements.

## Dependency Extractor

File:

```text
llmbom/extractors/dependency_extractor.py
```

Responsibilities:

- parse `requirements.txt`
- parse Python imports from `.py` files
- create `SCRIPT` nodes for Python source files
- create `LIBRARY` nodes for imports
- create `DEPENDS_ON` edges from scripts to libraries

For Python source, it calls:

```python
extract_imports(file_path)
```

from `llmbom/parsers/python_parser.py`.

That parser uses Python's `ast` module. It detects:

- `import x`
- `import x.y`
- `from x import y`

It records only the top-level module name, so:

```python
import torch.nn
```

becomes:

```text
torch
```

This keeps dependency nodes package-oriented rather than symbol-oriented.

## Requirements Parsing

File:

```text
llmbom/parsers/requirements_parser.py
```

The basic requirements parser reads non-comment lines from `requirements.txt`
and strips `==` pinned versions. This is lightweight and static.

The more advanced transitive extractor handles more dependency file patterns.

## Transitive Extractor

File:

```text
llmbom/extractors/transitive_extractor.py
```

This extractor is project-level. It is called as:

```python
transitive_extractor.extract_transitive(project_root, builder, enable_transitive=True)
```

It looks for:

- `requirements.txt`
- `requirements-dev.txt`
- `requirements/*.txt`
- `Pipfile.lock`
- `poetry.lock`
- `setup.cfg`
- `pyproject.toml`
- `pip-requirements.txt`

It parses these files using stdlib-only logic:

- JSON parsing for `Pipfile.lock`
- `ConfigParser` for `setup.cfg`
- regex/text parsing for `poetry.lock` and `pyproject.toml`
- line parsing for requirements-style files

When it finds packages not already represented as library nodes, it creates new
`LIBRARY` nodes and marks them:

```json
{
  "is_transitive": true,
  "source_lockfile": "pyproject.toml",
  "is_stdlib": false,
  "import_count": 0
}
```

This is useful because it separates imported packages from declared or
lockfile-derived packages. A package with `import_count: 0` may still matter if
it is declared in project metadata.

## Notebook Extractor

File:

```text
llmbom/extractors/notebook_extractor.py
```

This extractor scans for `.ipynb` files and reads them as JSON. It creates:

- a notebook parent node as `CONFIG`
- a `SCRIPT` node for each code cell
- `CONTAINS` edges from the notebook node to cell script nodes

Cell script nodes receive metadata such as:

- `cell_index`
- `cell_type`
- `is_notebook_cell`
- `notebook_parent`
- `code_length`

The extractor includes a regex-based helper for extracting imports from cell
code. The current implementation records extracted imports in the returned
notebook info, while the graph relationship focus is the notebook-to-cell
structure.

## JavaScript/TypeScript Extractor

File:

```text
llmbom/extractors/js_ts_extractor.py
```

This extractor supports:

- `.js`
- `.ts`
- `.mjs`
- `.cjs`
- `.jsx`
- `.tsx`

It uses regex patterns to detect:

- ES module imports
- CommonJS `require(...)`
- dynamic `import(...)`

It normalizes package names:

- `lodash/map` becomes `lodash`
- `@scope/package/path` becomes `@scope/package`
- relative imports such as `./local/file` are skipped

It filters Node.js built-in modules such as `fs`, `path`, `crypto`, and
`node:fs`.

For non-builtin packages, it creates `LIBRARY` nodes and `DEPENDS_ON` edges.
Library nodes may receive metadata:

```json
{
  "is_npm_package": true,
  "language": "javascript"
}
```

## Model and Dataset Extractors

The Python parser includes static helpers for AI/ML signals:

- `extract_models(path)` finds string literal arguments to `from_pretrained`.
- `extract_datasets(path)` finds string literal arguments to `load_dataset`.

These detectors are useful for AI/ML supply-chain intelligence because model
and dataset references are not normal package dependencies. They are still
important external artifacts.

When model or dataset references are not statically resolvable, the
orchestrator tracks unresolved counts and records them in context results.

## Fine-Tune, Quantization, Pipeline, Tooling, and Infra Detectors

The orchestrator also runs specialized extractors for AI/ML workflow signals:

- fine-tuning methods
- quantization usage
- pipeline usage
- ML tooling
- vector/API infrastructure signals

These modules help LLMBOM go beyond a traditional package SBOM by exposing
source-level AI workflow evidence.

## Error Tolerance

Most extractors catch exceptions and continue. This is deliberate for static
analysis over arbitrary repositories:

- a malformed file should not kill the whole scan.
- one unsupported file should not prevent the graph from being generated.
- partial evidence is still useful if clearly represented.

