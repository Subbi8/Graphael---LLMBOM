# LLMBOM Graph Pipeline

The LLMBOM graph pipeline is the core static analysis path. It begins in
`cli/main.py` and delegates to `llmbom.engine.orchestrator.LLMBOMOrchestrator`.

## Pipeline Entry

`cmd_generate()` creates the orchestrator:

```python
orchestrator = LLMBOMOrchestrator(args.repo)
graph_data = orchestrator.run(...)
```

The orchestrator receives the target repository path and creates:

- `ScanContext`: stores project path, discovered files, and auxiliary results.
- `LLMBOMBuilder`: owns graph creation helpers and records nodes/edges.

## Project Scanning

`ProjectScanner.scan()` walks the repository with `os.walk()` and returns every
file path it sees.

Current behavior is intentionally simple:

```text
for every directory under repo:
  for every file:
    record absolute/relative filesystem path
```

The scanner itself does not filter aggressively. Filtering happens mostly in
extractors, where each extractor decides whether a file is relevant.

## Extractor Pass

The orchestrator creates a list of per-file extractors:

- `ModelExtractor`
- `DatasetExtractor`
- `DependencyExtractor`
- `PipelineExtractor`
- `QuantizationExtractor`
- `ToolingDetector`
- `JavaScriptTypeScriptExtractor`

For every scanned file, the orchestrator calls each extractor:

```text
for file_path in scanned_files:
  for extractor in extractors:
    extractor.extract(file_path, builder)
```

Each extractor can add nodes and edges through `LLMBOMBuilder`.

## Project-Level Detectors

After the per-file extractor pass, the orchestrator runs detectors that need a
project-level view:

- `InfraDetector`: looks for vector/API infrastructure signals.
- `FineTuneDetector`: looks for fine-tuning related methods.
- `TransitiveExtractor`: parses static dependency/lock/config files.
- `NotebookExtractor`: parses `.ipynb` files and creates notebook cell nodes.

These are separated because they scan the repository as a whole or need
context beyond one file at a time.

## Graph Builder

`LLMBOMBuilder` is the write interface used by extractors. It exposes helpers
such as:

- `add_script(name, metadata=None)`
- `add_library(name, metadata=None)`
- `add_model(name, metadata=None)`
- `add_dataset(name, metadata=None)`
- `add_config(name, metadata=None)`
- `link_depends_on(source_id, lib_id)`
- `link_contains(parent_id, child_id)`
- `link_configures(source_id, config_id)`
- `link_loads(source_id, target_id)`
- `link_saves(source_id, target_id)`

Models and datasets are represented as `CONFIG` nodes with metadata such as:

```json
{
  "artifact_type": "model"
}
```

or:

```json
{
  "artifact_type": "dataset"
}
```

This keeps the graph schema structural instead of adding many semantic node
types.

## Graph Storage

The actual graph lives in `LLMBOMGraph`.

It stores:

- `nodes`: dictionary of node ID to `LLMBOMNode`
- `edges`: list of `LLMBOMEdge`
- `_edge_set`: set used to prevent duplicate edges
- `registry`: node registry used to reuse existing nodes

## Deterministic Node IDs

When a node is created, its ID is:

```text
sha256(f"{node_type}:{name}")
```

This makes node IDs deterministic for identical type/name pairs. The same
repository evidence should produce stable node IDs across runs, as long as
names are normalized the same way.

## Edge Deduplication

Before adding an edge, `LLMBOMGraph.add_edge()` checks:

```text
(source_id, target_id, edge_type)
```

against `_edge_set`. If the edge already exists, it is ignored.

This avoids duplicate dependency relationships when multiple extractors observe
the same relationship.

## Metadata Enrichment

After extractors finish, the orchestrator runs `MetadataEnricher`.

For libraries, it adds:

- `is_stdlib`: whether the library is recognized as part of the Python stdlib.
- `import_count`: number of incoming `DEPENDS_ON` edges.

For scripts, it adds static file metadata:

- `file_size_bytes`
- `line_count`
- `sha256`
- `language`
- `file_path_normalized`

This metadata is derived from files and graph edges, not runtime execution.

## Internal Module Marking

`_mark_internal_modules()` identifies library nodes that likely refer to
internal project modules.

It builds a set of script filename stems and top-level package names, then marks
matching library nodes with:

```json
{
  "is_internal": true
}
```

The node is not removed. Internal status is represented as metadata.

## Serialization

`LLMBOMGraph.to_dict()` returns:

```json
{
  "nodes": [],
  "edges": []
}
```

Nodes are sorted by:

```text
(type, name)
```

Edges are sorted by:

```text
(source, target, type)
```

This deterministic ordering is useful for diffs, audits, and repeatable demo
outputs.

