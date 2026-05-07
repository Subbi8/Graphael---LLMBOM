"""AST-backed pipeline extractor.

Detects training/pipeline patterns like `train()` calls, `save_pretrained`
and config file references. Produces `SCRIPT` and `CONFIG` nodes and
connects them to `MODEL` nodes when possible.
"""

import ast
import os

from llmbom.extractors.base_extractor import BaseExtractor
from llmbom.parsers.python_parser import extract_models, extract_datasets
from llmbom.core.schema import NodeType


class PipelineExtractor(BaseExtractor):
    def extract(self, file_path, builder):
        if not file_path.endswith(".py"):
            return

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            tree = ast.parse(content, filename=file_path)

            class Visitor(ast.NodeVisitor):
                def __init__(self):
                    self.has_train = False
                    self.save_calls = []
                    self.config_files = set()

                def visit_Call(self, node: ast.Call):
                    fname = ""
                    if isinstance(node.func, ast.Attribute):
                        fname = node.func.attr
                    elif isinstance(node.func, ast.Name):
                        fname = node.func.id

                    if fname in ("train", "fit"):
                        self.has_train = True

                    if fname in ("save_pretrained", "save_model"):
                        self.save_calls.append(fname)

                    # collect string constants that look like config files
                    for a in node.args:
                        if isinstance(a, ast.Constant) and isinstance(a.value, str):
                            if a.value.endswith((".json", ".yaml", ".yml")):
                                self.config_files.add(a.value)
                    for kw in getattr(node, "keywords", []):
                        v = kw.value
                        if isinstance(v, ast.Constant) and isinstance(v.value, str):
                            if v.value.endswith((".json", ".yaml", ".yml")):
                                self.config_files.add(v.value)

                    self.generic_visit(node)

            vis = Visitor()
            vis.visit(tree)

            if not (vis.has_train or vis.save_calls or vis.config_files):
                return

            script_name = os.path.relpath(file_path)
            script_id = builder.add_script(script_name)

            # add config nodes
            for cfg in vis.config_files:
                cfg_id = builder.add_config(cfg)
                builder.link_configures(script_id, cfg_id)

            # link saves to models if models are declared in the file
            models = extract_models(file_path)
            datasets = extract_datasets(file_path)

            model_unknown_count = sum(1 for name in models if name == "<unknown>")
            dataset_unknown_count = sum(1 for name in datasets if name == "<unknown>")
            if model_unknown_count:
                builder.unresolved_model_refs += model_unknown_count
            if dataset_unknown_count:
                builder.unresolved_dataset_refs += dataset_unknown_count
            models = [m for m in models if m != "<unknown>"]
            datasets = [d for d in datasets if d != "<unknown>"]

            if vis.save_calls:
                for m in models:
                    model_id = builder.graph.registry._index.get((NodeType.MODEL, m))
                    if not model_id:
                        model_id = builder.add_model(m)
                    builder.link_saves(script_id, model_id)

            # if training detected, link models -> datasets
            if vis.has_train and models and datasets:
                for m in models:
                    model_id = builder.graph.registry._index.get((NodeType.MODEL, m))
                    if not model_id:
                        model_id = builder.add_model(m)
                    for ds in datasets:
                        ds_id = builder.graph.registry._index.get((NodeType.DATASET, ds))
                        if not ds_id:
                            ds_id = builder.add_dataset(ds)
                        builder.link_trained_on(model_id, ds_id)

        except Exception:
            pass
