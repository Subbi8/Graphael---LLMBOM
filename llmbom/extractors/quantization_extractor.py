"""AST-backed quantization extractor.

Detects common quantization usage patterns (imports like
``bitsandbytes`` or keyword arguments such as ``load_in_8bit=True``)
and records `QUANTIZATION` nodes linked to their parent models.
"""

import ast
from llmbom.extractors.base_extractor import BaseExtractor
from llmbom.parsers.python_parser import extract_models, extract_imports
from llmbom.core.schema import NodeType


class QuantizationExtractor(BaseExtractor):
    def extract(self, file_path, builder):
        if not file_path.endswith(".py"):
            return

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            tree = ast.parse(content, filename=file_path)

            imports = set(extract_imports(file_path))
            uses_bitsandbytes = any(i.lower() == "bitsandbytes" for i in imports)

            class Visitor(ast.NodeVisitor):
                def __init__(self):
                    self.quant_calls = []
                    self.load_in_8bit = False

                def visit_Call(self, node: ast.Call):
                    # look for keyword load_in_8bit=True in calls
                    for kw in getattr(node, "keywords", []):
                        if kw.arg == "load_in_8bit" and isinstance(kw.value, ast.Constant):
                            if kw.value.value is True:
                                self.load_in_8bit = True

                    # look for functions named 'quantize' or attr 'quantize'
                    fname = ""
                    if isinstance(node.func, ast.Attribute):
                        fname = node.func.attr
                    elif isinstance(node.func, ast.Name):
                        fname = node.func.id

                    if fname == "quantize":
                        self.quant_calls.append(fname)

                    self.generic_visit(node)

            vis = Visitor()
            vis.visit(tree)

            # If no quant indicators, skip
            if not (uses_bitsandbytes or vis.load_in_8bit or vis.quant_calls):
                return

            # For any model declared in this file, create a quant node and link
            models = extract_models(file_path)
            unknown_count = sum(1 for name in models if name == "<unknown>")
            if unknown_count:
                builder.unresolved_model_refs += unknown_count
            models = [m for m in models if m != "<unknown>"]

            for m in models:
                # create quantization node specific to this model
                qname = f"{m}-quant"
                qid = builder.add_quantization(qname)

                # find model id (if exists) or create
                model_id = builder.graph.registry._index.get((NodeType.MODEL, m))
                if not model_id:
                    model_id = builder.add_model(m)

                # link quant -> parent model
                builder.link_quantized_from(qid, model_id)

                # if bitsandbytes used, add library node and link
                if uses_bitsandbytes:
                    lib_id = builder.add_library("bitsandbytes")
                    builder.link_depends_on(model_id, lib_id)

        except Exception:
            pass
