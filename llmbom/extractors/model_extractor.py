from llmbom.extractors.base_extractor import BaseExtractor
from llmbom.parsers.python_parser import extract_models


class ModelExtractor(BaseExtractor):
    """Scan a Python file for model instantiation patterns.

    Uses AST-based helpers in ``parsers.python_parser`` to locate
    ``from_pretrained`` calls and convert them to ``MODEL`` nodes.
    """

    def extract(self, file_path, builder):
        if not file_path.endswith(".py"):
            return

        try:
            models = extract_models(file_path)
            unknown_count = sum(1 for name in models if name == "<unknown>")
            if unknown_count:
                builder.unresolved_model_refs += unknown_count
            for name in models:
                if name == "<unknown>":
                    continue
                builder.add_model(name)
        except Exception:
            pass
