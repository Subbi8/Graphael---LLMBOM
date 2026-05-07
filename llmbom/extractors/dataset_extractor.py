from llmbom.extractors.base_extractor import BaseExtractor
from llmbom.parsers.python_parser import extract_datasets


class DatasetExtractor(BaseExtractor):
    """Look for dataset usage and register datasets in the graph."""

    def extract(self, file_path, builder):
        if not file_path.endswith(".py"):
            return

        try:
            datasets = extract_datasets(file_path)
            unknown_count = sum(1 for name in datasets if name == "<unknown>")
            if unknown_count:
                builder.unresolved_dataset_refs += unknown_count
            for name in datasets:
                if name == "<unknown>":
                    continue
                builder.add_dataset(name)
        except Exception:
            pass
