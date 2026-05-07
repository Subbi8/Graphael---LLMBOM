import os

from llmbom.engine.scanner import ProjectScanner
from llmbom.engine.context import ScanContext
from llmbom.builders.llmbom_builder import LLMBOMBuilder
from llmbom.extractors.model_extractor import ModelExtractor
from llmbom.extractors.dataset_extractor import DatasetExtractor
from llmbom.extractors.dependency_extractor import DependencyExtractor
from llmbom.extractors.pipeline_extractor import PipelineExtractor
from llmbom.extractors.quantization_extractor import QuantizationExtractor
from llmbom.extractors.tooling_detector import ToolingDetector
from llmbom.extractors.fine_tune_detector import FineTuneDetector
from llmbom.extractors.vector_api_detector import InfraDetector
from llmbom.extractors.transitive_extractor import TransitiveExtractor
from llmbom.extractors.notebook_extractor import NotebookExtractor
from llmbom.extractors.js_ts_extractor import JavaScriptTypeScriptExtractor
from llmbom.core.metadata_enricher import MetadataEnricher
from llmbom.utils.file_utils import normalize_path
from llmbom.utils.logging_utils import get_logger
from llmbom.core.schema import NodeType


class LLMBOMOrchestrator:

    def __init__(self, project_path):
        self.context = ScanContext(project_path)
        self.builder = LLMBOMBuilder(project_path)

    def run(self, enable_transitive=True, enable_notebook_cells=True, hide_internal=False):
        scanner = ProjectScanner(self.context.project_path)
        self.context.files = scanner.scan()

        extractors = [
            ModelExtractor(),
            DatasetExtractor(),
            DependencyExtractor(),
            PipelineExtractor(),
            QuantizationExtractor(),
            ToolingDetector(),
            JavaScriptTypeScriptExtractor(),
        ]

        # project-level detectors
        infra_detector = InfraDetector(self.context.project_path)
        fine_tune_detector = FineTuneDetector(self.context.project_path)
        transitive_extractor = TransitiveExtractor()
        notebook_extractor = NotebookExtractor()

        for file_path in self.context.files:
            for extractor in extractors:
                extractor.extract(file_path, self.builder)

        # run project-level detectors and record some findings
        try:
            vector_configs, api_calls = infra_detector.extract()
            for v in vector_configs:
                self.builder.add_environment(v.get("name"))
            for a in api_calls:
                self.builder.add_library(a.get("name"))
        except Exception:
            pass

        try:
            ft_methods = fine_tune_detector.extract()
            self.context.results["fine_tune_methods"] = ft_methods
        except Exception:
            pass

        # Extract transitive dependencies from lockfiles
        try:
            transitive_extractor.extract_transitive(
                self.context.project_path,
                self.builder,
                enable_transitive=enable_transitive
            )
        except Exception:
            pass

        # Extract notebook cells
        try:
            notebook_extractor.extract_notebooks(
                self.context.project_path,
                self.builder,
                enable_notebook_cells=enable_notebook_cells
            )
        except Exception:
            pass

        # enrich metadata before building output
        enricher = MetadataEnricher(self.context.project_path)
        enricher.enrich_library_nodes(self.builder.graph)

        # enrich script nodes with file metadata
        script_paths = {}
        for fpath in self.context.files:
            if fpath.endswith(".py"):
                for nid, node in self.builder.graph.nodes.items():
                    if node.type == NodeType.SCRIPT and normalize_path(fpath, self.context.project_path) == node.name:
                        script_paths[fpath] = nid
        enricher.enrich_script_batch(self.builder.graph, script_paths)

        # Mark internal modules
        self._mark_internal_modules()

        # report unresolved model/dataset refs encountered during static analysis
        unresolved_models = getattr(self.builder, 'unresolved_model_refs', 0)
        unresolved_datasets = getattr(self.builder, 'unresolved_dataset_refs', 0)
        if unresolved_models or unresolved_datasets:
            logger = get_logger(__name__)
            logger.warning(
                "Skipped %d unresolved model reference(s) and %d unresolved dataset reference(s) during static analysis. "
                "These references could not be resolved without execution.",
                unresolved_models,
                unresolved_datasets,
            )
            self.context.results['unresolved_references'] = {
                'models': unresolved_models,
                'datasets': unresolved_datasets,
            }

        # build graph structure
        graph_dict = self.builder.build(hide_internal=hide_internal)

        # optionally run static analysis if caller wants full report
        try:
            from llmbom.analysis.engine import run_analysis
            analysis_report = run_analysis(self.builder.graph)
            return {"graph": graph_dict, "analysis": analysis_report}
        except Exception:
            # fallback to previous behaviour
            return graph_dict

    def _mark_internal_modules(self):
        """Mark library nodes that correspond to internal project modules."""
        internal_names = set()

        stems = set()
        internal_packages = set()

        for node_id, node in self.builder.graph.nodes.items():
            if node.type != NodeType.SCRIPT:
                continue

            metadata = getattr(node, 'metadata', {}) or {}
            path = metadata.get('file_path_normalized') or node.name
            path = path.replace('\\', '/').lstrip('./')

            filename = os.path.basename(path)
            stem = os.path.splitext(filename)[0]
            if stem and stem not in ('__init__', '__main__'):
                stems.add(stem)

            # If this is a top-level package __init__.py, treat that package as internal.
            parts = path.split('/')
            if len(parts) == 2 and parts[1] == '__init__.py':
                internal_packages.add(parts[0])

        for node_id, node in self.builder.graph.nodes.items():
            if node.type != NodeType.LIBRARY:
                continue

            metadata = getattr(node, 'metadata', {}) or {}
            if node.name in stems or node.name in internal_packages:
                metadata['is_internal'] = True
                node.metadata = metadata
