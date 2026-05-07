"""Framework/tooling detection from imports.

For each detected tool/framework in TOOL_KEYWORDS, creates appropriate nodes
and links them. No hardcoded vendor logic; detection is purely syntactic.
"""

import os

from llmbom.extractors.base_extractor import BaseExtractor
from llmbom.parsers.python_parser import extract_imports
from llmbom.parsers.requirements_parser import parse_requirements
from llmbom.core.schema import NodeType, EdgeType
from llmbom.utils.file_utils import normalize_package_name

class ToolingDetector(BaseExtractor):
    """Detect imports from requirements and python files and create LIBRARY
    nodes when present. This extractor intentionally does not perform any
    semantic classification; it records only structural LIBRARY nodes and
    connects scripts to them using DEPENDS_ON edges.
    """

    def extract(self, file_path, builder):
        fname = os.path.basename(file_path)

        # requirements.txt: register each listed package as a LIBRARY
        if fname == "requirements.txt":
            try:
                reqs = parse_requirements(file_path)
                unique_reqs = set(reqs)
                for pkg in unique_reqs:
                    lib_id = builder.add_library(pkg)
                return
            except Exception:
                return

        # python files: add script node and record imports as libraries
        if file_path.endswith(".py"):
            try:
                imports = extract_imports(file_path)
                unique_imports = set(imports)
                script_id = builder.add_script(file_path)
                for lib in unique_imports:
                    lib_id = builder.add_library(lib)
                    builder.link_depends_on(script_id, lib_id)
            except Exception:
                return

