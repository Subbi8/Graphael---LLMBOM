"""AST-backed dependency extractor.

Produces SCRIPT and LIBRARY nodes linked by DEPENDS_ON edges.
"""

import os

from llmbom.extractors.base_extractor import BaseExtractor
from llmbom.parsers.requirements_parser import parse_requirements
from llmbom.parsers.python_parser import extract_imports
from llmbom.core.schema import NodeType
from llmbom.utils.file_utils import normalize_package_name


class DependencyExtractor(BaseExtractor):
    """For requirements.txt, create LIBRARY nodes.  For Python files, create a
    SCRIPT node and LIBRARY nodes for each import, linking them via DEPENDS_ON.
    """

    def extract(self, file_path, builder):
        # requirements.txt support
        if file_path.endswith("requirements.txt"):
            try:
                dependencies = parse_requirements(file_path)
                unique_deps = set(dependencies)
                for dep in unique_deps:
                    builder.add_library(dep)
            except Exception:
                pass
            return

        # Python imports
        if not file_path.endswith(".py"):
            return

        try:
            libs = extract_imports(file_path)
            if not libs:
                return

            unique_libs = set(libs)
            script_id = builder.add_script(file_path)

            for lib in unique_libs:
                lib_id = builder.add_library(lib)
                builder.link_depends_on(script_id, lib_id)
        except Exception:
            pass
