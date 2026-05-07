"""Notebook cell-level extraction using stdlib JSON parsing.

Parses .ipynb files and creates per-cell SCRIPT nodes with NOTEBOOK parent node.
Supports code cells only; markdown cells are tracked but not extracted as dependencies.
"""

import os
import sys
import json
import hashlib
from typing import Dict, Any, List, Tuple

from llmbom.extractors.base_extractor import BaseExtractor
from llmbom.core.schema import NodeType, EdgeType


class NotebookExtractor(BaseExtractor):
    """Extract code cells from Jupyter notebooks as individual SCRIPT nodes."""

    NOTEBOOK_EXTENSIONS = {'.ipynb'}

    def extract(self, file_path, builder):
        """Entry point for per-file extraction (not used for notebooks).
        
        Use extract_notebooks() instead for project-level processing.
        """
        pass

    def extract_notebooks(self, project_root, builder, enable_notebook_cells=True):
        """Extract all .ipynb files in project and create per-cell SCRIPT nodes.
        
        Args:
            project_root: root path of project
            builder: LLMBOMBuilder instance
            enable_notebook_cells: if False, do nothing
            
        Returns:
            list of extracted notebooks with their cell info
        """
        if not enable_notebook_cells:
            return []

        extracted = []

        # Find all .ipynb files
        for root, dirs, files in os.walk(project_root):
            for fname in files:
                if fname.endswith('.ipynb'):
                    fpath = os.path.join(root, fname)
                    try:
                        notebook_info = self._extract_notebook(fpath, project_root, builder)
                        if notebook_info:
                            extracted.append(notebook_info)
                    except Exception as e:
                        print(f"Warning: Failed to extract notebook {fpath}: {e}", file=sys.stderr)

        return extracted

    def _extract_notebook(self, fpath: str, project_root: str, builder) -> Dict[str, Any]:
        """Extract cells from a single notebook file.
        
        Args:
            fpath: absolute path to .ipynb file
            project_root: root project path (for normalization)
            builder: LLMBOMBuilder instance
            
        Returns:
            dict with notebook metadata and extracted cell info, or None on error
        """
        with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
            try:
                notebook = json.load(f)
            except json.JSONDecodeError:
                return None

        # Normalize notebook path
        rel_path = os.path.relpath(fpath, project_root)
        notebook_node_name = rel_path.replace('\\', '/')

        # Create NOTEBOOK node
        notebook_id = builder.add_config(notebook_node_name)
        
        notebook_node = builder.graph.nodes[notebook_id]
        notebook_node.metadata = notebook_node.metadata or {}
        notebook_node.metadata['file_type'] = 'notebook'
        notebook_node.metadata['format'] = 'jupyter'
        notebook_node.metadata['is_notebook_parent'] = True

        # Extract code cells
        cells = notebook.get('cells', [])
        cell_count = 0
        code_cell_count = 0
        extracted_imports = []

        for cell_idx, cell in enumerate(cells):
            cell_type = cell.get('cell_type', 'code')

            if cell_type == 'code':
                code_cell_count += 1
                # Get source code from cell
                source = cell.get('source', [])
                if isinstance(source, list):
                    code = ''.join(source)
                else:
                    code = source

                # Create cell-level SCRIPT node
                cell_name = f"{notebook_node_name}#cell_{cell_idx + 1}"
                cell_id = builder.add_script(cell_name)

                if cell_id in builder.graph.nodes:
                    cell_node = builder.graph.nodes[cell_id]
                    cell_node.metadata = cell_node.metadata or {}
                    cell_node.metadata['cell_index'] = cell_idx
                    cell_node.metadata['cell_type'] = 'code'
                    cell_node.metadata['is_notebook_cell'] = True
                    cell_node.metadata['notebook_parent'] = notebook_node_name
                    cell_node.metadata['code_length'] = len(code)

                    # Extract imports from cell code
                    cell_imports = self._extract_imports_from_code(code)
                    extracted_imports.extend(cell_imports)

                    # Create CONTAINS edge from NOTEBOOK to cell SCRIPT
                    builder.link_contains(notebook_id, cell_id)

                cell_count += 1

            elif cell_type == 'markdown':
                # Count markdown cells but don't extract as dependencies
                pass

        return {
            'notebook_path': notebook_node_name,
            'notebook_id': notebook_id,
            'cell_count': len(cells),
            'code_cell_count': code_cell_count,
            'extracted_imports': extracted_imports,
        }

    def _extract_imports_from_code(self, code: str) -> List[str]:
        """Extract import statements from Python code using regex (stdlib-only).
        
        Args:
            code: Python code string
            
        Returns:
            list of imported module names
        """
        imports = []
        import re

        # Pattern for: import x, import x as y, import x,y,z
        import_pattern = r'^\s*import\s+([^#\n]+)'
        # Pattern for: from x import y
        from_pattern = r'^\s*from\s+([^\s]+)\s+import'

        for line in code.split('\n'):
            # Skip comments
            if '#' in line:
                line = line[:line.index('#')]

            # Check for import statements
            import_match = re.match(import_pattern, line)
            if import_match:
                names = import_match.group(1).split(',')
                for name in names:
                    # Extract module name (first part before 'as' or space)
                    module = name.strip().split()[0].strip()
                    if module:
                        imports.append(module)

            from_match = re.match(from_pattern, line)
            if from_match:
                module = from_match.group(1).strip()
                if module and module != '__future__':
                    imports.append(module)

        return list(set(imports))  # Deduplicate
