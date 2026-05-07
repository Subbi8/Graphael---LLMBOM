"""JavaScript/TypeScript dependency extractor using regex-based parsing.

Extracts imports and requires from .js, .ts, .mjs, .cjs files using stdlib only.
No network calls, no parsing libraries, full offline operation.
"""

import os
import sys
import re
from typing import List, Set, Tuple

from llmbom.extractors.base_extractor import BaseExtractor
from llmbom.core.schema import NodeType, EdgeType


class JavaScriptTypeScriptExtractor(BaseExtractor):
    """Extract dependencies from JavaScript and TypeScript files using regex."""

    # Hardcoded Node.js built-in modules (stdlib for JavaScript)
    NODEJS_BUILTIN_MODULES = {
        'assert', 'async_hooks', 'buffer', 'child_process', 'cluster',
        'crypto', 'dgram', 'diagnostics_channel', 'dns', 'domain', 'events',
        'fs', 'fs/promises', 'http', 'http2', 'https', 'inspector',
        'inspector/promises', 'module', 'net', 'os', 'path', 'perf_hooks',
        'punycode', 'querystring', 'readline', 'repl', 'stream', 'string_decoder',
        'sys', 'timers', 'timers/promises', 'tls', 'trace_events', 'tty',
        'url', 'util', 'v8', 'vm', 'wasi', 'worker_threads', 'zlib',
        # Common globals (not really modules but imported as if they were)
        'console', 'global', 'process', 'Buffer',
    }

    SUPPORTED_EXTENSIONS = {'.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx'}

    def extract(self, file_path, builder):
        """Extract imports from JavaScript/TypeScript file."""
        fname = os.path.basename(file_path)
        _, ext = os.path.splitext(fname)

        if ext not in self.SUPPORTED_EXTENSIONS:
            return

        # Determine language
        language = 'typescript' if ext in {'.ts', '.tsx'} else 'javascript'

        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                code = f.read()
        except Exception:
            return

        # Get or create SCRIPT node for this file
        script_name = file_path
        # Try to normalize path relative to project root if available
        if hasattr(builder, 'project_root') and builder.project_root:
            try:
                from llmbom.utils.file_utils import normalize_path
                script_name = normalize_path(file_path, builder.project_root)
            except Exception:
                pass

        script_id = builder.add_script(script_name)

        # Enrich script node with JS/TS metadata
        if script_id in builder.graph.nodes:
            script_node = builder.graph.nodes[script_id]
            if not script_node.metadata:
                script_node.metadata = {}
            script_node.metadata['language'] = language
            script_node.metadata['is_javascript_file'] = True

        # Extract all imports and requires
        imports = self._extract_imports(code)

        # Create edges to dependencies (filter out nodejs stdlib)
        for import_name in imports:
            if not self._is_nodejs_builtin(import_name):
                # Add LIBRARY node for dependency
                lib_id = builder.add_library(import_name)

                # Enrich library node
                if lib_id in builder.graph.nodes:
                    lib_node = builder.graph.nodes[lib_id]
                    if not lib_node.metadata:
                        lib_node.metadata = {}
                    lib_node.metadata['is_npm_package'] = True
                    lib_node.metadata['language'] = 'javascript'

                # Create DEPENDS_ON edge
                builder.link_depends_on(script_id, lib_id)

    def _extract_imports(self, code: str) -> Set[str]:
        """Extract imported module names from JavaScript/TypeScript code.
        
        Handles:
        - import x from 'module'
        - import { x, y } from 'module'
        - import * as x from 'module'
        - require('module')
        - const x = require('module')
        
        Args:
            code: JavaScript/TypeScript source code
            
        Returns:
            set of imported module names (deduplicated)
        """
        imports = set()

        # Pattern 1: ES6 import statements
        # import x from 'module'
        # import { x, y } from 'module'
        # import * as x from 'module'
        es6_pattern = r"import\s+(?:(?:\{[^}]*\})|(?:\*\s+as\s+\w+)|(?:\w+))(?:\s*,\s*\{[^}]*\})*\s+from\s+['\"]([^'\"]+)['\"]"
        for match in re.finditer(es6_pattern, code, re.MULTILINE):
            module = match.group(1).strip()
            if module:
                imports.add(self._normalize_module_name(module))

        # Pattern 2: CommonJS require()
        # require('module')
        # const x = require('module')
        require_pattern = r"require\s*\(\s*['\"]([^'\"]+)['\"]\s*\)"
        for match in re.finditer(require_pattern, code):
            module = match.group(1).strip()
            if module:
                imports.add(self._normalize_module_name(module))

        # Pattern 3: Dynamic import()
        # import('module')
        dynamic_import_pattern = r"import\s*\(\s*['\"]([^'\"]+)['\"]\s*\)"
        for match in re.finditer(dynamic_import_pattern, code):
            module = match.group(1).strip()
            if module:
                imports.add(self._normalize_module_name(module))

        return imports

    def _normalize_module_name(self, module_path: str) -> str:
        """Normalize a module path to its package name.
        
        Examples:
        - 'lodash' -> 'lodash'
        - '@angular/core' -> '@angular/core'
        - 'lodash/map' -> 'lodash'
        - './local/file' -> local file (skip)
        - '../parent' -> parent file (skip)
        - '/absolute' -> absolute file (skip)
        
        Args:
            module_path: raw import path
            
        Returns:
            normalized package name, or empty string if local/relative
        """
        # Skip relative imports and absolute paths
        if module_path.startswith('.') or module_path.startswith('/'):
            return ''

        # Handle scoped packages (@scope/package)
        if module_path.startswith('@'):
            # Extract @scope/package, ignore any subpaths
            parts = module_path.split('/')
            if len(parts) >= 2:
                return f"{parts[0]}/{parts[1]}"
            return module_path.split('/')[0]

        # For regular packages, extract the first component (package name)
        # and ignore subpaths like 'lodash/map' -> 'lodash'
        parts = module_path.split('/')
        return parts[0]

    def _is_nodejs_builtin(self, module_name: str) -> bool:
        """Check if module name is a Node.js built-in module.
        
        Args:
            module_name: normalized module name
            
        Returns:
            True if it's a Node.js builtin, False otherwise
        """
        # Exact match
        if module_name in self.NODEJS_BUILTIN_MODULES:
            return True

        # Check with 'node:' prefix (Node.js 12.20+)
        if module_name.startswith('node:'):
            without_prefix = module_name[5:]
            return without_prefix in self.NODEJS_BUILTIN_MODULES

        return False
