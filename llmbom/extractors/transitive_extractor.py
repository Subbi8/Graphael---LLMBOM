"""Transitive dependency extractor using static lockfile parsing.

Parses requirements.txt, Pipfile.lock, poetry.lock, setup.cfg, and pyproject.toml
using Python stdlib only. No network calls, no subprocess execution.
"""

import os
import sys
import json
import re
from configparser import ConfigParser

from llmbom.extractors.base_extractor import BaseExtractor
from llmbom.core.schema import NodeType


class TransitiveExtractor(BaseExtractor):
    """Parse lockfiles to discover transitive dependencies without executing code."""

    # Node.js for future use; not needed for Python yet
    PYTHON_BUILTIN_MODULES = {
        'abc', 'aifc', 'argparse', 'array', 'ast', 'asynchat', 'asyncio',
        'atexit', 'audioop', 'base64', 'bdb', 'binascii', 'binhex', 'bisect',
        'builtins', 'bz2', 'calendar', 'cgi', 'cgitb', 'chunk', 'cmath', 'cmd',
        'code', 'codecs', 'codeop', 'collections', 'colorsys', 'compileall',
        'concurrent', 'configparser', 'contextlib', 'contextvars', 'copy',
        'copyreg', 'cProfile', 'crypt', 'csv', 'ctypes', 'curses', 'dataclasses',
        'datetime', 'dbm', 'decimal', 'defusedxml', 'difflib', 'dis', 'doctest',
        'dummy_thread', 'dummy_threading', 'email', 'encodings', 'enum', 'errno',
        'faulthandler', 'fcntl', 'filecmp', 'fileinput', 'fnmatch', 'formatter',
        'fractions', 'ftplib', 'functools', 'gc', 'getopt', 'getpass', 'gettext',
        'glob', 'grp', 'gzip', 'hashlib', 'heapq', 'hmac', 'html', 'http',
        'idlelib', 'imaplib', 'imghdr', 'imp', 'importlib', 'inspect', 'io',
        'ipaddress', 'itertools', 'json', 'keyword', 'lib2to3', 'linecache',
        'locale', 'logging', 'lzma', 'mailbox', 'mailcap', 'marshal', 'math',
        'mimetypes', 'mmap', 'modulefinder', 'msilib', 'msvcrt', 'multiprocessing',
        'netrc', 'nis', 'nntplib', 'numbers', 'operator', 'optparse', 'os',
        'ossaudiodev', 'parser', 'pathlib', 'pdb', 'pickle', 'pickletools',
        'pipes', 'pkgutil', 'platform', 'plistlib', 'poplib', 'posix', 'posixpath',
        'pprint', 'profile', 'pstats', 'pty', 'pwd', 'py_compile', 'pyclbr',
        'pydoc', 'pyexpat', 'pyphd', 'queue', 'quopri', 'random', 'readline',
        're', 'reprlib', 'resource', 'rlcompleter', 'runpy', 'sched', 'secrets',
        'select', 'selectors', 'shelve', 'shlex', 'shutil', 'signal', 'site',
        'smtpd', 'smtplib', 'sndhdr', 'socket', 'socketserver', 'spwd', 'sqlite3',
        'ssl', 'stat', 'statistics', 'string', 'stringprep', 'struct', 'subprocess',
        'sunau', 'symbol', 'symtable', 'sys', 'sysconfig', 'syslog', 'tabnanny',
        'tarfile', 'telnetlib', 'tempfile', 'termios', 'test', 'textwrap',
        'threading', 'time', 'timeit', 'tkinter', 'token', 'tokenize', 'trace',
        'traceback', 'tracemalloc', 'tty', 'turtle', 'types', 'typing',
        'unicodedata', 'unittest', 'urllib', 'uu', 'uuid', 'venv', 'warnings',
        'wave', 'weakref', 'webbrowser', 'wsgiref', 'xdrlib', 'xml', 'xmlrpc',
        'zipapp', 'zipfile', 'zipimport', 'zlib',
    }

    def extract(self, file_path, builder):
        """Entry point is not used for transitive extractor.
        
        Use extract_transitive() instead, called at project level.
        """
        pass

    def extract_transitive(self, project_root, builder, enable_transitive=True):
        """Parse all lockfiles in project_root and create transitive LIBRARY nodes.
        
        Args:
            project_root: root path of the project
            builder: LLMBOMBuilder instance
            enable_transitive: if False, do nothing
            
        Returns:
            list of discovered transitive packages (dict with name, source_lockfile, etc.)
        """
        if not enable_transitive:
            return []

        discovered = []

        # List of lockfile patterns to check
        lockfile_patterns = [
            'requirements.txt',
            'requirements-dev.txt',
            'requirements/*.txt',  # any .txt in requirements/ dir
            'Pipfile.lock',
            'poetry.lock',
            'setup.cfg',
            'pyproject.toml',
            'pip-requirements.txt',
        ]

        for pattern in lockfile_patterns:
            if '/' in pattern:
                # Handle directory patterns like requirements/*.txt
                dir_part, file_part = pattern.split('/', 1)
                dir_path = os.path.join(project_root, dir_part)
                if os.path.isdir(dir_path):
                    for fname in os.listdir(dir_path):
                        if fname.endswith(file_part.replace('*', '')):
                            fpath = os.path.join(dir_path, fname)
                            try:
                                pkgs = self._parse_lockfile(fpath, project_root)
                                for pkg in pkgs:
                                    discovered.append(pkg)
                            except Exception as e:
                                print(f"Warning: Failed to parse {fpath}: {e}", file=sys.stderr)
            else:
                fpath = os.path.join(project_root, pattern)
                if os.path.exists(fpath):
                    try:
                        pkgs = self._parse_lockfile(fpath, project_root)
                        for pkg in pkgs:
                            discovered.append(pkg)
                    except Exception as e:
                        print(f"Warning: Failed to parse {fpath}: {e}", file=sys.stderr)

        # Now create LIBRARY nodes for transitive packages not already present
        existing_libs = {
            node.name.lower(): nid
            for nid, node in builder.graph.nodes.items()
            if node.type == NodeType.LIBRARY
        }

        added_libs = []
        for pkg_info in discovered:
            pkg_name = pkg_info['name']
            norm_name = pkg_name.lower().strip()

            # Check if already exists (case-insensitive)
            if norm_name not in existing_libs:
                # Create a new transitive LIBRARY node
                lib_id = builder.add_library(pkg_name)
                # Enrich with transitive metadata
                if lib_id in builder.graph.nodes:
                    node = builder.graph.nodes[lib_id]
                    if not node.metadata:
                        node.metadata = {}
                    node.metadata['is_transitive'] = True
                    node.metadata['source_lockfile'] = pkg_info.get('source_lockfile')
                    node.metadata['is_stdlib'] = False
                    node.metadata['import_count'] = 0
                    added_libs.append(pkg_info)

        return added_libs

    def _parse_lockfile(self, fpath, project_root):
        """Parse a single lockfile and return list of discovered packages."""
        fname = os.path.basename(fpath)
        relative_path = os.path.relpath(fpath, project_root)

        if fname.endswith('.txt'):
            return self._parse_requirements_txt(fpath, relative_path)
        elif fname == 'Pipfile.lock':
            return self._parse_pipfile_lock(fpath, relative_path)
        elif fname == 'poetry.lock':
            return self._parse_poetry_lock(fpath, relative_path)
        elif fname == 'setup.cfg':
            return self._parse_setup_cfg(fpath, relative_path)
        elif fname == 'pyproject.toml':
            return self._parse_pyproject_toml(fpath, relative_path)
        else:
            return []

    def _parse_requirements_txt(self, fpath, lockfile_path):
        """Parse requirements.txt-style file."""
        packages = []
        try:
            with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and blank lines
                    if not line or line.startswith('#'):
                        continue
                    # Remove inline comments
                    if '#' in line:
                        line = line.split('#')[0].strip()
                    # Remove version specifiers and extras
                    # Pattern: package_name[extra,...]>=version
                    pkg_name = re.split(r'[<>=!~\[]', line)[0].strip()
                    if pkg_name:
                        packages.append({
                            'name': pkg_name,
                            'source_lockfile': lockfile_path,
                        })
        except Exception:
            pass
        return packages

    def _parse_pipfile_lock(self, fpath, lockfile_path):
        """Parse Pipfile.lock (JSON format)."""
        packages = []
        try:
            with open(fpath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            # Pipfile.lock has "default" and "develop" sections
            for section in ['default', 'develop']:
                if section in data:
                    for pkg_name in data[section].keys():
                        packages.append({
                            'name': pkg_name,
                            'source_lockfile': lockfile_path,
                        })
        except Exception:
            pass
        return packages

    def _parse_poetry_lock(self, fpath, lockfile_path):
        """Parse poetry.lock (TOML-like, but parse via regex/text for stdlib-only)."""
        packages = []
        try:
            with open(fpath, 'r', encoding='utf-8') as f:
                content = f.read()
            # poetry.lock format: [[package]] blocks with name = "..."
            # Extract all [[package]] sections and the name field
            pattern = r'\[\[package\]\]\s*\nname\s*=\s*["\']([^"\']+)["\']'
            matches = re.findall(pattern, content)
            for pkg_name in matches:
                packages.append({
                    'name': pkg_name,
                    'source_lockfile': lockfile_path,
                })
        except Exception:
            pass
        return packages

    def _parse_setup_cfg(self, fpath, lockfile_path):
        """Parse setup.cfg using configparser."""
        packages = []
        try:
            config = ConfigParser()
            config.read(fpath)
            if config.has_option('options', 'install_requires'):
                deps_str = config.get('options', 'install_requires')
                for line in deps_str.split('\n'):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    pkg_name = re.split(r'[<>=!~\[]', line)[0].strip()
                    if pkg_name:
                        packages.append({
                            'name': pkg_name,
                            'source_lockfile': lockfile_path,
                        })
        except Exception:
            pass
        return packages

    def _parse_pyproject_toml(self, fpath, lockfile_path):
        """Parse pyproject.toml (TOML-like, parsed via regex for stdlib-only)."""
        packages = []
        try:
            with open(fpath, 'r', encoding='utf-8') as f:
                content = f.read()

            # Parse [project] dependencies
            project_section = re.search(
                r'\[project\].*?dependencies\s*=\s*\[(.*?)\]',
                content,
                re.DOTALL
            )
            if project_section:
                deps_str = project_section.group(1)
                for line in deps_str.split(','):
                    line = line.strip().strip('"\'')
                    if line and not line.startswith('#'):
                        pkg_name = re.split(r'[<>=!~\[]', line)[0].strip()
                        if pkg_name:
                            packages.append({
                                'name': pkg_name,
                                'source_lockfile': lockfile_path,
                            })

            # Parse [tool.poetry.dependencies]
            poetry_section = re.search(
                r'\[tool\.poetry\.dependencies\].*?(?=\[|\Z)',
                content,
                re.DOTALL
            )
            if poetry_section:
                section_content = poetry_section.group(0)
                # Find all lines like: package = "..."
                pattern = r'^(\w+(?:-\w+)*)\s*=\s*["\']'
                for line in section_content.split('\n'):
                    match = re.match(pattern, line.strip())
                    if match:
                        pkg_name = match.group(1)
                        if pkg_name != 'python':  # skip python version specifier
                            packages.append({
                                'name': pkg_name,
                                'source_lockfile': lockfile_path,
                            })
        except Exception:
            pass
        return packages
