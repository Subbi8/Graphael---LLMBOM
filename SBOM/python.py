import json
import os
import re
from pathlib import Path


class PythonExtractor:
    def __init__(self, path):
        self.path = path

    def extract_packages(self):
        """Extract Python packages from requirements.txt, setup.py, and pyproject.toml

        Returns:
            list<dict<{'category': list<packages>}>: packages -> {'name': '', 'version': '','vendor' : '', 'type': '', 'file':''}
        """
        packages = []
        build_packages = []

        # Find and parse requirements.txt files
        for root, folders, files in os.walk(self.path):
            for file in files:
                if file.lower() == "requirements.txt":
                    filepath = os.path.join(root, file)
                    reqs = self._parse_requirements_file(filepath)
                    packages.extend(reqs)
                elif file.lower() == "setup.py":
                    filepath = os.path.join(root, file)
                    reqs = self._parse_setup_py(filepath)
                    packages.extend(reqs)
                elif file.lower() == "pyproject.toml":
                    filepath = os.path.join(root, file)
                    reqs_deps, reqs_build = self._parse_pyproject_toml(filepath)
                    packages.extend(reqs_deps)
                    build_packages.extend(reqs_build)
                elif file.lower() == "pipfile":
                    filepath = os.path.join(root, file)
                    reqs = self._parse_pipfile(filepath)
                    packages.extend(reqs)

        # Remove duplicates based on name
        packages = self._deduplicate_packages(packages)
        build_packages = self._deduplicate_packages(build_packages)

        result = []
        if packages:
            result.append({'python': packages})
        if build_packages:
            result.append({'python_build_packages': build_packages})

        return result if result else [{'python': []}]

    def _parse_requirements_file(self, filepath):
        """Parse requirements.txt file

        Args:
            filepath (str): Path to requirements.txt

        Returns:
            list<dict>: List of packages
        """
        packages = []
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    # Remove inline comments
                    if '#' in line:
                        line = line.split('#')[0].strip()

                    # Parse the requirement (name and version)
                    name, version = self._parse_requirement_line(line)
                    if name:
                        packages.append({
                            'name': name,
                            'version': version or 'unknown',
                            'vendor': 'unknown',
                            'type': 'requires',
                            'file': filepath
                        })
        except Exception as e:
            print(f"Error parsing {filepath}: {e}")
        return packages

    def _parse_setup_py(self, filepath):
        """Parse setup.py file to extract dependencies

        Args:
            filepath (str): Path to setup.py

        Returns:
            list<dict>: List of packages
        """
        packages = []
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()

            # Try to find install_requires and extras_require
            # This is a simple regex-based approach; full AST parsing would be more robust
            
            # Look for install_requires
            install_requires_match = re.search(
                r'install_requires\s*=\s*\[([^\]]*)\]',
                content,
                re.DOTALL
            )
            if install_requires_match:
                requires_str = install_requires_match.group(1)
                for req in re.findall(r"['\"]([^'\"]+)['\"]", requires_str):
                    name, version = self._parse_requirement_line(req)
                    if name:
                        packages.append({
                            'name': name,
                            'version': version or 'unknown',
                            'vendor': 'unknown',
                            'type': 'requires',
                            'file': filepath
                        })
        except Exception as e:
            print(f"Error parsing {filepath}: {e}")
        return packages

    def _parse_pyproject_toml(self, filepath):
        """Parse pyproject.toml file to extract dependencies

        Args:
            filepath (str): Path to pyproject.toml

        Returns:
            tuple: (packages, build_packages)
        """
        packages = []
        build_packages = []
        try:
            import toml
        except ImportError:
            # Fallback simple parser if toml is not installed
            print(f"toml module not available, using simple parser for {filepath}")
            return self._parse_pyproject_toml_simple(filepath), []

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = toml.load(f)

            # Extract dependencies from [project] section
            if 'project' in content:
                project = content['project']
                if 'dependencies' in project:
                    for dep in project['dependencies']:
                        name, version = self._parse_requirement_line(dep)
                        if name:
                            packages.append({
                                'name': name,
                                'version': version or 'unknown',
                                'vendor': 'unknown',
                                'type': 'requires',
                                'file': filepath
                            })

            # Extract build dependencies from [build-system] section
            if 'build-system' in content:
                build_system = content['build-system']
                if 'requires' in build_system:
                    for dep in build_system['requires']:
                        name, version = self._parse_requirement_line(dep)
                        if name:
                            build_packages.append({
                                'name': name,
                                'version': version or 'unknown',
                                'vendor': 'unknown',
                                'type': 'build requires',
                                'file': filepath
                            })
        except Exception as e:
            print(f"Error parsing {filepath}: {e}")

        return packages, build_packages

    def _parse_pyproject_toml_simple(self, filepath):
        """Simple parser for pyproject.toml when toml module is not available

        Args:
            filepath (str): Path to pyproject.toml

        Returns:
            list<dict>: List of packages
        """
        packages = []
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()

            # Simple regex-based extraction
            in_dependencies = False
            for line in content.split('\n'):
                if 'dependencies' in line and '=' in line:
                    in_dependencies = True
                    continue

                if in_dependencies:
                    if line.strip() == ']':
                        in_dependencies = False
                    elif line.strip().startswith('"') or line.strip().startswith("'"):
                        # Extract package line
                        match = re.search(r'["\']([^"\']+)["\']', line)
                        if match:
                            dep = match.group(1)
                            name, version = self._parse_requirement_line(dep)
                            if name:
                                packages.append({
                                    'name': name,
                                    'version': version or 'unknown',
                                    'vendor': 'unknown',
                                    'type': 'requires',
                                    'file': filepath
                                })
        except Exception as e:
            print(f"Error parsing {filepath}: {e}")

        return packages

    def _parse_pipfile(self, filepath):
        """Parse Pipfile to extract dependencies

        Args:
            filepath (str): Path to Pipfile

        Returns:
            list<dict>: List of packages
        """
        packages = []
        try:
            import toml
            with open(filepath, 'r', encoding='utf-8') as f:
                content = toml.load(f)

            if 'packages' in content:
                for name, version in content['packages'].items():
                    if isinstance(version, str):
                        v = version
                    elif isinstance(version, dict):
                        v = version.get('version', 'unknown')
                    else:
                        v = 'unknown'

                    packages.append({
                        'name': name,
                        'version': v,
                        'vendor': 'unknown',
                        'type': 'requires',
                        'file': filepath
                    })
        except Exception as e:
            print(f"Error parsing {filepath}: {e}")

        return packages

    def _parse_requirement_line(self, line):
        """Parse a single requirement line to extract name and version

        Args:
            line (str): A requirement line

        Returns:
            tuple: (name, version)
        """
        # Handle various formats: name, name==1.0, name>=1.0, name[extra]==1.0, etc.
        # Extract the package name (before any version specifier or extras)
        match = re.match(r'^([a-zA-Z0-9_\-\.]+)', line)
        if not match:
            return None, None

        name = match.group(1)

        # Extract version if present
        version = None
        if '==' in line:
            parts = line.split('==')
            version = parts[1].split(';')[0].split('#')[0].strip()
        elif '>=' in line:
            parts = line.split('>=')
            version = f'>={parts[1].split(";")[0].split("#")[0].strip()}'
        elif '~=' in line:
            parts = line.split('~=')
            version = f'~={parts[1].split(";")[0].split("#")[0].strip()}'
        elif '!=' in line:
            parts = line.split('!=')
            version = f'!={parts[1].split(";")[0].split("#")[0].strip()}'

        return name, version

    def _deduplicate_packages(self, packages):
        """Remove duplicate packages based on name

        Args:
            packages (list<dict>): List of packages

        Returns:
            list<dict>: Deduplicated list
        """
        seen = {}
        for pkg in packages:
            key = pkg['name'].lower()
            if key not in seen:
                seen[key] = pkg
        return list(seen.values())
