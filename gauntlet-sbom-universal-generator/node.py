import json
import os


class NodeExtractor:
    def __init__(self, path):
        self.path = path

    def extract_packages(self):
        """Extract JavaScript/TypeScript packages from package.json and package-lock.json

        Returns:
            list<dict<{'category': list<packages>}>: packages -> {'name': '', 'version': '','vendor' : '', 'type': '', 'file':''}
        """
        packages = []
        dev_packages = []

        # Find and parse package.json files
        for root, folders, files in os.walk(self.path):
            # Skip node_modules
            folders[:] = [f for f in folders if f != 'node_modules']

            for file in files:
                if file == "package.json":
                    filepath = os.path.join(root, file)
                    reqs_deps, reqs_dev = self._parse_package_json(filepath)
                    packages.extend(reqs_deps)
                    dev_packages.extend(reqs_dev)

        # Remove duplicates
        packages = self._deduplicate_packages(packages)
        dev_packages = self._deduplicate_packages(dev_packages)

        result = []
        if packages:
            result.append({'javascript': packages})
        if dev_packages:
            result.append({'javascript_dev_packages': dev_packages})

        return result if result else [{'javascript': []}]

    def _parse_package_json(self, filepath):
        """Parse package.json file to extract dependencies

        Args:
            filepath (str): Path to package.json

        Returns:
            tuple: (packages, dev_packages)
        """
        packages = []
        dev_packages = []

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = json.load(f)

            # Extract dependencies
            if 'dependencies' in content:
                for name, version in content['dependencies'].items():
                    packages.append({
                        'name': name,
                        'version': version or 'unknown',
                        'vendor': 'unknown',
                        'type': 'requires',
                        'file': filepath
                    })

            # Extract devDependencies
            if 'devDependencies' in content:
                for name, version in content['devDependencies'].items():
                    dev_packages.append({
                        'name': name,
                        'version': version or 'unknown',
                        'vendor': 'unknown',
                        'type': 'dev requires',
                        'file': filepath
                    })

            # Extract peerDependencies
            if 'peerDependencies' in content:
                for name, version in content['peerDependencies'].items():
                    packages.append({
                        'name': name,
                        'version': version or 'unknown',
                        'vendor': 'unknown',
                        'type': 'peer requires',
                        'file': filepath
                    })

        except Exception as e:
            print(f"Error parsing {filepath}: {e}")

        return packages, dev_packages

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
