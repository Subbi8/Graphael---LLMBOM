import json
import logging
import os
import re
import time
from collections import defaultdict
from typing import Any
from urllib.parse import quote

import requests

# Constants
NVD_RATE_LIMIT_DELAY = 0.6
GITHUB_RATE_LIMIT_DELAY = 0.2
MAX_ITERATIONS = 10
MAX_SEARCH_RESULTS = 20
MAX_PAGINATION_PAGES = 50
TAGS_PER_PAGE = 100
API_TIMEOUT = 15
HEAD_REQUEST_TIMEOUT = 5
DEFAULT_ENCODING = 'utf-8'
JSON_INDENT = 2

# Configure logging for clean output
logging.basicConfig(
    level=logging.WARNING, # Changed to INFO for more visibility during development
    format='%(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

# --- Third-party library imports (Removed unnecessary try-except if they are hard dependencies) ---
# If these are truly optional, then the try-except is fine, but the logic relying on them
# needs to robustly handle their absence. Assuming for now they are essential.
try:
    from exploit_fix import ExploitResolver as BaseExploitResolver
    class ExploitResolverWrapper:
        """Wrapper class to provide the expected interface for ExploitResolver."""
        def __init__(self):
            self.base_resolver = BaseExploitResolver()
        def fetch_exploit_data_for_cve(self, cve_id: str, package_name: str,
                                       version: str, ecosystem: str) -> dict[str, Any]:
            return self.base_resolver.vdb_searcher.fetch_exploit_data_for_cve(
                cve_id, package_name, version, ecosystem
            )
        def create_exploit_fix_field(self, vulnerability: dict[str, Any],
                                      package_name: str) -> dict[str, Any]:
            return self.base_resolver.exploit_fix_creator.create_exploit_fix_field(
                vulnerability, package_name
            )
        def enhance_vulnerability_with_exploits(self, vulnerability: dict[str, Any],
                                                 package_name: str,
                                                 package_version: str,
                                                 ecosystem: str) -> dict[str, Any]:
            return self.base_resolver.enhance_vulnerability_with_exploits(
                vulnerability, package_name, package_version, ecosystem
            )
        def enhance_sbom_package_with_exploits(self,
                                                 sbom_package: dict[str, Any]) -> dict[str, Any]:
            return self.base_resolver.enhance_sbom_package_with_exploits(sbom_package)

    ExploitResolver = ExploitResolverWrapper
    EXPLOIT_RESOLVER_AVAILABLE = True
    logger.info("Exploit Resolver module loaded successfully.")
except ImportError:
    EXPLOIT_RESOLVER_AVAILABLE = False
    logger.warning("WARNING: Exploit Resolver module (exploit_fix.py) not found. Exploit detection will be disabled.")

try:
    from github_validation_july import validate_version_for_recursion
    GITHUB_VALIDATION_AVAILABLE = True
    logger.info("GitHub validation module loaded successfully")
except ImportError:
    GITHUB_VALIDATION_AVAILABLE = False
    logger.warning("WARNING: GitHub validation module not available. GitHub validation will be disabled.")

try:
    from vdb.lib import search
    VDB_AVAILABLE = True
except ImportError:
    VDB_AVAILABLE = False
    logger.warning(
        "VDB library not available. Will use alternative CVE data sources where possible, but core functionality may be limited."
    )

class BetaVersionDetector:
    """Detects beta/pre-release versions in package version strings."""

    def __init__(self):
        """Initialize beta version patterns."""
        self.beta_patterns = [
            r'.*[a]\d*$',    # ends with a, b, c followed by optional digits (alpha)
            r'.*[b]\d*$',    # ends with b followed by optional digits (beta)
            r'.*[c]\d*$',    # ends with c followed by optional digits (candidate)
            r'.*rc\d*$',     # contains 'rc' followed by optional digits
            r'.*alpha.*',    # contains 'alpha'
            r'.*beta.*',     # contains 'beta'
            r'.*pre.*',      # contains 'pre'
            r'.*dev.*',      # contains 'dev'
            r'.*snapshot.*', # contains 'snapshot'
            r'.*-M\d+$',     # Maven milestones (e.g., 1.0-M1)
            r'.*-RC\d+$',    # Maven release candidates
            r'.*-BETA$',     # General BETA suffix
        ]

    def is_beta_version(self, version_str: str) -> bool:
        """
        Check if a version string represents a beta/pre-release version.

        Args:
            version_str: Version string to check

        Returns:
            True if version is beta/pre-release, False otherwise
        """
        if not version_str:
            return False

        # Clean version by removing operators
        clean_version = re.sub(r'^[<>=^~]+', '', version_str.strip())

        # Check for beta indicators
        for pattern in self.beta_patterns:
            if re.match(pattern, clean_version, re.IGNORECASE):
                return True

        return False


class VersionParser:
    """Handles version string parsing and comparison."""

    def parse_version(self, version_str: str) -> tuple[int, ...]:
        """
        Parse version string into comparable tuple for semantic version comparison.
        Handles semantic versioning including letter suffixes (a, b, c, etc.)
        """
        if not version_str:
            return (0,)

        try:
            # Remove version range operators like <, <=, >, >=, ^, ~
            clean_version = re.sub(r'^[<>=^~]+', '', str(version_str).strip())

            # Remove common prefixes
            clean_version = clean_version.lstrip('v').lstrip('V')

            # Handle versions with letter suffixes (1.1.1c -> 1.1.1.3)
            # Extract the main version and any letter suffix
            match = re.match(r'^(\d+(?:\.\d+)*)([a-zA-Z]+\d*)?', clean_version)
            if not match:
                return (0,)

            main_version = match.group(1)
            suffix = match.group(2) or ""

            # Parse main version parts
            parts = []
            for part in main_version.split('.'):
                if part.isdigit():
                    parts.append(int(part))

            # Handle letter suffix (a=1, b=2, c=3, etc.)
            if suffix:
                # Extract the letter part and digits
                letter_match = re.match(r'^([a-zA-Z]+)(\d*)', suffix)
                if letter_match:
                    letter_chars = letter_match.group(1).lower()
                    letter_value = 0
                    # Convert multi-letter suffixes (e.g., 'alpha' -> sum of char values)
                    for char in letter_chars:
                        letter_value = letter_value * 26 + (ord(char) - ord('a') + 1)

                    parts.append(letter_value)

                    # Add any trailing digits from the suffix
                    digit_suffix = letter_match.group(2)
                    if digit_suffix:
                        parts.append(int(digit_suffix))

            return tuple(parts) if parts else (0,)

        except (ValueError, AttributeError) as e:
            logger.warning(f"Failed to parse version '{version_str}': {e}")
            return (0,)

    def version_in_range(self, version: str, version_range: str) -> bool:
        """
        Check if a version falls within a version range.
        Supports ranges like: >=6.2.0, <=6.2.5, >6.1.0, <6.1.4, etc.
        """
        try:
            version_tuple = self.parse_version(version)

            # Handle different range operators
            if version_range.startswith('>='):
                range_version = self.parse_version(version_range[2:])
                return version_tuple >= range_version
            elif version_range.startswith('<='):
                range_version = self.parse_version(version_range[2:])
                return version_tuple <= range_version
            elif version_range.startswith('>'):
                range_version = self.parse_version(version_range[1:])
                return version_tuple > range_version
            elif version_range.startswith('<'):
                range_version = self.parse_version(version_range[1:])
                return version_tuple < range_version
            elif version_range.startswith('='):
                range_version = self.parse_version(version_range[1:])
                return version_tuple == range_version
            else:
                # Exact match
                range_version = self.parse_version(version_range)
                return version_tuple == range_version

        except Exception as e:
            logger.warning(
                f"Failed to check version range {version} in {version_range}: {e}"
            )
            return False


class MultiEcosystemVersionFetcher:
    """
    Fetches latest versions from multiple package ecosystems.
    """

    def __init__(self):
        """Initialize the version fetcher with session and cache."""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CVE-Optimizer-Latest-Version-Checker/1.0'
        })
        # Cache to avoid duplicate API calls for same packages
        self.version_cache = {}

    def detect_ecosystem(self, package_name: str, vendor: list[str],
                            purl_prefix: str = "") -> str:
        """Detect the package ecosystem based on various indicators."""

        # Priority 1: Check purl_prefix first (most reliable)
        if purl_prefix:
            if "pkg:npm/" in purl_prefix:
                return "npm"
            elif "pkg:pypi/" in purl_prefix:
                return "pypi"
            elif "pkg:maven/" in purl_prefix:
                return "maven"
            elif "pkg:nuget/" in purl_prefix:
                return "nuget"
            elif "pkg:cargo/" in purl_prefix:
                return "cargo"
            elif "pkg:gem/" in purl_prefix:
                return "gem"
            elif "pkg:composer/" in purl_prefix:
                return "composer"
            elif "pkg:golang/" in purl_prefix or "pkg:go/" in purl_prefix:
                return "golang"
            elif "pkg:generic/" in purl_prefix:
                return "generic"

        # Priority 2: Check vendor information
        if vendor:
            vendor_str = " ".join(vendor).lower()
            if "npm" in vendor_str or any(v.startswith('@') for v in vendor):
                return "npm"
            elif "pypi" in vendor_str or "python" in vendor_str or "pip" in vendor_str:
                return "pypi"
            elif "maven" in vendor_str or "mvn" in vendor_str or "java" in vendor_str:
                return "maven"
            elif "nuget" in vendor_str or ".net" in vendor_str or "dotnet" in vendor_str:
                return "nuget"
            elif "cargo" in vendor_str or "rust" in vendor_str or "crate" in vendor_str:
                return "cargo"
            elif "gem" in vendor_str or "ruby" in vendor_str or "rubygems" in vendor_str:
                return "gem"
            elif "composer" in vendor_str or "php" in vendor_str or "packagist" in vendor_str:
                return "composer"
            elif "golang" in vendor_str or "go" in vendor_str:
                return "golang"

        # Priority 3: Check package name structure patterns (more general, less specific than hardcoded lists)
        #package_lower = package_name.lower()

        if package_name.startswith('@') and '/' in package_name:
            return "npm"  # Scoped npm packages like @angular/core
        elif ':' in package_name:
            # Could be Maven (groupId:artifactId) or Composer (vendor/package)
            # Maven often uses multiple dots in groupId, Composer uses slash
            parts = package_name.split(':', 1)
            if '.' in parts[0] or parts[0].count('/') == 0: # Heuristic for Maven group ID
                 return "maven"
            else: # Heuristic for Composer
                 return "composer"
        elif package_name.count('.') >= 2:
            return "maven"  # Common Java package naming convention (e.g., org.apache.commons.lang3)
        elif package_name.startswith('github.com/') or '/' in package_name:
            # This pattern is tricky as many ecosystems use GitHub.
            # However, for Go, the module path often directly reflects the GitHub path.
            # If not already detected, this is a strong indicator for golang.
            return "golang"
        elif '-' in package_name or '_' in package_name:
            # Common for Python (kebab-case, snake_case) and NPM (kebab-case).
            # Default to PyPI as a common fallback for these formats.
            return "pypi"

        # Default fallback if no specific pattern matches
        return "generic"

    def construct_full_package_name(self, package_name: str, vendor: list[str],
                                    ecosystem: str) -> str:
        """Construct the full package name including scope if needed."""
        if ecosystem == "npm":
            if package_name.startswith('@'):
                return package_name

            # Special handling for packages that start with underscore (converted scopes)
            # This is a less common case, but might occur from certain SBOM tools
            if package_name.startswith('_'):
                potential_scoped_name = package_name.replace('_', '@', 1)
                if self._npm_package_exists(potential_scoped_name):
                    return potential_scoped_name

            # Try to infer scope from vendor if not already scoped
            for v in vendor:
                if v and v != '*' and self._could_be_npm_scope(v):
                    potential_scoped_name = f"@{v}/{package_name}"
                    if self._npm_package_exists(potential_scoped_name):
                        return potential_scoped_name
        elif ecosystem == "maven":
            # Maven names often are "group:artifact". If only artifact, try to find group in vendor.
            if ':' not in package_name and vendor:
                for v in vendor:
                    # Very simple heuristic: if vendor looks like a java package name
                    if '.' in v:
                        potential_maven_name = f"{v}:{package_name}"
                        # No easy way to validate Maven package existence without a full search.
                        # For now, we return the constructed name.
                        return potential_maven_name
        return package_name

    def _could_be_npm_scope(self, vendor: str) -> bool:
        """Check if a vendor string could be an npm scope."""
        # Skip obvious non-scopes
        if vendor.lower() in ['*', 'npm', 'node', 'javascript', 'js', 'common', 'apache', 'google', 'microsoft']:
            return False

        # Common scope patterns: starts with letter, contains dash, not too short
        if re.match(r'^[a-z][a-z0-9-]{1,}$', vendor.lower()):
            return True

        return False

    def _npm_package_exists(self, package_name: str) -> bool:
        """Quick check if an npm package exists using lightweight HEAD request."""
        try:
            # NPM registry uses URL-encoded slashes for scoped packages
            encoded_name = quote(package_name, safe='')

            url = f"https://registry.npmjs.org/{encoded_name}"

            # Use HEAD request for faster checking
            response = self.session.head(url, timeout=HEAD_REQUEST_TIMEOUT)
            return response.status_code == 200

        except Exception:
            return False

    def get_latest_npm_version(self, package_name: str) -> dict[str, str] | None:
        """Fetch latest version for npm packages."""
        try:
            encoded_name = quote(package_name, safe='') # URL-encode the package name
            url = f"https://registry.npmjs.org/{encoded_name}/latest"
            response = self.session.get(url, timeout=API_TIMEOUT)

            if response.status_code == 200:
                data = response.json()
                version = data.get('version')
                if version:
                    npm_url = f"https://www.npmjs.com/package/{package_name}/v/{version}"
                    return {
                        "version": version,
                        "url": npm_url
                    }
            elif response.status_code == 404:
                logger.debug(f"NPM package not found: {package_name}")
                return None
            else:
                logger.warning(
                    f"Failed to fetch NPM version for {package_name}: {response.status_code}"
                )
                return None

        except Exception as e:
            logger.error(f"Error fetching NPM version for {package_name}: {str(e)}")
            return None

    def get_latest_pypi_version(self, package_name: str) -> dict[str, str] | None:
        """Fetch latest version for Python packages from PyPI."""
        try:
            # PyPI prefers lowercase names for simple API
            clean_package_name = package_name.lower().replace('.', '-') # Normalize often for PyPI

            url = f"https://pypi.org/pypi/{clean_package_name}/json"
            response = self.session.get(url, timeout=API_TIMEOUT)

            if response.status_code == 200:
                data = response.json()
                version = data.get('info', {}).get('version')
                if version:
                    pypi_url = f"https://pypi.org/project/{clean_package_name}/{version}/"
                    return {
                        "version": version,
                        "url": pypi_url
                    }
            elif response.status_code == 404:
                # If lowercase fails, try the original casing (though less common for PyPI)
                if clean_package_name != package_name:
                    url = f"https://pypi.org/pypi/{package_name}/json"
                    response = self.session.get(url, timeout=API_TIMEOUT)
                    if response.status_code == 200:
                        data = response.json()
                        version = data.get('info', {}).get('version')
                        if version:
                            pypi_url = f"https://pypi.org/project/{package_name}/{version}/"
                            return {
                                "version": version,
                                "url": pypi_url
                            }
                logger.debug(f"PyPI package not found: {package_name}")
                return None
            else:
                logger.warning(
                    f"Failed to fetch PyPI version for {package_name}: {response.status_code}"
                )
                return None

        except Exception as e:
            logger.error(f"Error fetching PyPI version for {package_name}: {str(e)}")
            return None

    def get_latest_maven_version(self, package_name: str) -> dict[str, str] | None:
        """Fetch latest version for Maven packages."""
        try:
            group_id = ""
            artifact_id = package_name
            if ':' in package_name:
                group_id, artifact_id = package_name.split(':', 1)

            # Maven Central Search API
            url = "https://search.maven.org/solrsearch/select"
            params = {
                'q': f'g:"{group_id}" AND a:"{artifact_id}"' if group_id else f'a:"{artifact_id}"',
                'rows': 1,
                'wt': 'json',
                'core': 'gav' # Search by GAV
            }

            response = self.session.get(url, params=params, timeout=API_TIMEOUT)

            if response.status_code == 200:
                data = response.json()
                docs = data.get('response', {}).get('docs', [])
                if docs:
                    version = docs[0].get('latestVersion')
                    # Prefer 'v' prefixed versions if available and newer
                    # This logic is simplified; a more robust parser would be better
                    release_version = docs[0].get('release')
                    if release_version and (not version or VersionParser().parse_version(release_version) > VersionParser().parse_version(version)):
                        version = release_version

                    if version:
                        # Construct Maven Central URL for this version
                        actual_group_id = docs[0].get('g', group_id)
                        actual_artifact_id = docs[0].get('a', artifact_id)
                        maven_url = f"https://search.maven.org/artifact/{actual_group_id}/{actual_artifact_id}/{version}"
                        return {
                            "version": version,
                            "url": maven_url
                        }
                else:
                    logger.debug(f"Maven package not found: {package_name}")
                    return None
            else:
                logger.warning(
                    f"Failed to fetch Maven version for {package_name}: {response.status_code}"
                )
                return None

        except Exception as e:
            logger.error(f"Error fetching Maven version for {package_name}: {str(e)}")
            return None

    def get_latest_nuget_version(self, package_name: str) -> dict[str, str] | None:
        """Fetch latest version for NuGet packages."""
        try:
            # NuGet API requires package ID to be lowercase
            url = f"https://api.nuget.org/v3-flatcontainer/{package_name.lower()}/index.json"
            response = self.session.get(url, timeout=API_TIMEOUT)

            if response.status_code == 200:
                data = response.json()
                versions = data.get('versions', [])
                if versions:
                    # Versions are typically sorted, so the last one is the latest stable
                    # Filter out pre-release versions
                    stable_versions = [v for v in versions if not BetaVersionDetector().is_beta_version(v)]
                    if stable_versions:
                        version = stable_versions[-1]
                        nuget_url = f"https://www.nuget.org/packages/{package_name}/{version}"
                        return {
                            "version": version,
                            "url": nuget_url
                        }
                logger.debug(f"NuGet package versions not found or only pre-release: {package_name}")
                return None
            elif response.status_code == 404:
                logger.debug(f"NuGet package not found: {package_name}")
                return None
            else:
                logger.warning(
                    f"Failed to fetch NuGet version for {package_name}: {response.status_code}"
                )
                return None

        except Exception as e:
            logger.error(f"Error fetching NuGet version for {package_name}: {str(e)}")
            return None

    def get_latest_cargo_version(self, package_name: str) -> dict[str, str] | None:
        """Fetch latest version for Rust packages from crates.io."""
        try:
            url = f"https://crates.io/api/v1/crates/{package_name}"
            response = self.session.get(url, timeout=API_TIMEOUT)

            if response.status_code == 200:
                data = response.json()
                # max_version is typically the latest stable version
                version = data.get('crate', {}).get('max_version')
                if version:
                    cargo_url = f"https://crates.io/crates/{package_name}/{version}"
                    return {
                        "version": version,
                        "url": cargo_url
                    }
                logger.debug(f"Cargo package max_version not found: {package_name}")
                return None
            elif response.status_code == 404:
                logger.debug(f"Cargo package not found: {package_name}")
                return None
            else:
                logger.warning(
                    f"Failed to fetch Cargo version for {package_name}: {response.status_code}"
                )
                return None

        except Exception as e:
            logger.error(f"Error fetching Cargo version for {package_name}: {str(e)}")
            return None

    def get_latest_gem_version(self, package_name: str) -> dict[str, str] | None:
        """Fetch latest version for Ruby gems."""
        try:
            url = f"https://rubygems.org/api/v1/gems/{package_name}.json"
            response = self.session.get(url, timeout=API_TIMEOUT)

            if response.status_code == 200:
                data = response.json()
                version = data.get('version')
                if version:
                    gem_url = f"https://rubygems.org/gems/{package_name}/versions/{version}"
                    return {
                        "version": version,
                        "url": gem_url
                    }
                logger.debug(f"Gem package version not found: {package_name}")
                return None
            elif response.status_code == 404:
                logger.debug(f"Gem package not found: {package_name}")
                return None
            else:
                logger.warning(
                    f"Failed to fetch Gem version for {package_name}: {response.status_code}"
                )
                return None

        except Exception as e:
            logger.error(f"Error fetching Gem version for {package_name}: {str(e)}")
            return None

    def get_latest_composer_version(self, package_name: str) -> dict[str, str] | None:
        """Fetch latest version for PHP packages from Packagist."""
        try:
            url = f"https://repo.packagist.org/p/{package_name}.json"
            response = self.session.get(url, timeout=API_TIMEOUT)

            if response.status_code == 200:
                data = response.json()
                packages = data.get('packages', {}).get(package_name, {})
                if packages:
                    # Packagist versions are not always strictly ordered; parse and find latest stable
                    versions = list(packages.keys())
                    beta_detector = BetaVersionDetector()
                    version_parser = VersionParser()

                    stable_versions = []
                    for v in versions:
                        if not beta_detector.is_beta_version(v):
                            stable_versions.append(v)

                    if stable_versions:
                        # Find the maximum version among stable ones
                        version = max(stable_versions, key=version_parser.parse_version)
                        composer_url = f"https://packagist.org/packages/{package_name}#{version}"
                        return {
                            "version": version,
                            "url": composer_url
                        }
                logger.debug(f"Composer package versions not found or only pre-release: {package_name}")
                return None
            elif response.status_code == 404:
                logger.debug(f"Composer package not found: {package_name}")
                return None
            else:
                logger.warning(
                    f"Failed to fetch Composer version for {package_name}: {response.status_code}"
                )
                return None

        except Exception as e:
            logger.error(f"Error fetching Composer version for {package_name}: {str(e)}")
            return None

    def get_latest_golang_version(self, package_name: str) -> dict[str, str] | None:
        """Fetch latest version for Go packages from proxy.golang.org."""
        try:
            # Go module paths can be complex, ensure it's URL-encoded
            encoded_package_name = quote(package_name, safe='')

            url = f"https://proxy.golang.org/{encoded_package_name}/@v/list"
            response = self.session.get(url, timeout=API_TIMEOUT)

            if response.status_code == 200:
                versions_text = response.text.strip()
                if versions_text:
                    versions = versions_text.split('\n')
                    beta_detector = BetaVersionDetector()
                    version_parser = VersionParser()

                    stable_versions = []
                    for v in versions:
                        if not beta_detector.is_beta_version(v) and re.match(r'^v?\d+\.\d+\.\d+$', v):
                            stable_versions.append(v)

                    if stable_versions:
                        # Find the maximum version among stable ones
                        version = max(stable_versions, key=version_parser.parse_version)
                        golang_url = f"https://pkg.go.dev/{package_name}@{version}"
                        return {
                            "version": version,
                            "url": golang_url
                        }
                logger.debug(f"Golang package versions not found or only pre-release: {package_name}")
                return None
            elif response.status_code == 404:
                logger.debug(f"Golang package not found: {package_name}")
                return None
            else:
                logger.warning(
                    f"Failed to fetch Golang version for {package_name}: {response.status_code}"
                )
                return None

        except Exception as e:
            logger.error(f"Error fetching Golang version for {package_name}: {str(e)}")
            return None

    def get_latest_generic_version(self, package_name: str) -> dict[str, str] | None:
        """Placeholder for generic packages - returns None as no universal registry."""
        return None

    def get_latest_version(self, package_name: str, vendor: list[str],
                            purl_prefix: str = "") -> tuple[dict[str, str] | None, str]:
        """Get latest version based on detected ecosystem."""
        # Detect the ecosystem
        ecosystem = self.detect_ecosystem(package_name, vendor, purl_prefix)

        # Construct full package name if needed (e.g., for NPM scopes)
        full_package_name = self.construct_full_package_name(
            package_name, vendor, ecosystem
        )

        # Use cache if available
        cache_key = f"{ecosystem}-{full_package_name}"
        if cache_key in self.version_cache:
            return self.version_cache[cache_key], ecosystem

        latest_version_info = None

        logger.debug(
            f"Package: {package_name}, Detected ecosystem: {ecosystem}, "
            f"Full name: {full_package_name}"
        )

        # Fetch version based on ecosystem
        if ecosystem == "npm":
            latest_version_info = self.get_latest_npm_version(full_package_name)
            if not latest_version_info and full_package_name != package_name: # Fallback if scoped fails
                latest_version_info = self.get_latest_npm_version(package_name)
        elif ecosystem == "pypi":
            latest_version_info = self.get_latest_pypi_version(full_package_name)
            if not latest_version_info and full_package_name != package_name: # Fallback if modified lookup fails
                latest_version_info = self.get_latest_pypi_version(package_name)
        elif ecosystem == "maven":
            latest_version_info = self.get_latest_maven_version(full_package_name)
        elif ecosystem == "nuget":
            latest_version_info = self.get_latest_nuget_version(full_package_name)
        elif ecosystem == "cargo":
            latest_version_info = self.get_latest_cargo_version(full_package_name)
        elif ecosystem == "gem":
            latest_version_info = self.get_latest_gem_version(full_package_name)
        elif ecosystem == "composer":
            latest_version_info = self.get_latest_composer_version(full_package_name)
        elif ecosystem == "golang":
            latest_version_info = self.get_latest_golang_version(full_package_name)
        elif ecosystem == "generic":
            latest_version_info = self.get_latest_generic_version(full_package_name)

        # If primary ecosystem fails, try fallback ecosystems for common packages
        if not latest_version_info:
            fallback_ecosystems = self._get_fallback_ecosystems(ecosystem)

            for fallback_eco in fallback_ecosystems:
                try:
                    if fallback_eco == "pypi":
                        latest_version_info = self.get_latest_pypi_version(package_name)
                    elif fallback_eco == "npm":
                        latest_version_info = self.get_latest_npm_version(package_name)
                    elif fallback_eco == "maven":
                        latest_version_info = self.get_latest_maven_version(package_name)

                    if latest_version_info:
                        logger.debug(
                            f"Found {package_name} in fallback ecosystem: {fallback_eco}"
                        )
                        ecosystem = fallback_eco  # Update the detected ecosystem
                        break
                except Exception as e:
                    logger.debug(f"Fallback {fallback_eco} failed for {package_name}: {e}")
                    continue

        # Cache the result
        self.version_cache[cache_key] = latest_version_info

        # Add delay to respect rate limits
        time.sleep(0.1)

        return latest_version_info, ecosystem

    def _get_fallback_ecosystems(self, ecosystem: str) -> list[str]:
        """Get fallback ecosystems for the given ecosystem."""
        # Fallback order should be sensible. PyPI and NPM are very common.
        if ecosystem == "npm":
            return ["pypi"]
        elif ecosystem == "pypi":
            return ["npm"]
        elif ecosystem == "maven":
            return ["pypi", "npm"] # Maven can sometimes be a generic name that exists elsewhere
        elif ecosystem == "generic":
            return ["pypi", "npm", "maven"] # Try common ones if generic
        return []


class MalwareDetector:
    """Detects malware packages based on CVE prefixes and version data."""

    def is_malware_package(self, package_data: dict[str, Any]) -> bool:
        """
        Check if a package contains any CVE that starts with "MAL" prefix
        or if it's explicitly marked as a malware package.
        """
        # Check for null or missing first_optimal_version (indicates malware exclusion)
        first_optimal_version = package_data.get('first_optimal_version')
        if not first_optimal_version:
            # If there's no optimal version data, it might imply it was filtered out
            # earlier as malware, or it simply had no vulnerabilities.
            # We need to be more explicit if this field missing guarantees malware.
            # Assuming for now this field being empty isn't *solely* for malware.
            pass

        # Check if first_optimal_version indicates malware package directly
        if isinstance(first_optimal_version, dict):
            high_critical_data = first_optimal_version.get('High and critical cves', {})
            all_cves_data = first_optimal_version.get('All cves', {})

            # Check recommendation details for malware flags
            high_critical_details = high_critical_data.get('recommendation_details', {})
            all_cves_details = all_cves_data.get('recommendation_details', {})

            if (high_critical_details.get('malware_package') or
                high_critical_details.get('package_excluded') or
                all_cves_details.get('malware_package') or
                all_cves_details.get('package_excluded')):
                return True

        # Check vulnerabilities for MAL prefix
        vulnerabilities = (package_data.get('vulnerabilties', []) or
                           package_data.get('vulnerabilities', []))

        for vuln in vulnerabilities:
            cve_id = vuln.get('cve_id', '')
            if cve_id.upper().startswith('MAL'):
                return True

        return False

    def is_malware_cve(self, cve_id: str) -> bool:
        """
        Check if a CVE ID represents a malware-related vulnerability.
        """
        if not cve_id or not isinstance(cve_id, str):
            return False

        return cve_id.upper().startswith('MAL')


class EcosystemDetector:
    """Determines package ecosystem based on package data."""

    def determine_package_ecosystem(self, package_data: dict[str, Any]) -> str:
        """
        Determine package ecosystem based on package data.
        """
        package_name = package_data.get('package_name', '')

        # Use MultiEcosystemVersionFetcher's more robust detection logic
        # It's already equipped to handle various fields like purl_prefix and vendor.
        # This prevents duplicating detection logic and ensures consistency.
        fetcher = MultiEcosystemVersionFetcher() # Create an instance to use its methods
        ecosystem = fetcher.detect_ecosystem(
            package_name=package_name,
            vendor=package_data.get('vendor', []),
            purl_prefix=package_data.get('purl_prefix', '')
        )

        # Add any specific overriding rules if absolutely necessary, but keep minimal.
        # For example, if 'libxml2' is definitively 'generic' regardless of other indicators.
        if package_name.lower() == 'xmlsoft/libxml2' or package_name.lower() == 'libxml2':
            return 'generic'

        return ecosystem


class PurlCreator:
    """Creates Package URL (PURL) for different ecosystems."""

    def create_purl(self, package_name: str, version: str, ecosystem: str) -> str:
        """
        Create Package URL (PURL) for different ecosystems.
        """
        encoded_package_name = quote(package_name, safe='')
        encoded_version = quote(version, safe='')

        if ecosystem == 'pypi':
            return f"pkg:pypi/{encoded_package_name}@{encoded_version}"
        elif ecosystem == 'npm':
            # npm scoped packages need special handling for the slash in PURL
            if package_name.startswith('@') and '/' in package_name:
                scope_part, name_part = package_name.split('/', 1)
                encoded_scope = quote(scope_part, safe='')
                encoded_name = quote(name_part, safe='')
                return f"pkg:npm/{encoded_scope}/{encoded_name}@{encoded_version}"
            return f"pkg:npm/{encoded_package_name}@{encoded_version}"
        elif ecosystem == 'maven':
            # Maven PURLs usually require group:artifact
            if ':' in package_name:
                group_id, artifact_id = package_name.split(':', 1)
                return f"pkg:maven/{quote(group_id, safe='')}/{quote(artifact_id, safe='')}@{encoded_version}"
            else:
                # If only artifact_id is given, try to make a best guess or use a generic representation.
                # This might be less accurate without group_id.
                return f"pkg:maven/{encoded_package_name}/{encoded_package_name}@{encoded_version}"
        elif ecosystem == 'nuget':
            return f"pkg:nuget/{encoded_package_name}@{encoded_version}"
        elif ecosystem == 'cargo':
            return f"pkg:cargo/{encoded_package_name}@{encoded_version}"
        elif ecosystem == 'gem':
            return f"pkg:gem/{encoded_package_name}@{encoded_version}"
        elif ecosystem == 'composer':
            return f"pkg:composer/{encoded_package_name}@{encoded_version}"
        elif ecosystem == 'golang':
            return f"pkg:golang/{encoded_package_name}@{encoded_version}"
        else:
            # Default to generic format, which is less specific but always works
            return f"pkg:generic/{encoded_package_name}@{encoded_version}"


class CveApplicabilityChecker:
    """Checks if CVEs are applicable to specific versions."""

    def is_cve_applicable_to_version(self, description: str,
                                     current_version: str) -> bool:
        """
        Determine if a CVE applies to the current version based on version series logic.

        NOTE: The original implementation simply returned True.
        For robust applicability, this method would need to parse affected/fixed
        version ranges from the description or other CVE data fields.
        Given the current scope, maintaining the conservative approach.
        """
        if not description:
            return True # Conservative approach - assume it applies if unclear

        # Implement more sophisticated logic here if specific version applicability
        # needs to be derived from the description text itself.
        # This would typically involve regex or NLP to find phrases like "affects versions X to Y"
        # or "fixed in Z". However, this is usually provided by the CVE source itself.

        return True


class FixedVersionExtractor:
    """Extracts fixed version information from CVE descriptions."""

    def __init__(self):
        """Initialize fixed version detection patterns."""
        self.fixed_version_patterns = [
            re.compile(
                r'Versions?\s+((?:\d+(?:\.\d+)*(?:[a-zA-Z0-9\-]*)?(?:\s*,\s*(?:and\s*)?)?)+)\s+fix(?:es)?\s+(?:the\s+)?(?:issue|vulnerability|problem)',
                re.IGNORECASE),
            re.compile(
                r'Versions?\s+((?:\d+(?:\.\d+)*(?:[a-zA-Z0-9\-]*)?(?:\s*,\s*(?:and\s*)?)?)+)\s+(?:contain|include|have)\s+(?:the\s+)?(?:fix|patch)',
                re.IGNORECASE),
            re.compile(
                r'(?:fixed\s+in|addressed\s+in|resolved\s+in|fix\s+was\s+released\s+in|been\s+addressed\s+in)\s+(?:version\s+)?(?:v)?(\d+(?:\.\d+)*(?:[a-zA-Z]\d*)?)',
                re.IGNORECASE),
            re.compile(
                r'(?:patched\s+in|patch\s+(?:available\s+)?in)\s+(?:version\s+)?(\d+(?:\.\d+)*(?:[a-zA-Z]\d*)?)',
                re.IGNORECASE),
            re.compile(
                r'upgraded\s+to\s+version\s+(?:v)?(\d+(?:\.\d+)*(?:[a-zA-Z]\d*)?)',
                re.IGNORECASE), # Added for common upgrade phrases
            re.compile(
                r'upgrade\s+to\s+(?:version\s+)?(\d+(?:\.\d+)*(?:[a-zA-Z]\d*)?)',
                re.IGNORECASE), # Added for common upgrade phrases
        ]
        self.beta_detector = BetaVersionDetector()

    def extract_versions_from_text(self, text: str) -> list[str]:
        """
        Extract version numbers from CVE description text using regex patterns.
        Excludes beta versions from extracted versions.
        """
        versions = set()

        for pattern in self.fixed_version_patterns:
            matches = pattern.findall(text)
            for match in matches:
                if isinstance(match, str):
                    # Handle comma-separated version lists
                    version_parts = re.split(r'[,\s]+(?:and\s+)?', match)
                    for part in version_parts:
                        # Extract clean version number
                        version_match = re.search(
                            r'(\d+(?:\.\d+)*(?:[a-zA-Z0-9\-]*)?)',
                            part.strip()
                        )
                        if version_match:
                            version = version_match.group(1)
                            # Exclude beta versions
                            if not self.beta_detector.is_beta_version(version):
                                versions.add(version)

        return list(versions)


class VdbResultProcessor:
    """Processes VulnerabilityDB search results."""

    def __init__(self):
        """Initialize VDB result processor."""
        self.beta_detector = BetaVersionDetector()

    def get_fix_version_from_vdb_result(self, result: Any) -> str | None:
        """
        Extract fix_version from VulnerabilityDB 6.4.3 search result.
        This is the primary source for fix version information.
        Excludes beta versions from recommendations.
        """
        try:
            # VDB results can be dicts or objects depending on how they are returned
            if isinstance(result, dict):
                fix_version = result.get('fix_version')
            else: # Assuming it's an object from VDB library
                fix_version = getattr(result, 'fix_version', None)

            if fix_version and str(fix_version).strip():
                version = str(fix_version).strip()
                # Exclude beta versions
                if not self.beta_detector.is_beta_version(version):
                    return version
        except (AttributeError, TypeError) as e:
            logger.debug(f"Failed to extract VDB fix_version from result type {type(result)}: {e}")

        return None

    def get_description_from_vdb_result(self, result: Any) -> str | None:
        """
        Extract CVE description from VulnerabilityDB search result.
        This is used as fallback when fix_version is empty.
        """
        try:
            source_data = (result.get('source_data') if isinstance(result, dict)
                           else getattr(result, 'source_data', None))

            if source_data and hasattr(source_data, 'root'):
                cve_root = source_data.root
                if (hasattr(cve_root, 'containers') and cve_root.containers):
                    if (hasattr(cve_root.containers, 'cna') and
                        cve_root.containers.cna):
                        if (hasattr(cve_root.containers.cna, 'descriptions') and
                            cve_root.containers.cna.descriptions):
                            descriptions = cve_root.containers.cna.descriptions.root
                            for desc in descriptions:
                                if hasattr(desc, 'value'):
                                    return desc.value
        except (AttributeError, TypeError) as e:
            logger.debug(f"Failed to extract VDB description from result type {type(result)}: {e}")

        return None


class GitHubSecurityAdvisorySearcher:
    """Searches GitHub Security Advisories for fixed version information."""

    def __init__(self):
        """Initialize GitHub Security Advisory searcher."""
        self.version_parser = VersionParser()
        self.beta_detector = BetaVersionDetector()
        self.session = requests.Session()
        self.session.headers.update({
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'CVE-Optimizer-GitHub-Advisory-Checker/1.0'
        })


    def search_github_security_advisory(self, ghsa_id: str, package_name: str,
                                         current_version: str) -> str | None:
        """
        Search GitHub Security Advisory for fixed version information.
        Based on actual GitHub API response structure with vulnerabilities array.
        Excludes beta versions from recommendations.
        """
        if not ghsa_id or not ghsa_id.startswith('GHSA-'):
            return None

        logger.debug(f"Searching GitHub Security Advisory for {ghsa_id}")

        try:
            time.sleep(GITHUB_RATE_LIMIT_DELAY)

            api_url = f"https://api.github.com/advisories/{ghsa_id}"

            response = self.session.get(api_url, timeout=API_TIMEOUT)

            if response.status_code == 200:
                advisory_data = response.json()

                vulnerabilities = advisory_data.get('vulnerabilities', [])

                applicable_patches = []

                for vulnerability in vulnerabilities:
                    package_info = vulnerability.get('package', {})
                    vuln_package_name = package_info.get('name', '')

                    if vuln_package_name.lower() != package_name.lower():
                        continue

                    vulnerable_version_range = vulnerability.get('vulnerable_version_range', '')
                    first_patched_version = vulnerability.get('first_patched_version')

                    # Check if current version is affected by this vulnerability entry
                    if (vulnerable_version_range and
                        self._is_version_affected_by_range(current_version, vulnerable_version_range)):
                        if (first_patched_version and
                            not self.beta_detector.is_beta_version(first_patched_version)):
                            try:
                                # Only consider patch versions higher than current version
                                if (self.version_parser.parse_version(first_patched_version) >
                                    self.version_parser.parse_version(current_version)):
                                    applicable_patches.append(first_patched_version)
                                    logger.debug(
                                        f"Found applicable patch for {ghsa_id}: "
                                        f"{first_patched_version} (range: {vulnerable_version_range})"
                                    )
                            except Exception as e:
                                logger.warning(
                                    f"Failed to parse first patched version "
                                    f"{first_patched_version}: {e}"
                                )
                                continue

                if applicable_patches:
                    min_patch_version = min(
                        applicable_patches,
                        key=self.version_parser.parse_version
                    )
                    logger.debug(
                        f"Found GitHub Advisory optimal patch version for "
                        f"{ghsa_id}: {min_patch_version}"
                    )
                    return min_patch_version

                # Fallback: try to extract from summary/description if no specific vulnerability entry matches
                if not vulnerabilities: # Only try description if 'vulnerabilities' array is empty
                     return self._extract_from_description(advisory_data, current_version)

            elif response.status_code == 404:
                logger.debug(f"GitHub Advisory {ghsa_id} not found")
            else:
                logger.warning(
                    f"Failed to fetch GitHub Advisory {ghsa_id}: {response.status_code}"
                )

        except Exception as e:
            logger.error(f"Error searching GitHub Advisory for {ghsa_id}: {e}")

        return None

    def _extract_from_description(self, advisory_data: dict[str, Any],
                                  current_version: str) -> str | None:
        """Extract fixed version from advisory description as fallback."""
        summary = advisory_data.get('summary', '')
        description = advisory_data.get('description', '')

        combined_text = f"{summary} {description}"
        extractor = FixedVersionExtractor()
        fixed_versions = extractor.extract_versions_from_text(combined_text)

        if fixed_versions:
            # Filter for versions higher than current
            current_parsed = self.version_parser.parse_version(current_version)
            higher_versions = []

            for version in fixed_versions:
                try:
                    if self.version_parser.parse_version(version) > current_parsed:
                        higher_versions.append(version)
                except Exception as e:
                    logger.warning(f"Failed to parse extracted version {version}: {e}")
                    continue

            if higher_versions:
                min_fixed_version = min(
                    higher_versions,
                    key=self.version_parser.parse_version
                )
                logger.debug(
                    f"Found GitHub Advisory fixed version in description: "
                    f"{min_fixed_version}"
                )
                return min_fixed_version

        return None

    def _is_version_affected_by_range(self, version: str,
                                     version_range: str) -> bool:
        """
        Check if a version is affected by a vulnerability range.
        Handles GitHub Security Advisory version range formats.
        """
        if not version_range:
            return True   # Conservative assumption if range is not specified

        try:
            version_tuple = self.version_parser.parse_version(version)

            # Split multiple conditions by comma (e.g., ">=1.0, <2.0")
            conditions = [cond.strip() for cond in version_range.split(',')]

            # All conditions must be true for the version to be affected
            for condition in conditions:
                condition = condition.strip()

                if condition.startswith('>='):
                    range_version = self.version_parser.parse_version(condition[2:].strip())
                    if not (version_tuple >= range_version):
                        return False
                elif condition.startswith('<='):
                    range_version = self.version_parser.parse_version(condition[2:].strip())
                    if not (version_tuple <= range_version):
                        return False
                elif condition.startswith('>'):
                    range_version = self.version_parser.parse_version(condition[1:].strip())
                    if not (version_tuple > range_version):
                        return False
                elif condition.startswith('<'):
                    range_version = self.version_parser.parse_version(condition[1:].strip())
                    if not (version_tuple < range_version):
                        return False
                elif condition.startswith('='):
                    range_version = self.version_parser.parse_version(condition[1:].strip())
                    if not (version_tuple == range_version):
                        return False
                elif condition.startswith('!=') or condition.startswith('! '): # Not equal
                    range_version = self.version_parser.parse_version(condition[2:].strip())
                    if (version_tuple == range_version): # If it *is* equal to an excluded version
                        return False
                else:
                    # Handle exact matches or cases like "6.1.0"
                    range_version = self.version_parser.parse_version(condition)
                    if not (version_tuple == range_version):
                        return False

            return True   # All conditions passed - version is affected

        except Exception as e:
            logger.warning(
                f"Failed to check if version {version} is affected by "
                f"range {version_range}: {e}. Assuming affected."
            )
            return True   # Conservative assumption on error


class NvdSearcher:
    """Searches NVD for fixed version information."""

    def __init__(self):
        """Initialize NVD searcher."""
        self.extractor = FixedVersionExtractor()
        self.beta_detector = BetaVersionDetector()
        self.session = requests.Session() # Use session for potential connection pooling

    def search_nvd_for_fixed_version(self, cve_id: str) -> str | None:
        """
        Search NVD for fixed version information.
        Excludes beta versions from recommendations.
        """
        if not cve_id or not cve_id.startswith('CVE-'):
            return None

        logger.debug(f"Searching NVD for {cve_id}")
        nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={quote(cve_id)}"

        try:
            time.sleep(NVD_RATE_LIMIT_DELAY)
            response = self.session.get(nvd_url, timeout=API_TIMEOUT)
            response.raise_for_status() # Raise an exception for HTTP errors
            nvd_data = response.json()

            if not nvd_data or 'vulnerabilities' not in nvd_data:
                logger.debug(f"No vulnerabilities found in NVD for {cve_id}")
                return None

            for vuln in nvd_data['vulnerabilities']:
                cve = vuln.get('cve', {})

                # Search in configurations (CPE data) first, as it's more structured
                configs = cve.get('configurations', [])
                for config in configs:
                    nodes = config.get('nodes', [])
                    for node in nodes:
                        cpe_matches = node.get('cpeMatch', [])
                        for cpe_match in cpe_matches:
                            # versionEndExcluding means fixed in this version or later
                            version_end_excluding = cpe_match.get('versionEndExcluding')
                            # versionEndIncluding means fixed in this version or later (inclusive)
                            version_end_including = cpe_match.get('versionEndIncluding')

                            fixed_version = None
                            if version_end_excluding and not self.beta_detector.is_beta_version(version_end_excluding):
                                fixed_version = version_end_excluding
                            elif version_end_including and not self.beta_detector.is_beta_version(version_end_including):
                                fixed_version = version_end_including

                            if fixed_version:
                                logger.debug(
                                    f"Found fixed version in NVD configurations for "
                                    f"{cve_id}: {fixed_version}"
                                )
                                return fixed_version # Return the first valid fixed version found

                # Fallback: Search in descriptions
                descriptions = cve.get('descriptions', [])
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        description_text = desc.get('value', '')
                        fixed_versions_from_text = self.extractor.extract_versions_from_text(
                            description_text
                        )
                        if fixed_versions_from_text:
                            # Return the lowest non-beta version if multiple are found in text
                            beta_detector = BetaVersionDetector()
                            valid_versions = [v for v in fixed_versions_from_text if not beta_detector.is_beta_version(v)]
                            if valid_versions:
                                return min(valid_versions, key=VersionParser().parse_version)

        except requests.exceptions.RequestException as req_err:
            logger.error(f"Network error searching NVD for {cve_id}: {req_err}")
        except json.JSONDecodeError:
            logger.error(f"JSON decode error for NVD response for {cve_id}")
        except Exception as e:
            logger.error(f"Unhandled error searching NVD for {cve_id}: {e}")

        return None


class CveFixVersionFinder:
    """Finds fixed versions from multiple CVE data sources."""

    def __init__(self):
        """Initialize CVE fix version finder with all searchers."""
        self.vdb_processor = VdbResultProcessor()
        self.extractor = FixedVersionExtractor()
        self.github_searcher = GitHubSecurityAdvisorySearcher()
        self.nvd_searcher = NvdSearcher()
        self.beta_detector = BetaVersionDetector() # For final filtering

    def find_fixed_versions_from_cve(self, cve_id: str, cve_result: Any = None,
                                     package_name: str = "",
                                     current_version: str = "") -> list[str]:
        """
        Extract fixed version information from CVE data sources with hierarchy.
        Priority order: VDB fix_version -> VDB description -> GitHub (GHSA) -> NVD (CVE)
        Excludes beta versions from all sources.
        """
        fixed_versions_found = []

        # 1. Primary: Extract from VDB fix_version field (if VDB is available)
        if VDB_AVAILABLE and cve_result:
            fix_version = self.vdb_processor.get_fix_version_from_vdb_result(cve_result)
            if fix_version:
                fixed_versions_found.append(fix_version)
                logger.debug(f"Found fix_version in VDB for {cve_id}: {fix_version}")
                # If a direct VDB fix_version is found, it's highly reliable, return it.
                return list(set(fixed_versions_found))

        # 2. Secondary: Extract from VDB description if fix_version was empty or not found
        if VDB_AVAILABLE and cve_result:
            description = self.vdb_processor.get_description_from_vdb_result(cve_result)
            if description:
                description_versions = self.extractor.extract_versions_from_text(
                    description
                )
                if description_versions:
                    fixed_versions_found.extend(description_versions)
                    logger.debug(
                        f"Found versions in VDB description for {cve_id}: "
                        f"{description_versions}"
                    )

        # 3. Tertiary: If no versions found yet, and CVE ID starts with GHSA, query GitHub
        # Note: We query GitHub even if some versions were found in VDB description,
        # to gather all possible valid fixed versions.
        if cve_id.startswith('GHSA-') and GITHUB_VALIDATION_AVAILABLE:
            github_fixed_version = self.github_searcher.search_github_security_advisory(
                cve_id, package_name, current_version # Pass current_version for applicability check
            )
            if github_fixed_version:
                fixed_versions_found.append(github_fixed_version)
                logger.debug(
                    f"Found fix version in GitHub Advisory for {cve_id}: "
                    f"{github_fixed_version}"
                )

        # 4. Fallback: Query NVD if still no fixed versions, and CVE ID starts with CVE-
        # Similar to GitHub, query NVD to get more data points.
        if cve_id.startswith('CVE-'):
            nvd_fixed_version = self.nvd_searcher.search_nvd_for_fixed_version(cve_id)
            if nvd_fixed_version:
                # NVD searcher already filters beta versions and selects a reasonable one
                fixed_versions_found.append(nvd_fixed_version)
                logger.debug(
                    f"Found fix versions in NVD for {cve_id}: {nvd_fixed_version}"
                )

        # Final filtering for beta versions and uniqueness across all sources
        unique_and_stable_versions = set()
        for version in fixed_versions_found:
            if not self.beta_detector.is_beta_version(version):
                unique_and_stable_versions.add(version)

        return list(unique_and_stable_versions)


class CveSearcher:
    """Searches for CVEs affecting specific package versions."""

    def __init__(self):
        """Initialize CVE searcher."""
        self.purl_creator = PurlCreator()
        self.malware_detector = MalwareDetector()

    def get_cve_ids_for_version(self, package_name: str, version: str,
                                ecosystem: str) -> set[str]:
        """
        Retrieve all CVE IDs affecting a specific package version, excluding malware CVEs.
        """
        if not VDB_AVAILABLE:
            logger.warning("VDB not available, cannot search for CVEs by PURL.")
            return set()

        purl = self.purl_creator.create_purl(package_name, version, ecosystem)

        try:
            # search.search_by_any can take a purl and returns CVE objects or dicts
            search_results = search.search_by_any(purl, with_data=True)

            cve_ids = set()
            # malware_cves_found = set() # This set is not used, can remove if not needed for logging

            for result in search_results:
                # Ensure result is handled whether it's an object or a dictionary
                cve_id = result.get('cve_id', 'unknown') if isinstance(result, dict) else getattr(result, 'cve_id', 'unknown')

                if cve_id != 'unknown':
                    if self.malware_detector.is_malware_cve(cve_id):
                        # malware_cves_found.add(cve_id) # Can log if desired
                        continue # Skip malware CVEs
                    else:
                        cve_ids.add(cve_id)

            return cve_ids
        except Exception as e:
            logger.error(f"Error searching for CVEs in VDB for PURL {purl}: {e}")
            return set()


class CveApplicabilityFilter:
    """Filters CVEs for applicability and severity."""

    def __init__(self):
        """Initialize CVE applicability filter."""
        self.vdb_processor = VdbResultProcessor()
        self.applicability_checker = CveApplicabilityChecker()
        self.malware_detector = MalwareDetector()

    def has_applicable_cves(self, search_results: list[Any], current_version: str,
                            ecosystem: str, package_name: str,
                            exploit_resolver: Any | None,
                            excluded_cve_ids: set[str] = None,
                            severity_filter: str = 'all') -> list[dict[str, Any]]:
        """
        Filter search results for applicable CVEs, enhance with exploit data,
        and apply severity filter.
        """
        if excluded_cve_ids is None:
            excluded_cve_ids = set()

        applicable_cves_map = {} # Use a map to handle duplicates and ensure uniqueness by cve_id

        for result in search_results:
            # Extract CVE ID and source data
            cve_id = result.get('cve_id', 'unknown') if isinstance(result, dict) else getattr(result, 'cve_id', 'unknown')
            source_data = result.get('source_data') if isinstance(result, dict) else getattr(result, 'source_data', None)

            # Skip duplicates and explicitly excluded CVEs
            if cve_id in applicable_cves_map or cve_id in excluded_cve_ids:
                continue

            # Skip malware CVEs
            if self.malware_detector.is_malware_cve(cve_id):
                continue

            # Check version applicability (based on description or other metadata if implemented)
            description = self.vdb_processor.get_description_from_vdb_result(result)
            if not self.applicability_checker.is_cve_applicable_to_version(
                description, current_version
            ):
                continue

            # Exploit fix integration
            exploit_fix_info = {}
            if EXPLOIT_RESOLVER_AVAILABLE and exploit_resolver and hasattr(exploit_resolver, 'fetch_exploit_data_for_cve'):
                logger.debug(f"Checking for exploits in {cve_id} for {package_name}@{current_version}")

                exploit_data = exploit_resolver.fetch_exploit_data_for_cve(
                    cve_id, package_name, current_version, ecosystem
                )
                if exploit_data.get("exploitable"):
                    logger.info(f"EXPLOIT FOUND for {cve_id} (package: {package_name}, version: {current_version})!")
                    # Construct a temporary vulnerability object to create exploit_fix field
                    temp_vuln_for_exploit = {
                        'cve_id': cve_id,
                        'exploits_info': exploit_data.get('exploits_info', []),
                        'fix_version': None # Fix version is not known at this point
                    }
                    if hasattr(exploit_resolver, 'create_exploit_fix_field'):
                        exploit_fix_info = exploit_resolver.create_exploit_fix_field(
                            temp_vuln_for_exploit, package_name
                        )

            # Extract CVSS severity information
            severity = self._extract_severity_from_source_data(source_data, cve_id)

            # Apply severity filter
            is_applicable_severity = self._check_severity_filter(
                severity, severity_filter
            )

            if is_applicable_severity:
                cve_details = {
                    'cve_id': cve_id,
                    'severity': severity,
                    'result': result # Keep the original VDB result for later processing
                }
                # Add exploit_fix info if it was generated
                if exploit_fix_info:
                    cve_details['exploit_fix'] = exploit_fix_info

                applicable_cves_map[cve_id] = cve_details

        return list(applicable_cves_map.values())

    def _extract_severity_from_source_data(self, source_data: Any,
                                          cve_id: str) -> str:
        """Extract CVSS severity information from source data."""
        severity = 'unknown'

        try:
            if source_data and hasattr(source_data, 'root'):
                cve_root = source_data.root
                if hasattr(cve_root, 'containers') and cve_root.containers:
                    containers = cve_root.containers
                    if hasattr(containers, 'cna') and containers.cna:
                        cna = containers.cna
                        if hasattr(cna, 'metrics') and cna.metrics:
                            metrics = cna.metrics.root
                            # Prioritize CVSS V4, then V3.1, then V3.0
                            for cvss_version_attr in ['cvssV4_0', 'cvssV3_1', 'cvssV3_0']:
                                for metric in metrics:
                                    if hasattr(metric, cvss_version_attr):
                                        cvss_data = getattr(metric, cvss_version_attr)
                                        if cvss_data:
                                            # Check for 'baseSeverity' within the CVSS object
                                            if hasattr(cvss_data, 'root') and hasattr(cvss_data.root, 'baseSeverity'):
                                                severity = cvss_data.root.baseSeverity.value.lower()
                                                return severity
                                            elif hasattr(cvss_data, 'baseSeverity'):
                                                severity = cvss_data.baseSeverity.value.lower()
                                                return severity
        except (AttributeError, TypeError) as e:
            logger.debug(f"Failed to extract severity for {cve_id}: {e}")

        return severity

    def _check_severity_filter(self, severity: str, severity_filter: str) -> bool:
        """Check if severity meets the filter criteria."""
        if severity_filter == 'critical_high':
            return severity in ['critical', 'high']
        elif severity_filter == 'all':
            return True
        else:
            # If an unknown filter is provided, assume no filtering (conservative)
            logger.warning(f"Unknown severity filter '{severity_filter}'. Applying no filter.")
            return True


class OptimalVersionCalculator:
    """Calculates optimal versions that fix applicable CVEs."""

    def __init__(self):
        """Initialize optimal version calculator."""
        self.version_parser = VersionParser()
        self.cve_fix_finder = CveFixVersionFinder()
        self.beta_detector = BetaVersionDetector() # For final check

    def get_optimal_version_for_current(self, current_version: str,
                                         applicable_cves: list[dict[str, Any]],
                                         package_name: str = "") -> str | None:
        """
        Calculate optimal version that fixes all applicable CVEs with VDB 6.4.3 support.
        Excludes beta versions from recommendations.
        """
        current_parsed = self.version_parser.parse_version(current_version)
        cve_min_fixed_versions = []

        for cve_info in applicable_cves:
            cve_id = cve_info['cve_id']
            # Pass the original cve_result from VDB along with package_name and current_version
            fixed_versions = self.cve_fix_finder.find_fixed_versions_from_cve(
                cve_id, cve_info['result'], package_name, current_version
            )

            # Handle case where no fixed versions are found for a CVE
            if not fixed_versions:
                logger.debug(f"No stable fixed versions found for CVE {cve_id}.")
                continue

            # Filter for versions strictly higher than current and non-beta
            higher_fixed_versions = []
            for version in fixed_versions:
                try:
                    if (self.version_parser.parse_version(version) > current_parsed and
                        not self.beta_detector.is_beta_version(version)):
                        higher_fixed_versions.append(version)
                except Exception as e:
                    logger.warning(
                        f"Failed to parse version {version} for {cve_id}: {e}"
                    )
                    continue

            if higher_fixed_versions:
                # Take the minimum version that fixes this specific CVE
                min_fixed_version = min(
                    higher_fixed_versions,
                    key=self.version_parser.parse_version
                )
                cve_min_fixed_versions.append(min_fixed_version)
            else:
                logger.debug(f"No higher, stable fixed version found for {cve_id} relative to {current_version}.")

        if not cve_min_fixed_versions:
            logger.debug("No fixed versions found across all applicable CVEs that are higher than current.")
            return None

        # To ensure all CVEs are fixed, we need the maximum among the minimum fixed versions
        # This guarantees that the chosen version addresses the highest required fix.
        unique_min_fixed_versions = list(set(cve_min_fixed_versions))
        optimal_version = max(
            unique_min_fixed_versions,
            key=self.version_parser.parse_version
        )

        return optimal_version


class CveListExtractor:
    """Extracts CVE IDs from package vulnerability data."""

    def __init__(self):
        """Initialize CVE list extractor."""
        self.malware_detector = MalwareDetector()

    def get_initial_cve_list(self, package_data: dict[str, Any]) -> set[str]:
        """
        Extract CVE IDs from package vulnerability data, excluding malware CVEs.
        """
        cve_ids = set()

        # Handle both 'vulnerabilties' (typo) and 'vulnerabilities'
        vulnerabilities = (package_data.get('vulnerabilties', []) or
                           package_data.get('vulnerabilities', []))

        for vuln in vulnerabilities:
            if 'cve_id' in vuln:
                cve_id = vuln['cve_id']
                if not self.malware_detector.is_malware_cve(cve_id):
                    cve_ids.add(cve_id)

        return cve_ids


class RecursiveOptimizer:
    """Performs recursive version optimization with GitHub validation."""

    def __init__(self):
        """Initialize recursive optimizer with all required components."""
        self.cve_searcher = CveSearcher()
        self.cve_filter = CveApplicabilityFilter()
        self.optimal_calculator = OptimalVersionCalculator()
        self.version_parser = VersionParser()
        self.beta_detector = BetaVersionDetector()
        self.purl_creator = PurlCreator()

    def recursive_version_optimization_with_github(
        self, package_name: str, starting_version: str, ecosystem: str,
        exploit_resolver: Any | None,
        initial_cve_ids: set[str] = None, max_iterations: int = MAX_ITERATIONS,
        severity_filter: str = 'all', project_type: str = "",
        vendor: list[str] = None
    ) -> dict[str, Any]:
        """
        Recursively optimize package version with GitHub validation and VDB support.
        Returns detailed information about the optimization process.
        Excludes beta versions from recommendations.
        """
        if not VDB_AVAILABLE:
            logger.warning(
                f"VDB not available, returning starting version for {package_name} in {ecosystem}."
            )
            return {
                'final_version': starting_version,
                'optimization_path': [],
                'total_hops': 0,
                'cves_resolved': 0,
                'all_exploit_fixes': [],
                'error': 'VDB not available'
            }

        if initial_cve_ids is None:
            initial_cve_ids = set()

        current_version = starting_version
        iteration = 0
        version_history = [current_version]
        optimization_path = []
        total_cves_resolved = set()
        all_exploit_fixes = []

        # Record starting point
        optimization_path.append({
            'hop': 0,
            'version': current_version,
            'action': 'starting_version',
            'new_cves_found': len(initial_cve_ids),
            'new_cve_list': sorted(list(initial_cve_ids)), # Sort for consistent output
            'cves_resolved_this_hop': [],
            'exploits_found_this_hop': [],
            'github_validated': False,
            'notes': f'Starting optimization from version {current_version}'
        })

        while iteration < max_iterations:
            iteration += 1

            logger.info(f"  Hop {iteration}: Analyzing version {current_version} of {package_name}...")

            # Get all CVE IDs affecting current version (malware CVEs automatically excluded)
            current_version_cve_ids = self.cve_searcher.get_cve_ids_for_version(
                package_name, current_version, ecosystem
            )

            # Determine CVE IDs to exclude based on iteration (i.e., CVEs already resolved in previous hops)
            excluded_cve_ids = self._get_excluded_cve_ids(
                iteration, initial_cve_ids, version_history,
                package_name, ecosystem
            )

            # Calculate new CVEs introduced in current version
            # These are CVEs found in the current version that were NOT found in the previous version(s)
            new_cve_ids = current_version_cve_ids - excluded_cve_ids

            if not new_cve_ids:
                optimization_path.append({
                    'hop': iteration,
                    'version': current_version,
                    'action': 'no_new_cves',
                    'new_cves_found': 0,
                    'new_cve_list': [],
                    'cves_resolved_this_hop': [],
                    'exploits_found_this_hop': [],
                    'github_validated': False,
                    'notes': 'No new CVEs found - optimization complete for this path.'
                })
                logger.info(f"  No new CVEs found at version {current_version} for {severity_filter} severity. Optimization path complete.")
                break

            logger.info(f"  Found {len(new_cve_ids)} new CVEs in {current_version}: {', '.join(sorted(new_cve_ids))}")

            # Search for detailed CVE data for the *current* version
            # The search_results should contain the CVE objects for current_version_cve_ids
            purl_for_current = self.purl_creator.create_purl(package_name, current_version, ecosystem)
            search_results = self._get_search_results(
                purl_for_current, optimization_path, iteration, new_cve_ids
            )

            if not search_results:
                # If no search results are found for the current PURL, it could mean
                # the PURL is invalid or there's no VDB entry for this specific version.
                # This should probably break the loop as we can't find fixed versions.
                optimization_path.append({
                    'hop': iteration,
                    'version': current_version,
                    'action': 'no_vdb_data_for_current',
                    'new_cves_found': len(new_cve_ids),
                    'new_cve_list': sorted(list(new_cve_ids)),
                    'cves_resolved_this_hop': [],
                    'exploits_found_this_hop': [],
                    'github_validated': False,
                    'notes': f'No VDB data found for {package_name}@{current_version}. Cannot proceed with optimization.'
                })
                logger.warning(f"  No VDB data found for {package_name}@{current_version}. Stopping optimization path.")
                break

            # Filter for applicable CVEs based on severity filter
            applicable_cves = self.cve_filter.has_applicable_cves(
                search_results, current_version, ecosystem, package_name,
                exploit_resolver, excluded_cve_ids, severity_filter
            )

            exploits_found_this_hop = [
                cve['exploit_fix'] for cve in applicable_cves
                if 'exploit_fix' in cve and cve['exploit_fix']
            ]
            if exploits_found_this_hop:
                all_exploit_fixes.extend(exploits_found_this_hop)
                logger.info(f"  Found {len(exploits_found_this_hop)} exploitable CVEs in this hop.")

            if not applicable_cves:
                optimization_path.append({
                    'hop': iteration,
                    'version': current_version,
                    'action': 'no_applicable_cves_after_filter',
                    'new_cves_found': len(new_cve_ids),
                    'new_cve_list': sorted(list(new_cve_ids)),
                    'cves_resolved_this_hop': [],
                    'exploits_found_this_hop': exploits_found_this_hop,
                    'github_validated': False,
                    'notes': f'No applicable CVEs found after filtering for severity: {severity_filter}'
                })
                logger.info(f"  No applicable CVEs found for severity filter '{severity_filter}' at {current_version}. Optimization path complete.")
                break # No more CVEs to resolve at this severity level

            applicable_cve_ids = [cve['cve_id'] for cve in applicable_cves]
            logger.info(f"  Applicable CVEs for optimization at {current_version}: {', '.join(sorted(applicable_cve_ids))}")

            # Calculate optimal version considering all applicable CVEs
            next_version = self.optimal_calculator.get_optimal_version_for_current(
                current_version, applicable_cves, package_name
            )

            # Validate and process next version
            optimization_result = self._process_next_version(
                next_version, current_version, version_history, iteration,
                new_cve_ids, applicable_cve_ids, exploits_found_this_hop,
                optimization_path, project_type, vendor, package_name
            )

            if optimization_result['should_break']:
                break

            if optimization_result['updated_version']:
                current_version = optimization_result['updated_version']
                version_history.append(current_version)

                # Track CVEs resolved by this hop
                total_cves_resolved.update(applicable_cve_ids)

                # Record this hop
                optimization_path.append({
                    'hop': iteration,
                    'version': current_version,
                    'action': 'version_hop',
                    'new_cves_found': len(new_cve_ids), # CVEs newly found at the start of this hop
                    'new_cve_list': sorted(list(new_cve_ids)),
                    'cves_resolved_this_hop': sorted(applicable_cve_ids), # CVEs resolved by moving to `current_version`
                    'exploits_found_this_hop': exploits_found_this_hop,
                    'github_validated': optimization_result['github_validated'],
                    'notes': (
                        f'Hopped to version {current_version} to resolve '
                        f'{len(applicable_cve_ids)} CVEs from previous version.'
                    )
                })

                logger.info(f"  Hopped to version {current_version}. Resolved {len(applicable_cve_ids)} CVEs.")
                logger.info(f"  GitHub validated: {'Yes' if optimization_result['github_validated'] else 'No'}")

                # Add small delay between iterations to avoid hammering APIs
                time.sleep(0.5)
            else:
                # If updated_version is None, it means no valid next version was found.
                # The loop should terminate as no further progress can be made.
                logger.info(f"  No valid next version found from {current_version}. Stopping optimization path.")
                break

        return {
            'final_version': current_version,
            'optimization_path': optimization_path,
            'total_hops': len(optimization_path) - 1 if len(optimization_path) > 0 else 0, # Subtract 1 for starting point
            'cves_resolved': len(total_cves_resolved),
            'cves_resolved_list': sorted(list(total_cves_resolved)),
            'version_history': version_history,
            'all_exploit_fixes': all_exploit_fixes
        }

    def _get_excluded_cve_ids(self, iteration: int, initial_cve_ids: set[str],
                              version_history: list[str], package_name: str,
                              ecosystem: str) -> set[str]:
        """
        Get CVE IDs that should be excluded from consideration in the current hop.
        These are CVEs that were already present and potentially resolved in previous versions.
        For iteration 1, these are the original CVEs. For subsequent iterations, these are
        all CVEs present in the *immediately preceding* version.
        """
        if iteration == 1:
            # In the first hop, we are interested in *new* CVEs relative to the initial scan.
            # So, the "excluded" are the initial CVEs that are already there.
            return initial_cve_ids
        else:
            # For subsequent hops, we want to find CVEs that are *newly introduced*
            # by the current version compared to the *previous* version in the hop history.
            # Thus, we exclude CVEs that were present in the previous version.
            previous_version = version_history[-2] # -1 is current, -2 is previous
            return self.cve_searcher.get_cve_ids_for_version(
                package_name, previous_version, ecosystem
            )

    def _get_search_results(self, purl: str, optimization_path: list[dict],
                            iteration: int, new_cve_ids: set[str]) -> list[Any]:
        """Get search results from VDB."""
        try:
            # VDB search returns objects or dicts
            return search.search_by_any(purl, with_data=True)
        except Exception as e:
            logger.error(f"Error searching VDB for PURL {purl}: {e}")
            optimization_path.append({
                'hop': iteration,
                'version': purl.split('@')[-1] if '@' in purl else 'unknown', # Extract version from PURL
                'action': 'search_error',
                'new_cves_found': len(new_cve_ids),
                'new_cve_list': sorted(list(new_cve_ids)),
                'cves_resolved_this_hop': [],
                'exploits_found_this_hop': [],
                'github_validated': False,
                'notes': f'Error searching VDB for PURL: {str(e)}'
            })
            return []

    def _process_next_version(self, next_version: str | None, current_version: str,
                              version_history: list[str], iteration: int,
                              new_cve_ids: set[str], applicable_cve_ids: list[str],
                              exploits_found_this_hop: list[dict],
                              optimization_path: list[dict], project_type: str,
                              vendor: list[str], package_name: str) -> dict[str, Any]:
        """Process the next version and handle validation."""
        if not next_version:
            optimization_path.append({
                'hop': iteration,
                'version': current_version,
                'action': 'no_optimal_version',
                'new_cves_found': len(new_cve_ids),
                'new_cve_list': sorted(list(new_cve_ids)),
                'cves_resolved_this_hop': [],
                'exploits_found_this_hop': exploits_found_this_hop,
                'github_validated': False,
                'notes': 'No optimal version found to resolve CVEs (excluding beta versions).'
            })
            logger.info("  No optimal version found to resolve CVEs (excluding beta versions).")
            return {'should_break': True, 'updated_version': None, 'github_validated': False}

        # Additional check: ensure next_version is not a beta version (redundant but safe)
        if self.beta_detector.is_beta_version(next_version):
            optimization_path.append({
                'hop': iteration,
                'version': current_version, # Still at current version, as next was rejected
                'action': 'beta_version_rejected',
                'new_cves_found': len(new_cve_ids),
                'new_cve_list': sorted(list(new_cve_ids)),
                'cves_resolved_this_hop': [],
                'exploits_found_this_hop': exploits_found_this_hop,
                'github_validated': False,
                'notes': f'Calculated optimal version {next_version} is a beta version and was rejected.'
            })
            logger.info(f"  Calculated optimal version {next_version} is a beta version and was rejected.")
            return {'should_break': True, 'updated_version': None, 'github_validated': False}

        # Prevent cycles and infinite loops
        if next_version == current_version or next_version in version_history:
            optimization_path.append({
                'hop': iteration,
                'version': current_version, # Still at current version
                'action': 'cycle_detected',
                'new_cves_found': len(new_cve_ids),
                'new_cve_list': sorted(list(new_cve_ids)),
                'cves_resolved_this_hop': [],
                'exploits_found_this_hop': exploits_found_this_hop,
                'github_validated': False,
                'notes': f'Cycle detected or no progress: next version {next_version} is same as current or already seen.'
            })
            logger.info(f"  Cycle detected or no progress: next version {next_version} is same as current or already seen. Stopping optimization.")
            return {'should_break': True, 'updated_version': None, 'github_validated': False}

        logger.info(f"  Calculated optimal next version to try: {next_version}")

        # GitHub validation after every hop
        return self._validate_with_github(
            next_version, optimization_path, iteration, new_cve_ids,
            exploits_found_this_hop, project_type, vendor, package_name,
            current_version
        )

    def _validate_with_github(self, next_version: str, optimization_path: list[dict],
                              iteration: int, new_cve_ids: set[str],
                              exploits_found_this_hop: list[dict], project_type: str,
                              vendor: list[str], package_name: str,
                              current_version: str) -> dict[str, Any]:
        """Validate version with GitHub and return processing result."""
        github_validated = False
        updated_version = next_version # Assume valid until proven otherwise

        if GITHUB_VALIDATION_AVAILABLE:
            logger.info(f"  Attempting GitHub validation for {package_name} version {next_version}...")
            validated_version = validate_version_for_recursion(
                package_name=package_name,
                version=next_version,
                project_type=project_type,
                vendor=vendor or []
            )

            if validated_version:
                updated_version = validated_version # Use the version GitHub validated (could be slightly different, e.g., canonical form)
                github_validated = True
                logger.info(f"  GitHub successfully validated version: {validated_version}")
            else:
                # GitHub validation failed - this means the proposed `next_version` doesn't exist or isn't reachable via GitHub.
                # In this case, we cannot proceed with this version. The recursion should stop for this path.
                optimization_path.append({
                    'hop': iteration,
                    'version': current_version, # Revert to current as next was not validated
                    'action': 'github_validation_failed',
                    'new_cves_found': len(new_cve_ids),
                    'new_cve_list': sorted(list(new_cve_ids)),
                    'cves_resolved_this_hop': [],
                    'exploits_found_this_hop': exploits_found_this_hop,
                    'github_validated': False,
                    'notes': f'GitHub validation failed for calculated optimal version {next_version}. Stopping optimization path.'
                })
                logger.warning(f"  GitHub validation failed for version {next_version}. Cannot proceed with this hop.")
                return {'should_break': True, 'updated_version': None, 'github_validated': False}
        else:
            logger.info(f"  GitHub validation module not available. Proceeding with {updated_version} without external validation.")

        return {
            'should_break': False,
            'updated_version': updated_version,
            'github_validated': github_validated
        }


class PackageProcessor:
    """Processes individual packages for recursive optimization."""

    def __init__(self):
        """Initialize package processor with all required components."""
        self.malware_detector = MalwareDetector()
        self.ecosystem_detector = EcosystemDetector()
        self.cve_extractor = CveListExtractor()
        self.recursive_optimizer = RecursiveOptimizer()

    def process_package_recursion(self, package_data: dict[str, Any],
                                  exploit_resolver: Any | None) -> dict[str, Any]:
        """
        Process recursive optimization for a single package from first_optimal.json.
        Returns detailed optimization information including all hops and CVEs.
        """
        package_name = package_data.get('package_name')

        # Check if this is a malware package
        if self.malware_detector.is_malware_package(package_data):
            logger.info(f"Skipping package '{package_name}' as it is identified as malware.")
            return {
                'High and critical': None,
                'all cves': None,
                'malware_package': True,
                'message': f"Package '{package_name}' contains malware - no recommendations",
                'optimization_details': None,
                'exploit_fix': []
            }

        # Get the starting versions from the first_optimal_version field
        first_optimal_data = package_data.get('first_optimal_version', {})

        # Extract starting versions for both analyses
        high_critical_data = first_optimal_data.get('High and critical cves', {})
        all_cves_data = first_optimal_data.get('All cves', {})

        high_critical_version = high_critical_data.get('recommended_version')
        all_cves_version = all_cves_data.get('recommended_version')

        # Initialize result structure
        result = {
            'High and critical': high_critical_version,
            'all cves': all_cves_version,
            'exploit_fix': [],
            'optimization_details': {
                'high_critical': None,
                'all_cves': None
            }
        }

        # Skip if no package name or no starting versions available
        if not package_name or (not high_critical_version and not all_cves_version):
            logger.warning(f"Skipping package {package_name}: No package name or no starting recommended versions found.")
            return result

        # Determine ecosystem
        ecosystem = self.ecosystem_detector.determine_package_ecosystem(package_data)

        # Extract metadata for GitHub validation
        project_type = package_data.get('project_type', '')
        vendor = package_data.get('vendor', [])

        # Extract initial CVE IDs (malware CVEs automatically filtered out by CveListExtractor)
        initial_cve_ids = self.cve_extractor.get_initial_cve_list(package_data)

        logger.info(f"\n--- Processing Package: {package_name} (Ecosystem: {ecosystem}) ---")
        logger.info(f"  Initial Vulnerabilities detected: {len(initial_cve_ids)} ({', '.join(sorted(list(initial_cve_ids)[:5]))}{'...' if len(initial_cve_ids) > 5 else ''})")

        try:
            # Process High/Critical CVEs if starting version available
            if high_critical_version:
                logger.info(f"\n  Starting HIGH/CRITICAL CVEs optimization for {package_name}:")
                logger.info(f"    Initial recommended version: {high_critical_version}")

                high_critical_result = self.recursive_optimizer.recursive_version_optimization_with_github(
                    package_name=package_name,
                    starting_version=high_critical_version,
                    ecosystem=ecosystem,
                    exploit_resolver=exploit_resolver,
                    initial_cve_ids=initial_cve_ids,
                    max_iterations=MAX_ITERATIONS,
                    severity_filter='critical_high',
                    project_type=project_type,
                    vendor=vendor
                )

                result['High and critical'] = high_critical_result['final_version']
                result['optimization_details']['high_critical'] = high_critical_result

                if high_critical_result.get('all_exploit_fixes'):
                    result['exploit_fix'].extend(high_critical_result['all_exploit_fixes'])

                logger.info(f"  HIGH/CRITICAL optimization for {package_name} complete. Final version: {high_critical_result['final_version']}")
                logger.info(f"    Total hops: {high_critical_result['total_hops']}, CVEs resolved: {high_critical_result['cves_resolved']}")
            else:
                logger.info(f"  No 'High and critical' recommended version for {package_name}. Skipping this optimization path.")
                result['optimization_details']['high_critical'] = {
                    'final_version': None,
                    'optimization_path': [],
                    'total_hops': 0,
                    'cves_resolved': 0,
                    'all_exploit_fixes': [],
                    'error': 'No initial recommended version for high and critical CVEs.'
                }

            # Process All CVEs if starting version available
            if all_cves_version:
                logger.info(f"\n  Starting ALL CVEs optimization for {package_name}:")
                logger.info(f"    Initial recommended version: {all_cves_version}")

                all_cves_result = self.recursive_optimizer.recursive_version_optimization_with_github(
                    package_name=package_name,
                    starting_version=all_cves_version,
                    ecosystem=ecosystem,
                    exploit_resolver=exploit_resolver,
                    initial_cve_ids=initial_cve_ids,
                    max_iterations=MAX_ITERATIONS,
                    severity_filter='all',
                    project_type=project_type,
                    vendor=vendor
                )

                result['all cves'] = all_cves_result['final_version']
                result['optimization_details']['all_cves'] = all_cves_result

                if all_cves_result.get('all_exploit_fixes'):
                    result['exploit_fix'].extend(all_cves_result['all_exploit_fixes'])

                logger.info(f"  ALL CVEs optimization for {package_name} complete. Final version: {all_cves_result['final_version']}")
                logger.info(f"    Total hops: {all_cves_result['total_hops']}, CVEs resolved: {all_cves_result['cves_resolved']}")
            else:
                logger.info(f"  No 'all cves' recommended version for {package_name}. Skipping this optimization path.")
                result['optimization_details']['all_cves'] = {
                    'final_version': None,
                    'optimization_path': [],
                    'total_hops': 0,
                    'cves_resolved': 0,
                    'all_exploit_fixes': [],
                    'error': 'No initial recommended version for all CVEs.'
                }

        except Exception as e:
            logger.error(f"Error during optimization for package {package_name}: {e}", exc_info=True)
            result['error'] = str(e)
            # Ensure optimization_details are populated even on error for debugging
            if not result['optimization_details']['high_critical']:
                result['optimization_details']['high_critical'] = {'error': str(e), 'final_version': None, 'optimization_path': [], 'total_hops': 0, 'cves_resolved': 0, 'all_exploit_fixes': []}
            if not result['optimization_details']['all_cves']:
                result['optimization_details']['all_cves'] = {'error': str(e), 'final_version': None, 'optimization_path': [], 'total_hops': 0, 'cves_resolved': 0, 'all_exploit_fixes': []}

        # De-duplicate exploit_fix entries if necessary (should be handled by append logic)
        if result['exploit_fix']:
            # Convert to list of tuples of sorted items for hashability, then back to dict, then list
            unique_exploits = [
                dict(t) for t in {tuple(sorted(d.items())) for d in result['exploit_fix']}
            ]
            result['exploit_fix'] = unique_exploits

        return result


class FileManager:
    """Manages file input/output operations."""

    def load_input_file(self, input_file_path: str) -> list[dict[str, Any]]:
        """
        Load the original input file to get the structure for output.json.
        """
        try:
            with open(input_file_path, encoding=DEFAULT_ENCODING) as f:
                input_data = json.load(f)

            if not isinstance(input_data, list):
                raise ValueError("Input file should contain a JSON array of packages.")

            return input_data
        except FileNotFoundError:
            logger.error(f"Input file not found: {input_file_path}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON from input file {input_file_path}: {e}")
            raise
        except ValueError as e:
            logger.error(f"Invalid format in input file {input_file_path}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error loading input file {input_file_path}: {e}")
            raise

    def load_first_optimal_file(self, first_optimal_file_path: str) -> list[dict[str, Any]]:
        """
        Load the first_optimal.json file with GitHub-validated first optimal versions.
        """
        try:
            with open(first_optimal_file_path, encoding=DEFAULT_ENCODING) as f:
                first_optimal_data = json.load(f)

            if not isinstance(first_optimal_data, list):
                raise ValueError(
                    "First optimal file should contain a JSON array of packages."
                )

            return first_optimal_data
        except FileNotFoundError:
            logger.error(f"First optimal file not found: {first_optimal_file_path}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON from first optimal file {first_optimal_file_path}: {e}")
            raise
        except ValueError as e:
            logger.error(f"Invalid format in first optimal file {first_optimal_file_path}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error loading first optimal file {first_optimal_file_path}: {e}")
            raise

    def save_json_file(self, data: Any, file_path: str) -> None:
        """Save data to JSON file."""
        try:
            with open(file_path, 'w', encoding=DEFAULT_ENCODING) as f:
                json.dump(data, f, indent=JSON_INDENT, ensure_ascii=False)
        except OSError as e:
            logger.error(f"I/O error saving file {file_path}: {e}")
            raise
        except TypeError as e:
            logger.error(f"Type error while saving JSON to {file_path}. Data might not be serializable: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to save file {file_path}: {e}")
            raise


class LatestVersionManager:
    """Manages fetching and processing of latest versions."""

    def __init__(self):
        """Initialize latest version manager."""
        self.fetcher = MultiEcosystemVersionFetcher()
        self.malware_detector = MalwareDetector()

    def fetch_latest_versions_for_packages(self, input_data: list[dict[str, Any]]) -> dict[str, Any]:
        """Fetch latest versions for all packages in the input data."""
        logger.info("Starting to fetch latest versions from package registries...")

        # Track statistics
        ecosystem_stats = defaultdict(int)
        processed = 0
        latest_version_results = {}
        malware_packages_skipped = 0

        # Process each package
        for i, package in enumerate(input_data, 1):
            package_name = package.get('package_name', '')
            vendor = package.get('vendor', [])
            purl_prefix = package.get('purl_prefix', '')

            if not package_name:
                logger.warning(f"Skipping package at index {i} due to missing 'package_name'.")
                continue

            # Skip malware packages
            if self.malware_detector.is_malware_package(package):
                latest_version_results[package_name] = "Malware Package - Skipped"
                malware_packages_skipped += 1
                continue

            # Get the latest version and ecosystem
            latest_version_info, ecosystem = self.fetcher.get_latest_version(
                package_name, vendor, purl_prefix
            )

            # Update statistics
            ecosystem_stats[ecosystem] += 1
            processed += 1

            # Show progress
            if processed % 50 == 0 or processed == len(input_data):
                logger.info(
                    f"Fetched latest versions for {processed}/{len(input_data)} packages"
                )

            # Store the result (only version, not URL)
            if latest_version_info and isinstance(latest_version_info, dict):
                latest_version_results[package_name] = latest_version_info.get('version', 'N/A')
            else:
                latest_version_results[package_name] = "N/A"

        logger.info(f"Completed fetching latest versions for {processed} packages.")

        # Print ecosystem breakdown
        logger.info("Latest version ecosystem breakdown:")
        for ecosystem, count in sorted(ecosystem_stats.items()):
            logger.info(f"  {ecosystem}: {count}")

        packages_with_latest = sum(
            1 for v in latest_version_results.values()
            if v != "N/A" and v != "Malware Package - Skipped"
        )
        total_fetchable_packages = len(input_data) - malware_packages_skipped
        success_rate = (packages_with_latest / total_fetchable_packages) * 100 if total_fetchable_packages else 0
        logger.info(
            f"Latest version fetch success rate: {success_rate:.1f}% "
            f"({packages_with_latest}/{total_fetchable_packages})"
        )
        logger.info(f"Malware packages skipped: {malware_packages_skipped}")

        return latest_version_results


class OutputCreator:
    """Creates output JSON structures from processing results."""

    def create_output_json(self, input_data: list[dict[str, Any]],
                           recursion_results: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Create output.json with same structure as input but filled with recursion results.
        Only includes the original input data plus recommended_version, latest_version,
        and exploit_fix fields.
        """
        output_data = []

        for package in input_data:
            # Create a shallow copy of the original package data to avoid modifying input
            output_package = package.copy()

            package_name = package.get('package_name')

            if package_name and package_name in recursion_results:
                recursion_result = recursion_results[package_name]

                # Create the recommended_version field structure
                output_package['recommended_version'] = {
                    'High and critical': recursion_result.get('High and critical'),
                    'all cves': recursion_result.get('all cves')
                }

                # Add the exploit_fix field
                output_package['exploit_fix'] = recursion_result.get('exploit_fix', [])

                # Add status for tracking (minimal metadata for the main output)
                if recursion_result.get('malware_package'):
                    output_package['status'] = 'malware_package_excluded'
                elif recursion_result.get('error'):
                    output_package['status'] = 'processing_error'
                else:
                    output_package['status'] = 'processed'
            else:
                # If no recursion results (e.g., package name missing or not processed)
                output_package['recommended_version'] = {
                    'High and critical': None,
                    'all cves': None
                }
                output_package['exploit_fix'] = [] # Ensure field exists
                output_package['status'] = 'not_processed' # Indicate it wasn't processed by recursion

            output_data.append(output_package)

        return output_data


class StatisticsReporter:
    """Generates and reports processing statistics."""

    def __init__(self):
        """Initialize statistics reporter."""
        self.version_parser = VersionParser()

    def create_statistics(self, recursion_results: dict[str, dict[str, Any]],
                          first_optimal_data: list[dict[str, Any]],
                          config: dict[str, Any]) -> dict[str, Any]:
        """Create comprehensive statistics from processing results."""
        stats = {
            'total_packages': len(first_optimal_data), # Total from first_optimal_data
            'processed_packages': 0,
            'skipped_packages': 0, # Packages skipped in recursion due to no starting version
            'malware_packages_excluded': 0,
            'error_packages': 0,
            'improvements': 0,
            'vdb_fix_version_used': 0, # Placeholder, needs to be incremented within CveFixVersionFinder or similar
            'vdb_description_used': 0, # Placeholder
            'github_advisory_queries': 0, # Placeholder
            'nvd_queries': 0, # Placeholder
            'beta_versions_excluded': 0, # Placeholder
            'configuration': config,
            'exploit_fix_count': 0
        }

        for package_name, result in recursion_results.items():
            if result.get('malware_package'):
                stats['malware_packages_excluded'] += 1
                continue

            if result.get('error'):
                stats['error_packages'] += 1
                continue

            # Check if any optimization happened for this package
            high_critical_opt_details = result.get('optimization_details', {}).get('high_critical', {})
            all_cves_opt_details = result.get('optimization_details', {}).get('all_cves', {})

            if (high_critical_opt_details and high_critical_opt_details.get('final_version')) or \
               (all_cves_opt_details and all_cves_opt_details.get('final_version')):
                stats['processed_packages'] += 1

                # Calculate improvements
                package_data_from_first_optimal = self._find_package_in_first_optimal(
                    package_name, first_optimal_data
                )
                if package_data_from_first_optimal:
                    first_optimal_versions_info = package_data_from_first_optimal.get('first_optimal_version', {})

                    # Check for improvement in 'all cves' path
                    first_all_cves_version = first_optimal_versions_info.get('All cves', {}).get('recommended_version')
                    final_all_cves_version = result.get('all cves')
                    if (first_all_cves_version and final_all_cves_version and
                        self.version_parser.parse_version(final_all_cves_version) >
                        self.version_parser.parse_version(first_all_cves_version)):
                        stats['improvements'] += 1

                    # Also check for improvement in 'High and critical' path
                    first_high_critical_version = first_optimal_versions_info.get('High and critical cves', {}).get('recommended_version')
                    final_high_critical_version = result.get('High and critical')
                    if (first_high_critical_version and final_high_critical_version and
                        self.version_parser.parse_version(final_high_critical_version) >
                        self.version_parser.parse_version(first_high_critical_version)):
                        # If both improve, count as one package improvement or track separately
                        # For simplicity, if either improves, we count as an improvement for the package.
                        # If you need separate counts, adjust here.
                        pass # Already incremented for all_cves or this is a secondary check

                # Count exploit fixes
                stats['exploit_fix_count'] += len(result.get('exploit_fix', []))

                # Aggregate source usage and beta exclusions from optimization_details
                for path_type in ['high_critical', 'all_cves']:
                    details = result['optimization_details'].get(path_type)
                    if details and details.get('optimization_path'):
                        for hop in details['optimization_path']:
                            if hop.get('action') == 'beta_version_rejected':
                                stats['beta_versions_excluded'] += 1
                            # To increment `vdb_fix_version_used`, `vdb_description_used`, etc.
                            # you'd need to pass these counts from CveFixVersionFinder back
                            # through the recursion_results and aggregate them here.
                            # This requires more detailed tracking in the `RecursiveOptimizer` and `CveFixVersionFinder` classes.
                            # For now, these remain placeholders as the current code doesn't expose these granular counts easily.

            else:
                stats['skipped_packages'] += 1 # No recommendations generated (could be due to no vulnerabilities or other reasons)

        return stats

    def _find_package_in_first_optimal(self, package_name: str,
                                      first_optimal_data: list[dict[str, Any]]) -> dict[str, Any] | None:
        """Find package data in first optimal data."""
        for package in first_optimal_data:
            if package.get('package_name') == package_name:
                return package
        return None

    def print_summary(self, stats: dict[str, Any], output_file: str,
                      stats_file: str, detailed_report_file: str) -> None:
        """Print comprehensive processing summary."""
        logger.info("\n" + "=" * 80)
        logger.info("RECURSIVE OPTIMIZATION SUMMARY")
        logger.info("=" * 80)
        logger.info(f"Total packages in input: {stats['total_packages']}")
        logger.info(f"Packages successfully optimized: {stats['processed_packages']}")
        logger.info(f"Packages with version improvements (from initial recommended): {stats['improvements']}")
        logger.info(f"Malware packages excluded: {stats['malware_packages_excluded']}")
        logger.info(f"Packages skipped (no valid initial recommendations or issues): {stats['skipped_packages']}")
        logger.info(f"Packages with processing errors: {stats['error_packages']}")

        logger.info("\nEnhanced CVE data source usage (approximate - requires detailed logging within searchers):")
        # These counts would need to be passed up from the respective searchers (NvdSearcher, GitHubSecurityAdvisorySearcher, CveFixVersionFinder)
        # to the recursion_results and then aggregated in create_statistics.
        logger.info(f"- VDB fix_version field usage: {stats.get('vdb_fix_version_used', 'N/A')}")
        logger.info(f"- VDB description parsing usage: {stats.get('vdb_description_used', 'N/A')}")
        logger.info(f"- GitHub Security Advisory queries: {stats.get('github_advisory_queries', 'N/A')}")
        logger.info(f"- NVD API queries: {stats.get('nvd_queries', 'N/A')}")
        logger.info(f"- Beta versions excluded from recommendations: {stats.get('beta_versions_excluded', 'N/A')}")

        logger.info("\nFiles generated:")
        logger.info(f"- {output_file} (main output: input + recommended_version + latest_version + exploit_fix + status)")
        logger.info(f"- {stats_file} (processing statistics and configuration)")
        logger.info(f"- {detailed_report_file} (detailed hop analysis for each package)")

        logger.info("\nPipeline status:")
        logger.info("1. first_optimal_combined2.py -> first_optimal.json [COMPLETED]")
        logger.info("2. recursion_combined2.py -> output.json [COMPLETED]")
        logger.info("3. Final output ready for analysis")

        # Feature status summary
        config = stats.get('configuration', {})
        github_enabled = config.get('github_validation_enabled', False)
        exploit_enabled = config.get('exploit_detection_enabled', False)
        max_iterations = config.get('max_iterations', MAX_ITERATIONS)

        logger.info("\nConfiguration Summary:")
        logger.info(f"- GitHub validation: {'ENABLED' if github_enabled else 'DISABLED'}")
        logger.info(f"- Exploit detection: {'ENABLED' if exploit_enabled else 'DISABLED'}")
        logger.info(f"- Max iterations per optimization path: {max_iterations}")

        if exploit_enabled:
            logger.info(f"- Total unique exploit entries found across all packages: {stats['exploit_fix_count']}")

        logger.info("\nOutput file structure notes:")
        logger.info(f"- {output_file}: Contains original input data for each package, augmented with 'recommended_version' (final optimal versions), 'latest_version' (latest available from registries), 'exploit_fix' (if any exploits were found), and a 'status' field.")
        logger.info("- No detailed optimization path or intermediate CVE lists are included in the main output to keep it clean for production use.")
        logger.info("- All detailed tracking, including version hops and resolved CVEs for each package's optimization path, is available in the separate detailed report file.")

        logger.info("\nSecurity notes:")
        logger.info("- All malware packages (identified by 'MAL' CVE IDs or explicit flags) are excluded from analysis and recommendations.")
        logger.info("- All beta/pre-release versions are explicitly excluded from being recommended as optimal versions.")
        logger.info("- Enhanced ecosystem detection with PURL, vendor, project type, and structural pattern analysis for more accurate registry lookups.")

        logger.info("=" * 80 + "\n")


class RecursiveCveOptimizer:
    """Main class for recursive CVE optimization with GitHub validation and exploit detection."""

    def __init__(self):
        """Initialize the recursive CVE optimizer with all components."""
        self.file_manager = FileManager()
        self.package_processor = PackageProcessor()
        self.latest_version_manager = LatestVersionManager()
        self.output_creator = OutputCreator()
        self.statistics_reporter = StatisticsReporter()

    def main(self, input_file: str = None, first_optimal_file: str = None,
             output_file: str = None) -> int:
        """
        Main function for the recursion step in the 3-step pipeline:
        1. Reads first_optimal.json (output of first_optimal_combined2.py)
        2. Performs recursive optimization with GitHub validation and VDB support
        3. Creates output.json with same structure as original input but with final recommendations

        Args:
            input_file: Path to original input file (for structure reference)
            first_optimal_file: Path to first_optimal.json from step 1
            output_file: Path for final output file

        Returns:
            Exit code (0 for success, 1 for failure)
        """

        # Use provided parameters or default file names
        if input_file is None:
            input_file = "test_with_exploits.json"
        if first_optimal_file is None:
            first_optimal_file = "first_optimal_test.json"
        if output_file is None:
            output_file = "output_test.json"

        # Auto-generate auxiliary file names based on output file
        output_dir = os.path.dirname(output_file) or '.'
        output_basename = os.path.splitext(os.path.basename(output_file))[0]

        stats_file = os.path.join(output_dir, f"{output_basename}_stats.json")
        detailed_report_file = os.path.join(output_dir, f"{output_basename}_detailed_report.json")

        # Validate file paths
        if not os.path.exists(input_file):
            logger.error(f"Input file does not exist: {input_file}")
            return 1

        if not os.path.exists(first_optimal_file):
            logger.error(f"First optimal file does not exist: {first_optimal_file}")
            return 1

        # Create output directory if it doesn't exist
        os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)

        logger.info("\n" + "*" * 80)
        logger.info("RECURSIVE CVE OPTIMIZATION WITH GITHUB VALIDATION & EXPLOIT DETECTION")
        logger.info("*" * 80)
        logger.info(f"Input file: {input_file}")
        logger.info(f"First optimal file: {first_optimal_file}")
        logger.info(f"Output file: {output_file}")
        logger.info(f"Statistics file: {stats_file}")
        logger.info(f"Detailed report file: {detailed_report_file}")
        logger.info("*" * 80 + "\n")

        try:
            input_data = self.file_manager.load_input_file(input_file)
            logger.info(f"Loaded original input file: {len(input_data)} packages.")
        except Exception: # Already logged in FileManager
            return 1

        try:
            first_optimal_data = self.file_manager.load_first_optimal_file(first_optimal_file)
            logger.info(f"Loaded first optimal file: {len(first_optimal_data)} packages.")
        except Exception: # Already logged in FileManager
            return 1

        # GitHub validation status
        github_validation_enabled = GITHUB_VALIDATION_AVAILABLE
        if github_validation_enabled:
            logger.info("GitHub validation module: ENABLED.")
        else:
            logger.warning("GitHub validation module: DISABLED (module 'github_validation' not found).")

        # Initialize Exploit Resolver
        exploit_resolver = None
        exploit_detection_enabled = EXPLOIT_RESOLVER_AVAILABLE

        if exploit_detection_enabled:
            try:
                exploit_resolver = ExploitResolver()
                logger.info("Exploit detection: ENABLED.")
            except Exception as e:
                logger.warning(
                    f"Could not initialize ExploitResolver. "
                    f"Exploit detection DISABLED. Error: {e}"
                )
                exploit_detection_enabled = False
        else:
            logger.warning("Exploit detection: DISABLED (module 'exploit_fix.py' not found).")

        logger.info("Enhanced CVE data sources in use: VDB fix_version -> VDB description -> GitHub (GHSA) -> NVD (CVE).")
        logger.info("Beta version filtering enabled: Excluding versions ending with common pre-release indicators (e.g., alpha, beta, rc).")
        logger.info("Enhanced ecosystem support enabled: npm, pypi, maven, nuget, cargo, gem, composer, golang, generic.")

        # Configuration for statistics
        config = {
            'input_file': input_file,
            'first_optimal_file': first_optimal_file,
            'output_file': output_file,
            'max_iterations': MAX_ITERATIONS,
            'github_validation_enabled': github_validation_enabled,
            'exploit_detection_enabled': exploit_detection_enabled
        }

        # Process recursive optimization for all packages from first_optimal.json
        recursion_results = {}
        logger.info(f"\nInitiating recursive optimization for {len(first_optimal_data)} packages...")

        for i, package_data in enumerate(first_optimal_data, 1):
            package_name = package_data.get('package_name', 'Unknown Package')

            if i % 10 == 0 or i == len(first_optimal_data) or i == 1:
                logger.info(f"--- Processing package {i}/{len(first_optimal_data)}: {package_name} ---")

            try:
                package_recursion = self.package_processor.process_package_recursion(
                    package_data, exploit_resolver
                )
                recursion_results[package_name] = package_recursion

            except Exception as e:
                logger.error(f"Critical error during processing of {package_name}. Skipping to next package. Error: {e}", exc_info=True)
                recursion_results[package_name] = {
                    'High and critical': None,
                    'all cves': None,
                    'error': str(e),
                    'malware_package': self.package_processor.malware_detector.is_malware_package(package_data), # Preserve malware status
                    'optimization_details': {
                        'high_critical': {'error': str(e), 'final_version': None, 'optimization_path': [], 'total_hops': 0, 'cves_resolved': 0, 'all_exploit_fixes': []},
                        'all_cves': {'error': str(e), 'final_version': None, 'optimization_path': [], 'total_hops': 0, 'cves_resolved': 0, 'all_exploit_fixes': []}
                    }
                }
            time.sleep(0.1) # Small delay between packages

        # Create output.json with same structure as input.json but filled with results
        logger.info("\nCreating final output JSON structure...")
        output_data = self.output_creator.create_output_json(input_data, recursion_results)

        # Fetch latest versions for all packages (this is done separately to avoid API conflicts during recursion)
        logger.info("Fetching latest versions for all packages from external registries...")
        latest_version_results = self.latest_version_manager.fetch_latest_versions_for_packages(
            first_optimal_data
        )

        # Add latest version information to output data
        for package in output_data:
            package_name = package.get('package_name')
            if package_name and package_name in latest_version_results:
                package['latest_version'] = latest_version_results[package_name]
            else:
                package['latest_version'] = "N/A"

        # Save results
        try:
            logger.info("Saving all generated result files...")

            # Save main output file
            self.file_manager.save_json_file(output_data, output_file)
            logger.info(f"Main output saved: {output_file}")

            # Create and save statistics
            stats = self.statistics_reporter.create_statistics(
                recursion_results, first_optimal_data, config
            )
            self.file_manager.save_json_file(stats, stats_file)
            logger.info(f"Statistics saved: {stats_file}")

            # Save detailed optimization report
            detailed_report_content = {
                'report_metadata': {
                    'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'total_packages_analyzed': len(first_optimal_data),
                    'description': (
                        'Detailed recursive CVE optimization report, including '
                        'all version hops, new CVEs found per hop, resolved CVEs, '
                        'and GitHub validation status for each package.'
                    ),
                    'configuration_at_runtime': config
                },
                'package_optimizations': {}
            }

            for package_name, result in recursion_results.items():
                detailed_report_content['package_optimizations'][package_name] = {
                    'final_recommendations': {
                        'high_critical_cves_version': result.get('High and critical'),
                        'all_cves_version': result.get('all cves')
                    },
                    'optimization_details': result.get('optimization_details'),
                    'malware_package_status': result.get('malware_package', False),
                    'overall_processing_error': result.get('error')
                }

            self.file_manager.save_json_file(detailed_report_content, detailed_report_file)
            logger.info(f"Detailed optimization report saved: {detailed_report_file}")

            # Print summary to console
            self.statistics_reporter.print_summary(
                stats, output_file, stats_file, detailed_report_file
            )

            return 0  # Success

        except Exception as e:
            logger.error(f"Failed to save results or generate final reports: {e}", exc_info=True)
            return 1  # Failure


def main():
    """Entry point for command line execution."""
    import sys

    try:
        optimizer = RecursiveCveOptimizer()
        exit_code = optimizer.main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.warning("Process interrupted by user (Ctrl+C). Exiting gracefully.")
        sys.exit(130)  # Standard exit code for SIGINT
    except Exception as e:
        logger.error(f"An unexpected error occurred during execution: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
