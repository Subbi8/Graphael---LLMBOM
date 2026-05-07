"""
GitHub Validation Module

This module provides classes for validating package versions against GitHub
repositories, including repository discovery, tag validation, and version matching.
"""

import logging
import os
import re
from typing import Any
from urllib.parse import quote

import requests
from packaging.version import InvalidVersion
from packaging.version import parse as parse_version_lib

# Constants
API_TIMEOUT = 15
HEAD_REQUEST_TIMEOUT = 5
MAX_PAGINATION_PAGES = 50
TAGS_PER_PAGE = 100
MAX_SEARCH_RESULTS = 20
MAX_POTENTIAL_PATHS = 15
MAX_SAMPLE_TAGS = 20
MAX_SAMPLE_FORMATS = 15
GITHUB_API_DELAY = 0.1

# Set up logging
logger = logging.getLogger(__name__)


class GitHubAuthHandler:
    """Handles GitHub API authentication and headers."""

    @staticmethod
    def get_headers() -> dict[str, str]:
        """
        Get GitHub API headers with authentication if available.

        Returns:
            Headers for GitHub API requests
        """
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Vulnerability-Analysis-Tool/1.0'
        }

        github_token = os.getenv('GITHUB_TOKEN') or os.getenv('GITHUB_PAT')
        if github_token:
            headers['Authorization'] = f'token {github_token}'

        return headers


class PurlParser:
    """Handles Package URL (PURL) parsing operations."""

    @staticmethod
    def parse_purl(purl: str) -> dict[str, str]:
        """
        Parse a Package URL (PURL) into its components.

        Args:
            purl: Package URL in format "pkg:type/namespace/name@version"

        Returns:
            Parsed components including type, namespace, name, version
        """
        parsed = {
            'type': '',
            'namespace': '',
            'name': '',
            'version': '',
            'qualifiers': {},
            'subpath': ''
        }

        if not purl or not purl.startswith('pkg:'):
            return parsed

        purl_content = purl[4:]

        if '@' in purl_content:
            path_part, version = purl_content.rsplit('@', 1)
            parsed['version'] = version
        else:
            path_part = purl_content

        if '?' in path_part:
            path_part, qualifiers_str = path_part.split('?', 1)
            for qualifier in qualifiers_str.split('&'):
                if '=' in qualifier:
                    key, value = qualifier.split('=', 1)
                    parsed['qualifiers'][key] = value

        if '#' in path_part:
            path_part, subpath = path_part.split('#', 1)
            parsed['subpath'] = subpath

        parts = path_part.split('/')
        if parts:
            parsed['type'] = parts[0]
            if len(parts) > 1:
                if len(parts) == 2:
                    parsed['name'] = parts[1]
                else:
                    parsed['namespace'] = '/'.join(parts[1:-1])
                    parsed['name'] = parts[-1]

        return parsed


class GitHubUrlExtractor:
    """Extracts and validates GitHub repository URLs."""

    SKIP_PATTERNS = [
        'advisory-database', 'advisories', 'vuln', 'vulnerability',
        'security', 'cve', 'nvd', 'exploit', 'poc', 'fuzzing'
    ]

    KNOWN_ADVISORY_REPOS = [
        'github.com/advisories',
        'github.com/pypa/advisory-database',
        'github.com/rubysec/ruby-advisory-db',
        'github.com/rustsec/advisory-db',
        'github.com/nodejs/security-wg',
        'github.com/0fuzzingq/vuln'
    ]

    def extract_github_repo_from_source(self,
                                       vulnerabilities: list[dict[str, Any]]) -> list[str]:
        """
        Extract unique GitHub repository URLs from vulnerability sources.

        Args:
            vulnerabilities: List of vulnerability data

        Returns:
            List of unique GitHub repository URLs
        """
        repo_candidates = []

        for vuln in vulnerabilities:
            references = vuln.get('references', [])

            for ref in references:
                if isinstance(ref, dict):
                    self._extract_from_reference(ref, repo_candidates)

            source = vuln.get('source', {})
            if isinstance(source, dict):
                url = source.get('url', '')
                if url and 'github.com' in url:
                    repo_url = self.extract_repo_from_github_url(url)
                    if repo_url and self._is_likely_main_repo(repo_url):
                        repo_candidates.append(repo_url)

        unique_repo_urls = list(dict.fromkeys(repo_candidates))
        return unique_repo_urls

    def _extract_from_reference(self, ref: dict[str, Any],
                               candidates: list[str]) -> None:
        """Extract repository URLs from a single reference."""
        source = ref.get('source', {})
        if isinstance(source, dict):
            url = source.get('url', '')
            if url and 'github.com' in url:
                repo_url = self.extract_repo_from_github_url(url)
                if repo_url and self._is_likely_main_repo(repo_url):
                    candidates.append(repo_url)

        ref_url = ref.get('url', '')
        if ref_url and 'github.com' in ref_url:
            repo_url = self.extract_repo_from_github_url(ref_url)
            if repo_url and self._is_likely_main_repo(repo_url):
                candidates.append(repo_url)

    def _is_likely_main_repo(self, repo_url: str) -> bool:
        """Check if a GitHub URL is likely to be the main repository."""
        if not repo_url:
            return False

        repo_path = repo_url.replace('https://github.com/', '').lower()

        for pattern in self.SKIP_PATTERNS:
            if pattern in repo_path:
                return False

        for advisory_repo in self.KNOWN_ADVISORY_REPOS:
            if advisory_repo in repo_url.lower():
                return False

        return True

    def extract_repo_from_github_url(self, url: str) -> str | None:
        """
        Extract repository URL from any GitHub URL.

        Args:
            url: Any GitHub URL

        Returns:
            Clean repository URL or None
        """
        if not url or 'github.com' not in url:
            return None

        url = url.strip()

        patterns = [
            r'https?://github\.com/([^/]+/[^/]+)(?:/.*)?',
            r'git://github\.com/([^/]+/[^/]+)(?:/.*)?',
            r'git@github\.com:([^/]+/[^/]+)(?:\.git)?(?:/.*)?',
        ]

        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                repo_path_clean = match.group(1)
                return f"https://github.com/{repo_path_clean}"

        return None


class PackageTypeDetector:
    """Detects and corrects package types based on various indicators."""

    VALID_TYPES = ['npm', 'pypi', 'gem', 'golang', 'generic', 'maven',
                   'nuget', 'cargo']
    INVALID_TYPES = ['csv', 'unknown', '', 'text']

    PROJECT_TYPE_MAPPING = {
        'nodejs': 'npm',
        'node': 'npm',
        'javascript': 'npm',
        'ruby': 'gem',
        'rubygems': 'gem',
        'go': 'golang',
        'python': 'pypi'
    }

    def detect_project_type_from_package_name(self, package_name: str,
                                            project_type: str) -> str:
        """
        Intelligently detect the correct project type.

        Args:
            package_name: Package name
            project_type: Original project type

        Returns:
            Corrected project type
        """
        if package_name.startswith('@'):
            if project_type.lower() != 'npm':
                return 'npm'
            return 'npm'

        normalized_project_type = project_type.lower()

        if (normalized_project_type in self.VALID_TYPES and
            normalized_project_type not in self.INVALID_TYPES):
            return normalized_project_type

        if (normalized_project_type in self.INVALID_TYPES or
            not project_type):
            detected_type = self._detect_type_by_registry_check(package_name)
            if detected_type:
                return detected_type

            detected_type = self._detect_type_by_patterns(package_name)
            if detected_type and detected_type != project_type:
                return detected_type

        return project_type

    def _detect_type_by_registry_check(self, package_name: str) -> str | None:
        """Detect project type by checking registries."""
        registries_to_check = [
            ('npm', f"https://registry.npmjs.org/{quote(package_name, safe='')}", 5),
            ('pypi', f"https://pypi.org/pypi/{package_name}/json", 5),
            ('gem', f"https://rubygems.org/api/v1/gems/{package_name}.json", 5)
        ]

        for registry_type, url, timeout in registries_to_check:
            try:
                response = requests.head(url, timeout=timeout)
                if response.status_code == 200:
                    return registry_type
            except requests.RequestException as e:
                # Log specific error instead of generic exception handling
                logger.debug(f"Failed to check {registry_type} registry for {package_name}: {e}")
                # Don't continue immediately - try other registries
            except Exception as e:
                # Handle other unexpected exceptions
                logger.warning(f"Unexpected error checking {registry_type} registry for {package_name}: {e}")

        return None

    def _detect_type_by_patterns(self, package_name: str) -> str | None:
        """Detect project type based on package name patterns."""
        package_lower = package_name.lower()

        npm_patterns = ['-js', '.js', 'node-', 'js-']
        if (package_name.startswith('@') or
            any(pattern in package_lower for pattern in npm_patterns) or
            package_lower.endswith('js')):
            return 'npm'

        python_patterns = ['py-', '-py', 'python-', '-python']
        if (any(pattern in package_lower for pattern in python_patterns) or
            package_lower.startswith('py') or
            package_lower.endswith('py')):
            return 'pypi'

        ruby_patterns = ['rb-', '-rb', 'ruby-', '-ruby', 'gem-']
        if (any(pattern in package_lower for pattern in ruby_patterns) or
            package_lower.startswith('rb') or
            package_lower.endswith('rb')):
            return 'gem'

        go_indicators = ['github.com/', 'gitlab.com/', 'gopkg.in/',
                        'go-', '-go', 'golang-']
        if any(pattern in package_name or pattern in package_lower
               for pattern in go_indicators):
            return 'golang'

        return None


class RegistryLookup:
    """Handles package registry lookups for different ecosystems."""

    def __init__(self):
        self.type_detector = PackageTypeDetector()

    def get_github_repo_from_registry(self, package_name: str,
                                    project_type: str,
                                    namespace: str = "") -> str | None:
        """
        Get GitHub repository URL from package registry.

        Args:
            package_name: Name of the package
            project_type: Type of project
            namespace: Package namespace

        Returns:
            GitHub repository URL or None
        """
        corrected_project_type = (
            self.type_detector.detect_project_type_from_package_name(
                package_name, project_type))

        normalized_type = self.type_detector.PROJECT_TYPE_MAPPING.get(
            corrected_project_type.lower(), corrected_project_type.lower())

        try:
            if normalized_type == 'npm':
                return self._get_npm_repo(package_name)
            elif normalized_type == 'pypi':
                return self._get_pypi_repo(package_name)
            elif normalized_type == 'gem':
                return self._get_gem_repo(package_name)
            elif normalized_type == 'golang':
                return self._get_golang_repo(package_name, namespace)
            else:
                return self._get_generic_repo(package_name)

        except Exception as e:
            logger.error(f"Error getting repo from registry for {package_name}: {e}")
            return self._get_generic_repo(package_name)

    def _get_npm_repo(self, package_name: str) -> str | None:
        """Get GitHub repo from NPM registry."""
        encoded_package_name = quote(package_name, safe='')
        api_url = f"https://registry.npmjs.org/{encoded_package_name}"

        try:
            response = requests.get(api_url, timeout=API_TIMEOUT)
            if response.status_code != 200:
                return None

            data = response.json()

            repo_sources = [
                data.get('repository', {}),
                self._get_latest_version_data(data).get('repository', {}),
            ]

            for repo in repo_sources:
                repo_url = self._extract_repo_url_from_field(repo)
                if repo_url and 'github.com' in repo_url:
                    extractor = GitHubUrlExtractor()
                    cleaned_url = extractor.extract_repo_from_github_url(repo_url)
                    if cleaned_url:
                        return cleaned_url

            other_sources = [
                self._get_latest_version_data(data).get('homepage', ''),
                self._get_latest_version_data(data).get('bugs', {}),
                data.get('homepage', ''),
                data.get('bugs', {})
            ]

            for field in other_sources:
                if isinstance(field, dict):
                    url = field.get('url', '')
                else:
                    url = field

                if url and 'github.com' in url:
                    extractor = GitHubUrlExtractor()
                    cleaned_url = extractor.extract_repo_from_github_url(url)
                    if cleaned_url:
                        return cleaned_url

            return None
        except Exception as e:
            logger.error(f"Error fetching NPM repo for {package_name}: {e}")
            return None

    def _get_pypi_repo(self, package_name: str) -> str | None:
        """Get GitHub repo from PyPI registry."""
        url = f"https://pypi.org/pypi/{package_name}/json"

        try:
            response = requests.get(url, timeout=API_TIMEOUT)
            if response.status_code != 200:
                return None

            data = response.json()
            info = data.get('info', {})

            project_urls = info.get('project_urls', {})
            for key, url in project_urls.items():
                if url and 'github.com' in url:
                    extractor = GitHubUrlExtractor()
                    cleaned_url = extractor.extract_repo_from_github_url(url)
                    if cleaned_url:
                        return cleaned_url

            home_page = info.get('home_page', '')
            if home_page and 'github.com' in home_page:
                extractor = GitHubUrlExtractor()
                cleaned_url = extractor.extract_repo_from_github_url(home_page)
                if cleaned_url:
                    return cleaned_url

            return None
        except Exception as e:
            logger.error(f"Error fetching PyPI repo for {package_name}: {e}")
            return None

    def _get_gem_repo(self, package_name: str) -> str | None:
        """Get GitHub repo from RubyGems registry."""
        url = f"https://rubygems.org/api/v1/gems/{package_name}.json"

        try:
            response = requests.get(url, timeout=API_TIMEOUT)
            if response.status_code != 200:
                return None

            data = response.json()

            url_fields = [
                ('source_code_uri', data.get('source_code_uri', '')),
                ('homepage_uri', data.get('homepage_uri', '')),
                ('project_uri', data.get('project_uri', '')),
                ('gem_uri', data.get('gem_uri', ''))
            ]

            for field_name, url in url_fields:
                if url and 'github.com' in url:
                    extractor = GitHubUrlExtractor()
                    cleaned_url = extractor.extract_repo_from_github_url(url)
                    if cleaned_url:
                        return cleaned_url

            return None
        except Exception as e:
            logger.error(f"Error fetching RubyGems repo for {package_name}: {e}")
            return None

    def _get_golang_repo(self, package_name: str,
                        namespace: str = "") -> str | None:
        """Get GitHub repo for Go packages."""
        if namespace:
            full_package = f"{namespace}/{package_name}"
        else:
            full_package = package_name

        go_patterns = [
            r'^github\.com/([^/]+/[^/]+)',
            r'^gitlab\.com/([^/]+/[^/]+)',
            r'^bitbucket\.org/([^/]+/[^/]+)',
            r'^gopkg\.in/([^/]+/[^/]+)',
        ]

        for pattern in go_patterns:
            match = re.match(pattern, full_package)
            if match:
                if 'github.com' in full_package:
                    return f"https://github.com/{match.group(1)}"
                elif 'gopkg.in' in full_package:
                    try:
                        response = requests.head(f"https://{full_package}",
                                               allow_redirects=True,
                                               timeout=10)
                        if response.url and 'github.com' in response.url:
                            extractor = GitHubUrlExtractor()
                            cleaned_url = extractor.extract_repo_from_github_url(response.url)
                            if cleaned_url:
                                return cleaned_url
                    except requests.RequestException as e:
                        logger.debug(f"Failed to resolve gopkg.in redirect for {full_package}: {e}")
                    except Exception as e:
                        logger.warning(f"Unexpected error resolving gopkg.in for {full_package}: {e}")

        try:
            api_url = f"https://pkg.go.dev/{full_package}"
            response = requests.get(api_url, timeout=API_TIMEOUT)
            if response.status_code == 200:
                github_pattern = r'https://github\.com/([^/]+/[^/]+)'
                matches = re.findall(github_pattern, response.text)
                if matches:
                    return f"https://github.com/{matches[0]}"
        except Exception as e:
            logger.error(f"Error fetching Go package info for {full_package}: {e}")

        return None

    def _get_generic_repo(self, package_name: str) -> str | None:
        """Handle generic packages using multiple discovery strategies."""
        potential_github_paths = self._generate_potential_github_paths(package_name)
        for github_path in potential_github_paths:
            repo_url = f"https://github.com/{github_path}"
            if self._check_repo_exists(repo_url):
                return repo_url

        searcher = GitHubSearcher()
        return searcher.search_github_directly(package_name)

    def _generate_potential_github_paths(self, package_name: str) -> list[str]:
        """Generate potential GitHub repository paths."""
        package_lower = package_name.lower()
        potential_paths = [
            f"{package_lower}/{package_lower}",
            f"{package_lower}-project/{package_lower}",
            f"{package_lower}-dev/{package_lower}",
            f"{package_name}/{package_name}",
            f"{package_name.capitalize()}/{package_name.capitalize()}",
            f"the{package_lower}/{package_lower}",
            f"official-{package_lower}/{package_lower}",
            f"{package_lower}/{package_lower}-core",
            f"{package_lower}-foundation/{package_lower}",
            f"{package_lower}-org/{package_lower}",
        ]

        seen = set()
        unique_paths = []
        for path in potential_paths:
            if path not in seen:
                unique_paths.append(path)
                seen.add(path)

        return unique_paths[:MAX_POTENTIAL_PATHS]

    def _check_repo_exists(self, repo_url: str) -> bool:
        """Check if a GitHub repository exists."""
        try:
            response = requests.head(repo_url, timeout=HEAD_REQUEST_TIMEOUT)
            return response.status_code == 200
        except Exception as e:
            logger.debug(f"Failed to check repo existence for {repo_url}: {e}")
            return False

    def _get_latest_version_data(self, npm_data: dict) -> dict:
        """Extract data for the latest version from NPM registry response."""
        latest_version = npm_data.get('dist-tags', {}).get('latest', '')
        if latest_version:
            return npm_data.get('versions', {}).get(latest_version, {})
        return {}

    def _extract_repo_url_from_field(self, field) -> str:
        """Extract URL from various field formats."""
        if isinstance(field, dict):
            return field.get('url', '')
        elif isinstance(field, str):
            return field
        return ''


class GitHubSearcher:
    """Handles direct GitHub API searches."""

    def search_github_directly(self, package_name: str) -> str | None:
        """Search GitHub directly for the package repository."""
        try:
            headers = GitHubAuthHandler.get_headers()

            search_strategies = [
                (f'"{package_name}" in:name', 'exact_name'),
                (f"{package_name} sort:stars", 'popular'),
                (f"{package_name}", 'general'),
            ]

            if self._looks_like_c_project(package_name):
                search_strategies.insert(2,
                    (f"{package_name} in:name language:c", 'c_lang'))

            if self._looks_like_python_project(package_name):
                search_strategies.insert(2,
                    (f"{package_name} in:name language:python", 'python_lang'))

            if self._looks_like_js_project(package_name):
                search_strategies.insert(2,
                    (f"{package_name} in:name language:javascript", 'js_lang'))

            for query, strategy_name in search_strategies:
                search_url = (f"https://api.github.com/search/repositories?"
                            f"q={quote(query)}&sort=stars&order=desc"
                            f"&per_page={MAX_SEARCH_RESULTS}")

                try:
                    response = requests.get(search_url, headers=headers,
                                          timeout=API_TIMEOUT)

                    if response.status_code == 200:
                        data = response.json()
                        items = data.get('items', [])

                        if items:
                            scored_repos = self._score_search_results(package_name, items)

                            if scored_repos:
                                best_repo = scored_repos[0]
                                return best_repo['html_url']

                    elif response.status_code == 403:
                        logger.warning(f"GitHub API rate limit exceeded for search: {package_name}")
                        break

                except requests.RequestException as e:
                    logger.debug(f"Request failed for GitHub search strategy {strategy_name}: {e}")
                except Exception as e:
                    logger.warning(f"Unexpected error in GitHub search strategy {strategy_name}: {e}")

        except Exception as e:
            logger.error(f"Error in GitHub direct search for {package_name}: {e}")

        return None

    def _looks_like_c_project(self, package_name: str) -> bool:
        """Check if package name suggests it's a C/C++ project."""
        c_indicators = ['ssl', 'crypto', 'curl', 'lib', 'zlib', 'xml',
                       'sql', 'git', 'gcc', 'make']
        return any(indicator in package_name.lower() for indicator in c_indicators)

    def _looks_like_python_project(self, package_name: str) -> bool:
        """Check if package name suggests it's a Python project."""
        python_indicators = ['py', 'django', 'flask', 'numpy', 'pandas', 'requests']
        return any(indicator in package_name.lower() for indicator in python_indicators)

    def _looks_like_js_project(self, package_name: str) -> bool:
        """Check if package name suggests it's a JavaScript project."""
        js_indicators = ['js', 'node', 'react', 'vue', 'angular', 'express', 'webpack']
        return any(indicator in package_name.lower() for indicator in js_indicators)

    def _score_search_results(self, package_name: str,
                             repositories: list[dict]) -> list[dict]:
        """Score and rank GitHub search results based on relevance."""
        scored_results = []
        package_lower = package_name.lower()

        for repo in repositories:
            score = 0
            repo_name = repo.get('name', '').lower()
            repo_full_name = repo.get('full_name', '').lower()
            repo_description = repo.get('description', '').lower() if repo.get('description') else ''

            if repo_name == package_lower:
                score += 100
            elif package_lower in repo_name:
                score += 80
            elif package_lower in repo_full_name:
                score += 60
            elif package_lower in repo_description:
                score += 30

            stars = repo.get('stargazers_count', 0)
            if stars > 1000:
                score += 20
            elif stars > 100:
                score += 10
            elif stars > 10:
                score += 5

            if not repo.get('archived', False):
                score += 15

            topics = repo.get('topics', [])
            if any(package_lower in topic.lower() for topic in topics):
                score += 25

            if repo.get('fork', False):
                score -= 20

            if score > 20:
                repo_copy = repo.copy()
                repo_copy['relevance_score'] = score
                scored_results.append(repo_copy)

        scored_results.sort(key=lambda x: x['relevance_score'], reverse=True)
        return scored_results


class RepoSelector:
    """Selects the best repository from multiple candidates."""

    def select_best_repo_from_candidates(self, package_name: str,
                                       candidates: list[str]) -> str | None:
        """Select the most relevant GitHub repository URL from candidates."""
        if not candidates:
            return None

        pkg_name_lower = package_name.lower()
        scored_candidates = []

        for repo_url in candidates:
            score = 0
            repo_path_lower = repo_url.replace('https://github.com/', '').lower()
            owner_repo_parts = repo_path_lower.split('/')

            if len(owner_repo_parts) == 2:
                owner, repo_name = owner_repo_parts[0], owner_repo_parts[1]

                if repo_name == pkg_name_lower:
                    score += 100
                elif repo_name in [f"python-{pkg_name_lower}", f"{pkg_name_lower}-python"]:
                    score += 90
                elif ('/' in pkg_name_lower and
                      repo_name == pkg_name_lower.split('/')[-1]):
                    score += 85
                elif pkg_name_lower in repo_name:
                    score += 50
                elif pkg_name_lower in owner:
                    score += 20
            else:
                if pkg_name_lower in repo_path_lower:
                    score += 10

            scored_candidates.append((score, repo_url))

        scored_candidates.sort(key=lambda x: x[0], reverse=True)

        if scored_candidates:
            return scored_candidates[0][1]

        return None


class GitHubTagsFetcher:
    """Handles fetching and paginating through GitHub repository tags."""

    def get_all_github_tags(self, repo_url: str) -> tuple[bool, list[str], dict[str, Any]]:
        """Get ALL tags from a GitHub repository (handles pagination)."""
        if not repo_url.startswith('https://github.com/'):
            return False, [], {'error': 'Invalid GitHub URL format'}

        repo_path = repo_url.replace('https://github.com/', '')
        base_api_url = f"https://api.github.com/repos/{repo_path}/tags"

        headers = GitHubAuthHandler.get_headers()

        all_tags = []
        page = 1

        try:
            while True:
                url = f"{base_api_url}?page={page}&per_page={TAGS_PER_PAGE}"
                response = requests.get(url, headers=headers, timeout=API_TIMEOUT)

                if response.status_code == 200:
                    tags_data = response.json()

                    if not tags_data:
                        break

                    page_tags = [tag['name'] for tag in tags_data]
                    all_tags.extend(page_tags)

                    if len(tags_data) < TAGS_PER_PAGE:
                        break

                    page += 1

                    if page > MAX_PAGINATION_PAGES:
                        break

                elif response.status_code == 404:
                    return False, [], {'error': 'Repository not found', 'status_code': 404}
                elif response.status_code == 403:
                    return False, [], {'error': 'API rate limit exceeded', 'status_code': 403}
                else:
                    return False, [], {'error': f'HTTP {response.status_code}', 'status_code': response.status_code}

            metadata = {
                'total_tags': len(all_tags),
                'pages_fetched': page - 1,
                'status': 'success'
            }

            return True, all_tags, metadata

        except requests.RequestException as e:
            logger.error(f"Request failed while fetching tags for {repo_url}: {e}")
            return False, [], {'error': f'Request failed: {str(e)}'}
        except Exception as e:
            logger.error(f"Unexpected error while fetching tags for {repo_url}: {e}")
            return False, [], {'error': f'Unexpected error: {str(e)}'}


class VersionMatcher:
    """Handles version normalization and matching logic."""

    def __init__(self):
        self.prefixes_to_remove = [
            'v', 'V', 'version-', 'Version-', 'VERSION-',
            'release-', 'Release-', 'RELEASE-', 'rel-', 'Rel-', 'REL-',
            'tag-', 'Tag-', 'TAG-', 'ver-', 'Ver-', 'VER-',
            'r-', 'R-', 'build-', 'Build-', 'BUILD-',
            'stable-', 'Stable-', 'STABLE-',
            'final-', 'Final-', 'FINAL-'
        ]

    def is_version_range(self, version: str) -> bool:
        """Check if version string is a range."""
        range_operators = ['<', '>', '=', '~', '^', '<=', '>=', '!=']
        return any(op in version for op in range_operators)

    def extract_range_operator(self, version: str) -> tuple[str, str]:
        """Extract operator and version from a version range string."""
        version = version.strip()

        operators = ['<=', '>=', '!=', '<', '>', '=', '~', '^']

        for op in operators:
            if version.startswith(op):
                return op, version[len(op):].strip()

        return '', version

    def normalize_version_for_comparison(self, version_str: str,
                                       package_name: str = "") -> str:
        """Normalize version string for comparison."""
        if not version_str:
            return ""

        normalized = version_str.strip()

        if package_name:
            package_lower = package_name.lower()
            for separator in ['-', '_']:
                prefix = f"{package_lower}{separator}"
                if normalized.lower().startswith(prefix):
                    normalized = normalized[len(prefix):]
                    break

        for prefix in self.prefixes_to_remove:
            if normalized.lower().startswith(prefix.lower()):
                normalized = normalized[len(prefix):]
                break

        return normalized.strip()

    def convert_version_formats(self, version: str,
                               package_name: str = "") -> list[str]:
        """Convert a version into multiple possible GitHub tag formats."""
        if not version:
            return []

        possible_formats = []
        package_lower = package_name.lower() if package_name else ""

        version_parts = version.split('.')

        possible_formats.extend([
            version,
            f"v{version}",
            f"V{version}",
        ])

        if package_name:
            possible_formats.extend([
                f"{package_name}-{version}",
                f"{package_name}_{version}",
                f"{package_name.upper()}-{version}",
                f"{package_name.capitalize()}-{version}",
            ])

        if len(version_parts) >= 2:
            underscore_version = "_".join(version_parts)
            possible_formats.extend([
                f"rel_{underscore_version}",
                f"REL_{underscore_version}",
                f"release_{underscore_version}",
                f"version_{underscore_version}",
                f"v_{underscore_version}",
            ])

            if package_name:
                possible_formats.extend([
                    f"{package_lower}_{underscore_version}",
                    f"{package_lower}_rel_{underscore_version}",
                ])

        if len(version_parts) >= 2:
            dash_version = "-".join(version_parts)
            possible_formats.extend([
                f"version-{dash_version}",
                f"release-{dash_version}",
                f"rel-{dash_version}",
            ])

        common_prefixes = [
            "version-", "Version-", "VERSION-",
            "release-", "Release-", "RELEASE-",
            "rel-", "Rel-", "REL-",
            "tag-", "Tag-", "TAG-",
            "ver-", "Ver-", "VER-",
            "stable-", "Stable-", "STABLE-",
        ]

        for prefix in common_prefixes:
            possible_formats.extend([
                f"{prefix}{version}",
                f"{prefix}v{version}",
            ])

        unique_formats = []
        seen = set()
        for fmt in possible_formats:
            if fmt not in seen:
                unique_formats.append(fmt)
                seen.add(fmt)

        return unique_formats

    def _compare_version_components(self, target: str, tag: str) -> bool:
        """Compare versions by breaking them into components."""
        try:
            target_match = re.findall(r'\d+|\w+', target)
            tag_match = re.findall(r'\d+|\w+', tag)

            if not target_match or not tag_match:
                return False

            def normalize_component(comp):
                return int(comp) if comp.isdigit() else comp.lower()

            target_components = [normalize_component(c) for c in target_match]
            tag_components = [normalize_component(c) for c in tag_match]

            return target_components == tag_components

        except Exception as e:
            logger.debug(f"Error comparing version components {target} vs {tag}: {e}")
            return False

    def version_exists_in_github_tags(self, target_version: str,
                                    tag_version: str,
                                    package_name: str = "") -> bool:
        """Check if target version matches a GitHub tag using flexible matching."""
        if not target_version or not tag_version:
            return False

        try:
            normalized_target = self.normalize_version_for_comparison(
                target_version, package_name)
            normalized_tag = self.normalize_version_for_comparison(
                tag_version, package_name)

            if normalized_target.lower() == normalized_tag.lower():
                return True

            possible_formats = self.convert_version_formats(
                normalized_target, package_name)

            tag_lower = tag_version.lower()
            for fmt in possible_formats:
                if fmt.lower() == tag_lower:
                    return True
                if fmt.lower() == normalized_tag.lower():
                    return True

            try:
                target_parsed = parse_version_lib(normalized_target)
                tag_parsed = parse_version_lib(normalized_tag)

                if target_parsed == tag_parsed:
                    return True

                if target_parsed.base_version == tag_parsed.base_version:
                    if (not target_parsed.is_prerelease and
                        tag_parsed.is_prerelease):
                        return True
                    elif (target_parsed.is_prerelease and
                          tag_parsed.is_prerelease):
                        return True

            except InvalidVersion as e:
                logger.debug(f"Invalid version format when comparing {normalized_target} vs {normalized_tag}: {e}")

            return self._compare_version_components(normalized_target, normalized_tag)

        except Exception as e:
            logger.debug(f"Error in version matching {target_version} vs {tag_version}: {e}")
            return False


class GitHubRepoDiscovery:
    """Main class for discovering GitHub repositories from package data."""

    def __init__(self):
        self.url_extractor = GitHubUrlExtractor()
        self.registry_lookup = RegistryLookup()
        self.github_searcher = GitHubSearcher()
        self.repo_selector = RepoSelector()
        self.purl_parser = PurlParser()

    def get_github_repo_url(self, package_data: dict[str, Any]) -> str | None:
        """Get GitHub repository URL from package data."""
        purl_prefix = package_data.get('purl_prefix', '')
        if purl_prefix:
            purl_data = self.purl_parser.parse_purl(purl_prefix)
            package_name = purl_data['name']
            project_type = purl_data['type']
            namespace = purl_data['namespace']
        else:
            package_name = package_data.get('package_name', '')
            project_type = package_data.get('project_type', '')
            namespace = ''

        vulnerabilities = package_data.get("vulnerabilties", [])

        if (package_name.startswith('_') and '/' in package_name and
            project_type.lower() == 'npm'):
            package_name = '@' + package_name[1:]

        all_candidates = []

        repo_urls_from_source = self.url_extractor.extract_github_repo_from_source(
            vulnerabilities)
        if repo_urls_from_source:
            all_candidates.extend(repo_urls_from_source)

        if package_name and project_type:
            repo_url_from_registry = self.registry_lookup.get_github_repo_from_registry(
                package_name, project_type, namespace)
            if repo_url_from_registry:
                all_candidates.append(repo_url_from_registry)

        if not all_candidates and package_name:
            direct_search_result = self.github_searcher.search_github_directly(
                package_name)
            if direct_search_result:
                all_candidates.append(direct_search_result)

        if not all_candidates:
            return None

        all_candidates = list(dict.fromkeys(all_candidates))

        selected_repo_url = self.repo_selector.select_best_repo_from_candidates(
            package_name, all_candidates)

        return selected_repo_url


class GitHubVersionValidator:
    """Main class for validating package versions against GitHub repositories."""

    def __init__(self):
        self.repo_discovery = GitHubRepoDiscovery()
        self.tags_fetcher = GitHubTagsFetcher()
        self.version_matcher = VersionMatcher()
        self.purl_parser = PurlParser()

    def validate_version_exists_in_github(self, version: str, repo_url: str,
                                        package_name: str = "") -> dict[str, Any]:
        """Check if a recommended version exists as a tag in the GitHub repository."""
        result = {
            'version_exists': False,
            'tags_url': f"{repo_url}/tags",
            'version_checked': version,
            'validation_status': 'failed',
            'repo_url': repo_url,
            'package_name': package_name,
            'error': None
        }

        success, all_tags, metadata = self.tags_fetcher.get_all_github_tags(repo_url)

        if not success:
            status_code = metadata.get('status_code')
            if status_code == 404:
                result['validation_status'] = 'repo_not_found'
            elif status_code == 403:
                result['validation_status'] = 'rate_limited'
            else:
                result['validation_status'] = 'api_error'
            result['error'] = metadata.get('error', 'Unknown error')
            return result

        if not all_tags:
            result.update({
                'validation_status': 'no_tags_found',
                'total_tags': 0
            })
            return result

        version_to_check = version.strip()
        if self.version_matcher.is_version_range(version):
            _, version_to_check = self.version_matcher.extract_range_operator(version)
            version_to_check = version_to_check.strip()

        matched_tags = []

        for tag in all_tags:
            if self.version_matcher.version_exists_in_github_tags(
                version_to_check, tag, package_name):
                matched_tags.append(tag)

        if matched_tags:
            result.update({
                'version_exists': True,
                'validation_status': 'success',
                'matched_tag': matched_tags[0],
                'all_matched_tags': sorted(list(set(matched_tags))),
                'total_tags': len(all_tags),
                'pages_fetched': metadata.get('pages_fetched', 0)
            })
            return result

        sample_tags = all_tags[:MAX_SAMPLE_TAGS] if len(all_tags) > MAX_SAMPLE_TAGS else all_tags
        possible_formats = self.version_matcher.convert_version_formats(
            version_to_check, package_name)

        result.update({
            'validation_status': 'version_not_found',
            'total_tags': len(all_tags),
            'pages_fetched': metadata.get('pages_fetched', 0),
            'sample_tags': sample_tags,
            'possible_formats_checked': possible_formats[:MAX_SAMPLE_FORMATS],
            'formats_count': len(possible_formats)
        })

        return result

    def validate_package_version_on_github(self, package_data: dict[str, Any],
                                         recommended_version: str) -> str | None:
        """Main validation function: Check if the recommended version exists on GitHub."""
        if not recommended_version:
            return None

        purl_prefix = package_data.get('purl_prefix', '')
        if purl_prefix:
            purl_data = self.purl_parser.parse_purl(purl_prefix)
            package_name = purl_data['name']
        else:
            package_name = package_data.get('package_name', 'unknown')

        repo_url = self.repo_discovery.get_github_repo_url(package_data)
        if not repo_url:
            return None

        validation_result = self.validate_version_exists_in_github(
            recommended_version, repo_url, package_name)

        if validation_result.get('version_exists'):
            return recommended_version
        else:
            return None


# Convenience functions for backward compatibility
def validate_package_version_on_github(package_data: dict[str, Any],
                                      recommended_version: str) -> str | None:
    """Main validation function for backward compatibility."""
    validator = GitHubVersionValidator()
    return validator.validate_package_version_on_github(package_data, recommended_version)


def validate_purl_version_on_github(purl: str, version: str) -> str | None:
    """Convenience function to validate a version using PURL format."""
    package_data = {'purl_prefix': purl, 'vulnerabilties': []}
    validator = GitHubVersionValidator()
    return validator.validate_package_version_on_github(package_data, version)


def validate_version_for_recursion(package_name: str, version: str,
                                  project_type: str = "",
                                  vendor: list[str] = None,
                                  purl_prefix: str = "") -> str | None:
    """Simplified validation function for recursion module use."""
    if not version:
        return None

    if purl_prefix:
        package_data = {
            'purl_prefix': purl_prefix,
            'vulnerabilties': []
        }
    else:
        if not package_name:
            return None

        package_data = {
            'package_name': package_name,
            'project_type': project_type,
            'vendor': vendor or [],
            'vulnerabilties': []
        }

    validator = GitHubVersionValidator()
    return validator.validate_package_version_on_github(package_data, version)


def get_package_info_from_purl(purl: str) -> dict[str, str]:
    """Extract package information from PURL for debugging/logging purposes."""
    parser = PurlParser()
    return parser.parse_purl(purl)