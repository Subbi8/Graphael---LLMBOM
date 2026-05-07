"""
Vulnerability Analysis Tool

This module provides classes for analyzing package vulnerabilities,
finding optimal versions, and validating recommendations against GitHub.
"""

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from typing import Any

from exploit_fix import ExploitResolver

# Third-party imports - these are confirmed to exist
from github_validation_july import GitHubVersionValidator

# Constants
MAX_LINE_LENGTH = 79
GITHUB_API_DELAY = 0.3
DEFAULT_VERSION = (0,)
MALWARE_CVE_PREFIX = 'MAL'
TIMEOUT_SECONDS = 30
PROGRESS_INTERVAL = 10


class VersionParser:
    """Handles version string parsing and comparison operations."""

    BETA_PATTERNS = [
        r'.*[b]\d*$',
        r'.*beta.*',
        r'.*alpha.*',
        r'.*pre.*',
        r'.*dev.*',
    ]

    RANGE_OPERATORS = ['<=', '>=', '<', '>', '^', '~']

    VERSION_TOKEN_PATTERN = re.compile(
        r'^[vV]?\d+(?:\.\d+){0,4}(?:[-_.]?(?:post|patch|rc|alpha|beta|dev|a|b)\d*)?$',
        re.IGNORECASE,
    )

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

        clean_version = re.sub(r'^[<>=^~]+', '', version_str.strip())

        return any(re.match(pattern, clean_version, re.IGNORECASE)
                  for pattern in self.BETA_PATTERNS)

    def parse_version(self, version_str: str) -> tuple[int, ...]:
        """
        Parse a version string into a tuple for reliable comparison.

        Args:
            version_str: Version string to parse

        Returns:
            Parsed version as tuple with letter suffixes converted to numbers
        """
        if not version_str:
            return DEFAULT_VERSION

        try:
            clean_version = re.sub(r'^[<>=^~]+', '', version_str.strip())

            match = re.match(r'^(\d+(?:\.\d+)*)([a-z]+\d*)?', clean_version)
            if not match:
                return DEFAULT_VERSION

            main_version = match.group(1)
            suffix = match.group(2) or ""

            parts = [int(part) for part in main_version.split('.')
                    if part.isdigit()]

            if suffix:
                letter_match = re.match(r'^([a-z]+)', suffix)
                if letter_match:
                    letter = letter_match.group(1)[0]
                    letter_value = ord(letter.lower()) - ord('a') + 1
                    parts.append(letter_value)

            return tuple(parts) if parts else DEFAULT_VERSION
        except (ValueError, AttributeError):
            return DEFAULT_VERSION

    def is_version_range(self, version_str: str) -> bool:
        """Check if a version string is a range constraint."""
        if not version_str:
            return False
        return bool(re.match(r'^[<>=^~]', version_str.strip()))

    def is_package_version_like(self, version_str: str) -> bool:
        """Return True when a fix value looks like a package version, not a commit hash."""
        if not version_str:
            return False

        clean_version = re.sub(r'^[<>=^~]+', '', version_str.strip())
        if not clean_version:
            return False

        # Avoid treating git SHAs as versions.
        if re.fullmatch(r'[0-9a-f]{12,40}', clean_version, re.IGNORECASE):
            return False

        return bool(self.VERSION_TOKEN_PATTERN.match(clean_version))

    def extract_range_operator(self, version_str: str) -> tuple[str, str]:
        """Extract the range operator and clean version from a version range."""
        if not version_str:
            return ("", "")

        version_str = version_str.strip()
        match = re.match(r'^([<>=^~]+)', version_str)

        if match:
            operator = match.group(1)
            clean_version = version_str[len(operator):].strip()
            return (operator, clean_version)

        return ("", version_str)

    def version_compare(self, version1: str, version2: str) -> int:
        """
        Compare two version strings.

        Returns:
            -1 if version1 < version2
            0 if version1 == version2
            1 if version1 > version2
        """
        def clean_version(v):
            if self.is_version_range(v):
                _, clean_v = self.extract_range_operator(v)
                return clean_v
            return v

        v1_clean = clean_version(version1)
        v2_clean = clean_version(version2)

        v1_parts = self.parse_version(v1_clean)
        v2_parts = self.parse_version(v2_clean)

        max_len = max(len(v1_parts), len(v2_parts))
        v1_padded = v1_parts + (0,) * (max_len - len(v1_parts))
        v2_padded = v2_parts + (0,) * (max_len - len(v2_parts))

        if v1_padded < v2_padded:
            return -1
        elif v1_padded > v2_padded:
            return 1
        else:
            return 0

    def is_version_in_range(self, current_version: str,
                           version_range: str) -> bool:
        """Check if a version is within a specified range constraint."""
        if not current_version or not version_range:
            return False

        if not self.is_version_range(version_range):
            return self.version_compare(current_version, version_range) == 0

        operator, target_version = self.extract_range_operator(version_range)
        if not operator or not target_version:
            return False

        comparison = self.version_compare(current_version, target_version)

        operator_map = {
            "<": comparison < 0,
            "<=": comparison <= 0,
            ">": comparison > 0,
            ">=": comparison >= 0,
            "^": self._handle_caret_range(current_version, target_version,
                                       comparison),
            "~": self._handle_tilde_range(current_version, target_version,
                                       comparison)
        }

        return operator_map.get(operator, False)

    def _handle_caret_range(self, current_version: str, target_version: str,
                           comparison: int) -> bool:
        """Handle caret range logic."""
        if comparison < 0:
            return False
        current_parts = self.parse_version(current_version)
        target_parts = self.parse_version(target_version)
        if len(current_parts) > 0 and len(target_parts) > 0:
            return current_parts[0] == target_parts[0]
        return False

    def _handle_tilde_range(self, current_version: str, target_version: str,
                           comparison: int) -> bool:
        """Handle tilde range logic."""
        if comparison < 0:
            return False
        current_parts = self.parse_version(current_version)
        target_parts = self.parse_version(target_version)
        if len(current_parts) >= 2 and len(target_parts) >= 2:
            return (current_parts[0] == target_parts[0] and
                   current_parts[1] == target_parts[1])
        return False


class VulnerabilityChecker:
    """Handles vulnerability-related checks and filtering."""

    def __init__(self):
        self.version_parser = VersionParser()

    def is_malware_package(self, package_data: dict[str, Any]) -> bool:
        """Check if a package contains any CVE that starts with MAL prefix."""
        vulnerabilities = self._get_vulnerabilities(package_data)

        return any(cve.get('cve_id', '').startswith(MALWARE_CVE_PREFIX)
                  for cve in vulnerabilities)

    def _get_vulnerabilities(self, package_data: dict[str, Any]) -> list[dict]:
        """Get vulnerabilities from package data, handling both key variations."""
        return (package_data.get("vulnerabilties", []) or
                package_data.get("vulnerabilities", []))

    def categorize_cves(self, vulnerabilities: list[dict],
                       current_version: str) -> tuple[list[dict], list[dict],
                                                    list[dict], list[dict]]:
        """Categorize CVEs into different lists based on their properties."""
        all_cves_with_fixes = []
        malware_cves_excluded = []
        beta_versions_excluded = []
        already_fixed_cves = []

        for cve in vulnerabilities:
            fixed_location = cve.get("fixed_location")
            if not fixed_location or not fixed_location.strip():
                continue

            fixed_location_clean = fixed_location.strip()
            if not self.version_parser.is_package_version_like(fixed_location_clean):
                continue

            if self._is_malware_cve(cve, fixed_location_clean,
                                   malware_cves_excluded):
                continue

            if self._is_beta_cve(cve, fixed_location_clean,
                               beta_versions_excluded):
                continue

            if self._is_already_fixed(current_version, fixed_location_clean,
                                    cve, already_fixed_cves):
                continue

            all_cves_with_fixes.append({
                'cve_id': cve.get('cve_id'),
                'severity': cve.get('severity', 'unknown').lower(),
                'fixed_location': fixed_location_clean,
                'score': cve.get('score', 0),
                'malware': cve.get('malware', False)
            })

        return (all_cves_with_fixes, malware_cves_excluded,
                beta_versions_excluded, already_fixed_cves)

    def _is_malware_cve(self, cve: dict, fixed_location: str,
                       malware_list: list[dict]) -> bool:
        """Check if CVE is marked as malware and add to exclusion list."""
        if cve.get("malware") is True:
            malware_list.append({
                'cve_id': cve.get('cve_id'),
                'severity': cve.get('severity', 'unknown').lower(),
                'fixed_location': fixed_location,
                'reason': 'CVE marked as malware'
            })
            return True
        return False

    def _is_beta_cve(self, cve: dict, fixed_location: str,
                    beta_list: list[dict]) -> bool:
        """Check if CVE fix is a beta version and add to exclusion list."""
        if self.version_parser.is_beta_version(fixed_location):
            beta_list.append({
                'cve_id': cve.get('cve_id'),
                'severity': cve.get('severity', 'unknown').lower(),
                'fixed_location': fixed_location,
                'reason': 'Fixed version is beta/pre-release'
            })
            return True
        return False

    def _is_already_fixed(self, current_version: str, fixed_location: str,
                         cve: dict, fixed_list: list[dict]) -> bool:
        """Check if current version already includes the fix."""
        if not current_version or not fixed_location:
            return False

        current_version_clean = current_version.strip()

        if self.version_parser.is_version_range(current_version_clean):
            return self._handle_version_range_fix(current_version_clean,
                                                 fixed_location)
        else:
            return self._handle_exact_version_fix(current_version_clean,
                                                 fixed_location, cve,
                                                 fixed_list)

    def _handle_version_range_fix(self, current_version: str,
                                 fixed_location: str) -> bool:
        """Handle fix checking for version ranges."""
        if self.version_parser.is_version_in_range(fixed_location,
                                                  current_version):
            return False
        return False

    def _handle_exact_version_fix(self, current_version: str,
                                 fixed_location: str, cve: dict,
                                 fixed_list: list[dict]) -> bool:
        """
        Handle fix checking for exact versions.

        FIXED: Corrected the version comparison logic.
        CVE is already fixed ONLY if current_version >= fixed_location.
        """
        comparison = self.version_parser.version_compare(current_version, fixed_location)

        # FIXED: CVE is already fixed if current version >= fixed version
        if comparison >= 0:
            fixed_list.append({
                'cve_id': cve.get('cve_id'),
                'severity': cve.get('severity', 'unknown').lower(),
                'fixed_location': fixed_location,
                'reason': f"Current version {current_version} is >= fix version {fixed_location}"
            })
            return True
        else:
            # Current version < fixed version, so CVE is NOT fixed yet
            return False


class OptimalVersionFinder:
    """Finds optimal versions for packages based on CVE analysis."""

    def __init__(self):
        self.vulnerability_checker = VulnerabilityChecker()
        self.version_parser = VersionParser()
        self.github_validator = GitHubVersionValidator()

    def _detect_registry_provider(self, package_data: dict[str, Any]) -> str:
        project_type = str(package_data.get('project_type', '')).lower()
        purl = str(package_data.get('purl') or package_data.get('purl_prefix') or '').lower()

        if 'pkg:pypi/' in purl or 'python' in project_type or 'pypi' in project_type:
            return 'pypi'
        if 'pkg:npm/' in purl or 'javascript' in project_type or 'node' in project_type or 'npm' in project_type:
            return 'npm'
        if 'pkg:nuget/' in purl or 'nuget' in project_type or 'dotnet' in project_type:
            return 'nuget'

        return ''

    def _registry_version_exists(
        self,
        package_name: str,
        version: str,
        provider: str,
    ) -> tuple[bool, str]:
        if not package_name or not version or not provider:
            return False, ''

        clean_version = re.sub(r'^[<>=^~]+', '', version.strip())
        if provider == 'pypi':
            package = urllib.parse.quote(package_name)
            encoded_version = urllib.parse.quote(clean_version)
            url = f'https://pypi.org/pypi/{package}/{encoded_version}/json'
        elif provider == 'npm':
            package = urllib.parse.quote(package_name, safe='')
            encoded_version = urllib.parse.quote(clean_version, safe='')
            url = f'https://registry.npmjs.org/{package}/{encoded_version}'
        elif provider == 'nuget':
            package = urllib.parse.quote(package_name.lower(), safe='')
            encoded_version = urllib.parse.quote(clean_version.lower(), safe='')
            url = f'https://api.nuget.org/v3-flatcontainer/{package}/{encoded_version}/{package}.nuspec'
        else:
            return False, ''

        request = urllib.request.Request(
            url,
            headers={'User-Agent': 'LLMBOM-Version-Validator/1.0'},
            method='GET',
        )
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
                return 200 <= response.status < 300, url
        except urllib.error.HTTPError as exc:
            return False, url if exc.code == 404 else url
        except (urllib.error.URLError, TimeoutError, OSError):
            return False, url

    def _validate_with_registry(
        self,
        optimal_version: str,
        current_version: str,
        version_details: dict[str, Any],
        package_data: dict[str, Any],
        versions_to_try: list[str],
    ) -> tuple[str | None, dict, bool]:
        provider = self._detect_registry_provider(package_data)
        if not provider:
            return None, version_details, False

        package_name = package_data.get('package_name', '')
        validation_attempts = []
        for version_to_try in versions_to_try:
            exists, url = self._registry_version_exists(package_name, version_to_try, provider)
            validation_attempts.append({
                'version_tried': version_to_try,
                'found_in_registry': exists,
                'registry_url': url,
            })

            if exists:
                version_details['github_validation'] = {
                    'validation_attempted': True,
                    'validation_provider': provider,
                    'original_recommendation': optimal_version,
                    'github_validated_version': version_to_try,
                    'registry_validated_version': version_to_try,
                    'version_exists_on_github': True,
                    'version_exists_in_registry': True,
                    'fallback_used': version_to_try != optimal_version,
                    'validation_attempts': validation_attempts,
                }

                if version_to_try != optimal_version:
                    version_details['recommended_version'] = version_to_try
                    version_details['selection_reason'] += (
                        f" ({provider} fallback from {optimal_version} to {version_to_try})"
                    )

                return version_to_try, version_details, True

        version_details['github_validation'] = {
            'validation_attempted': True,
            'validation_provider': provider,
            'original_recommendation': optimal_version,
            'github_validated_version': None,
            'registry_validated_version': None,
            'version_exists_on_github': False,
            'version_exists_in_registry': False,
            'rejection_reason': (
                f'Neither {optimal_version} nor any fallback versions found in {provider} registry'
            ),
            'validation_attempts': validation_attempts,
            'fallback_attempted': len(validation_attempts) > 1,
        }
        return None, version_details, True

    def find_critical_high_optimal_version(self,
                                         package_data: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
        """Find optimal version prioritizing critical/high CVEs only."""
        vulnerabilities = self.vulnerability_checker._get_vulnerabilities(
            package_data)
        current_version = package_data.get("package_version", "")

        if not vulnerabilities:
            return self._create_no_vulnerabilities_result(package_data,
                                                         current_version)

        if self.vulnerability_checker.is_malware_package(package_data):
            return self._create_malware_result(package_data)

        (all_cves_with_fixes, malware_cves_excluded,
         beta_versions_excluded, already_fixed_cves) = (
            self.vulnerability_checker.categorize_cves(vulnerabilities,
                                                      current_version))

        if not all_cves_with_fixes:
            return self._handle_no_fixes_available(
                current_version, already_fixed_cves, malware_cves_excluded,
                beta_versions_excluded, package_data)

        critical_high_cves = [cve for cve in all_cves_with_fixes
                             if cve['severity'] in ['critical', 'high']]
        medium_low_cves = [cve for cve in all_cves_with_fixes
                          if cve['severity'] in ['medium', 'low']]

        optimal_version, selection_reason, cves_with_fixes = (
            self._select_optimal_version_critical_high(critical_high_cves,
                                                      medium_low_cves))

        if not optimal_version:
            optimal_version = current_version

        version_details = self._build_version_details(
            package_data, optimal_version, current_version, selection_reason,
            cves_with_fixes, already_fixed_cves, malware_cves_excluded,
            beta_versions_excluded)

        return self._validate_with_github(optimal_version, current_version,
                                        version_details, package_data)

    def find_all_cves_optimal_version(self,
                                    package_data: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
        """Find optimal version based on ALL CVE severities."""
        vulnerabilities = self.vulnerability_checker._get_vulnerabilities(
            package_data)
        current_version = package_data.get("package_version", "")

        if not vulnerabilities:
            return self._create_no_vulnerabilities_result(package_data,
                                                         current_version)

        if self.vulnerability_checker.is_malware_package(package_data):
            return self._create_malware_result(package_data)

        (cves_with_fixes, malware_cves_excluded,
         beta_versions_excluded, already_fixed_cves) = (
            self.vulnerability_checker.categorize_cves(vulnerabilities,
                                                      current_version))

        if not cves_with_fixes:
            return self._handle_no_fixes_available(
                current_version, already_fixed_cves, malware_cves_excluded,
                beta_versions_excluded, package_data)

        all_versions = [cve['fixed_location'] for cve in cves_with_fixes]
        optimal_version = max(all_versions,
                            key=lambda v: self.version_parser.parse_version(v))

        selection_reason = (f"MAX version among {len(all_versions)} versions "
                          f"fixing ALL CVEs regardless of severity")

        version_details = self._build_version_details(
            package_data, optimal_version, current_version, selection_reason,
            cves_with_fixes, already_fixed_cves, malware_cves_excluded,
            beta_versions_excluded)

        return self._validate_with_github(optimal_version, current_version,
                                        version_details, package_data)

    def _create_no_vulnerabilities_result(self, package_data: dict[str, Any],
                                        current_version: str) -> tuple[str, dict]:
        """Create result for packages with no vulnerabilities."""
        return current_version, {
            "message": "No vulnerabilities found for this package",
            "package_name": package_data.get('package_name'),
            "current_version": current_version,
            "recommended_version": current_version,
            "github_validation": {'validation_attempted': False}
        }

    def _create_malware_result(self,
                             package_data: dict[str, Any]) -> tuple[None, dict]:
        """Create result for malware packages."""
        package_name = package_data.get('package_name', 'unknown')
        return None, {
            "message": f"Package '{package_name}' contains CVE(s) "
                      f"starting with 'MAL'",
            "malware_package": True,
            "package_excluded": True
        }

    def _select_optimal_version_critical_high(self, critical_high_cves: list[dict],
                                            medium_low_cves: list[dict]) -> tuple[str | None, str, list[dict]]:
        """Select optimal version for critical/high approach."""
        if critical_high_cves:
            critical_high_versions = [cve['fixed_location']
                                    for cve in critical_high_cves]
            optimal_version = max(critical_high_versions,
                                key=lambda v: self.version_parser.parse_version(v))
            selection_reason = (f"MAX version among {len(critical_high_versions)} "
                              f"versions fixing critical/high CVEs")
            return optimal_version, selection_reason, critical_high_cves
        elif medium_low_cves:
            medium_low_versions = [cve['fixed_location']
                                 for cve in medium_low_cves]
            optimal_version = max(medium_low_versions,
                                key=lambda v: self.version_parser.parse_version(v))
            selection_reason = (f"No critical/high CVEs found. MAX version among "
                              f"{len(medium_low_versions)} versions fixing "
                              f"medium/low CVEs")
            return optimal_version, selection_reason, medium_low_cves

        return None, "", []

    def _build_version_details(self, package_data: dict[str, Any],
                              optimal_version: str, current_version: str,
                              selection_reason: str, cves_with_fixes: list[dict],
                              already_fixed_cves: list[dict],
                              malware_cves_excluded: list[dict],
                              beta_versions_excluded: list[dict]) -> dict[str, Any]:
        """Build detailed recommendation information."""
        if not optimal_version:
            return {}

        cves_fixed_by_optimal = [
            cve for cve in cves_with_fixes
            if cve['fixed_location'] == optimal_version
        ]
        severity_counts = Counter(cve['severity']
                                for cve in cves_fixed_by_optimal)

        total_cves_fixed = [
            cve for cve in cves_with_fixes
            if self.version_parser.version_compare(
                cve['fixed_location'], optimal_version) <= 0
        ]

        total_severity_counts = Counter(cve['severity']
                                      for cve in total_cves_fixed)

        return {
            'package_name': package_data.get('package_name'),
            'current_version': current_version,
            'recommended_version': optimal_version,
            'selection_reason': selection_reason,
            'cves_fixed_directly': len(cves_fixed_by_optimal),
            'total_cves_potentially_fixed': len(total_cves_fixed),
            'already_fixed_cves': len(already_fixed_cves),
            'malware_cves_excluded': len(malware_cves_excluded),
            'beta_cves_excluded': len(beta_versions_excluded),
            'malware_excluded_details': malware_cves_excluded,
            'beta_excluded_details': beta_versions_excluded,
            'already_fixed_details': already_fixed_cves,
            'severity_breakdown_direct': dict(severity_counts),
            'severity_breakdown_total': dict(total_severity_counts),
            'critical_count': total_severity_counts.get('critical', 0),
            'high_count': total_severity_counts.get('high', 0),
            'medium_count': total_severity_counts.get('medium', 0),
            'low_count': total_severity_counts.get('low', 0),
            'unknown_count': total_severity_counts.get('unknown', 0),
            'cve_ids_fixed_directly': [cve['cve_id']
                                     for cve in cves_fixed_by_optimal],
            'all_cve_ids_potentially_fixed': [cve['cve_id']
                                            for cve in total_cves_fixed],
            'vendor': package_data.get('vendor', []),
            'repo_name': package_data.get('repo_name', ''),
            'project_type': package_data.get('project_type', ''),
            'github_validation': {'validation_attempted': False}
        }

    def _handle_no_fixes_available(self, current_version: str,
                                 already_fixed_cves: list[dict],
                                 malware_cves_excluded: list[dict],
                                 beta_versions_excluded: list[dict],
                                 package_data: dict[str, Any]) -> tuple[str, dict]:
        """Handle case when no fixes are available."""
        message_parts = []
        if already_fixed_cves:
            message_parts.append(
                f"Current version ({current_version}) already includes "
                f"fixes for {len(already_fixed_cves)} CVE(s)")
        if malware_cves_excluded:
            message_parts.append(
                f"{len(malware_cves_excluded)} CVE(s) excluded due to "
                f"malware flag")
        if beta_versions_excluded:
            message_parts.append(
                f"{len(beta_versions_excluded)} CVE(s) excluded due to "
                f"beta/pre-release fixes")

        return current_version, {
            "message": (". ".join(message_parts) if message_parts else
                       "All CVEs are already fixed in current version"),
            "already_fixed_cves": len(already_fixed_cves),
            "malware_excluded_cves": len(malware_cves_excluded),
            "beta_excluded_cves": len(beta_versions_excluded),
            "malware_excluded_details": malware_cves_excluded,
            "beta_excluded_details": beta_versions_excluded,
            "already_fixed_details": already_fixed_cves,
            "github_validation": {'validation_attempted': True},
            "package_name": package_data.get('package_name'),
            "current_version": current_version,
            "recommended_version": current_version
        }

    def _validate_with_github(self, optimal_version: str, current_version: str,
                            version_details: dict[str, Any],
                            package_data: dict[str, Any]) -> tuple[str | None, dict]:
        """
        Validate recommended version with GitHub with enhanced fallback logic.
        If the optimal version is not found, try the next highest available versions.
        """
        if optimal_version and optimal_version != current_version:
            # Get all available fix versions for fallback
            all_fix_versions = self._get_all_available_fix_versions(package_data, current_version)

            # Start with the optimal version, then try fallbacks
            versions_to_try = [
                v for v in [optimal_version] + [v for v in all_fix_versions if v != optimal_version]
                if self.version_parser.is_package_version_like(v)
            ]

            registry_version, registry_details, registry_attempted = self._validate_with_registry(
                optimal_version,
                current_version,
                version_details,
                package_data,
                versions_to_try,
            )
            if registry_attempted:
                if registry_version is None:
                    version_details['recommended_version'] = None
                return registry_version, registry_details

            validation_attempts = []

            for version_to_try in versions_to_try:
                validated_version = self.github_validator.validate_package_version_on_github(
                    package_data, version_to_try)

                validation_attempts.append({
                    'version_tried': version_to_try,
                    'found_on_github': validated_version is not None
                })

                if validated_version is not None:
                    # Found a version that exists on GitHub
                    version_details['github_validation'] = {
                        'validation_attempted': True,
                        'original_recommendation': optimal_version,
                        'github_validated_version': validated_version,
                        'version_exists_on_github': True,
                        'fallback_used': version_to_try != optimal_version,
                        'validation_attempts': validation_attempts
                    }

                    if version_to_try != optimal_version:
                        version_details['recommended_version'] = validated_version
                        version_details['selection_reason'] += f" (GitHub fallback from {optimal_version} to {validated_version})"

                    return validated_version, version_details

            # No version found on GitHub after trying all available versions
            version_details['github_validation'] = {
                'validation_attempted': True,
                'original_recommendation': optimal_version,
                'github_validated_version': None,
                'version_exists_on_github': False,
                'rejection_reason': f'Neither {optimal_version} nor any fallback versions found in GitHub repository tags',
                'validation_attempts': validation_attempts,
                'fallback_attempted': len(validation_attempts) > 1
            }
            version_details['recommended_version'] = None
            return None, version_details
        else:
            version_details['github_validation'] = {
                'validation_attempted': False
            }
            return optimal_version, version_details

    def _get_all_available_fix_versions(self, package_data: dict[str, Any],
                                      current_version: str) -> list[str]:
        """
        Get all available fix versions that are higher than current version,
        sorted in ascending order for systematic fallback.
        """
        vulnerabilities = self.vulnerability_checker._get_vulnerabilities(package_data)

        all_fix_versions = set()
        current_parsed = self.version_parser.parse_version(current_version)

        for vuln in vulnerabilities:
            fixed_location = vuln.get('fixed_location')
            if fixed_location and fixed_location.strip():
                fixed_location_clean = fixed_location.strip()

                # Skip beta versions
                if self.version_parser.is_beta_version(fixed_location_clean):
                    continue

                # Only include versions higher than current
                if (self.version_parser.parse_version(fixed_location_clean) > current_parsed):
                    all_fix_versions.add(fixed_location_clean)

        # Sort versions in ascending order (lowest first for systematic fallback)
        sorted_versions = sorted(list(all_fix_versions),
                               key=lambda v: self.version_parser.parse_version(v))

        return sorted_versions


class PackageDeduplicator:
    """Handles package deduplication operations."""

    def __init__(self):
        self.version_parser = VersionParser()

    def deduplicate_packages(self,
                           data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Deduplicate packages by name, keeping the most specific version.
        Priority: exact version > version range > no version
        """
        package_groups = defaultdict(list)

        for package_data in data:
            package_name = package_data.get('package_name', '')
            if package_name:
                package_groups[package_name].append(package_data)

        deduplicated_data = []

        for package_name, packages in package_groups.items():
            if len(packages) == 1:
                deduplicated_data.append(packages[0])
            else:
                selected_package = self._select_best_package(packages)
                deduplicated_data.append(selected_package)

        return deduplicated_data

    def _select_best_package(self,
                           packages: list[dict[str, Any]]) -> dict[str, Any]:
        """Select the best package from multiple entries."""
        def version_priority(pkg):
            version = pkg.get('package_version', '')
            if not version:
                return 3
            elif self.version_parser.is_version_range(version):
                return 2
            else:
                return 1

        packages.sort(key=version_priority)
        selected_package = packages[0]

        all_vulnerabilities = []
        for pkg in packages:
            pkg_vulns = (pkg.get('vulnerabilties', []) or
                        pkg.get('vulnerabilities', []))
            all_vulnerabilities.extend(pkg_vulns)

        unique_cves = {}
        for vuln in all_vulnerabilities:
            cve_id = vuln.get('cve_id', '')
            if cve_id and cve_id not in unique_cves:
                unique_cves[cve_id] = vuln

        vulnerability_key = self._determine_vulnerability_key(selected_package)
        selected_package[vulnerability_key] = list(unique_cves.values())

        return selected_package

    def _determine_vulnerability_key(self, package: dict[str, Any]) -> str:
        """Determine which vulnerability key to use."""
        if 'vulnerabilties' in package:
            return 'vulnerabilties'
        elif 'vulnerabilities' in package:
            return 'vulnerabilities'
        else:
            return 'vulnerabilties'


class SummaryStatistics:
    """Manages summary statistics for vulnerability analysis."""

    def __init__(self):
        self.stats = self._initialize_summary_stats()

    def _initialize_summary_stats(self) -> dict[str, Any]:
        """Initialize summary statistics structure."""
        return {
            'total_packages': 0,
            'packages_with_vulnerabilities': 0,
            'packages_without_vulnerabilities': 0,
            'malware_packages_excluded': 0,
            'github_validation_stats': {
                'total_validations_attempted': 0,
                'versions_found_in_github': 0,
                'versions_not_found_in_github': 0,
                'packages_with_validated_recommendations': 0,
                'packages_with_rejected_recommendations': 0
            },
            'critical_high_only': self._initialize_approach_stats(),
            'all_cves': self._initialize_approach_stats(),
            'github_rejected_packages': []
        }

    def _initialize_approach_stats(self) -> dict[str, Any]:
        """Initialize statistics for a specific approach."""
        return {
            'packages_with_recommendations': 0,
            'packages_without_vulnerabilities': 0,
            'packages_without_fixes': 0,
            'packages_already_fixed': 0,
            'github_validated_recommendations': 0,
            'github_rejected_recommendations': 0,
            'total_malware_cves_excluded': 0,
            'total_beta_cves_excluded': 0,
            'severity_summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        }

    def update_package_counts(self, has_vulnerabilities: bool) -> None:
        """Update package count statistics."""
        self.stats['total_packages'] += 1
        if has_vulnerabilities:
            self.stats['packages_with_vulnerabilities'] += 1
        else:
            self.stats['packages_without_vulnerabilities'] += 1

    def update_malware_count(self) -> None:
        """Update malware package count."""
        self.stats['malware_packages_excluded'] += 1

    def update_github_validation_stats(self, details: dict[str, Any]) -> None:
        """Update GitHub validation statistics."""
        github_validation = details.get('github_validation', {})

        if github_validation.get('validation_attempted'):
            self.stats['github_validation_stats']['total_validations_attempted'] += 1
            if github_validation.get('version_exists_on_github'):
                self.stats['github_validation_stats']['versions_found_in_github'] += 1
            else:
                self.stats['github_validation_stats']['versions_not_found_in_github'] += 1

    def update_approach_stats(self, details: dict[str, Any],
                             approach_name: str, current_version: str) -> None:
        """Update statistics for a specific approach."""
        recommended_version = details.get('recommended_version')
        stats = self.stats[approach_name]

        if recommended_version and recommended_version != current_version:
            stats['packages_with_recommendations'] += 1

            github_validation = details.get('github_validation', {})
            if (github_validation.get('validation_attempted') and
                github_validation.get('version_exists_on_github')):
                stats['github_validated_recommendations'] += 1
            elif (github_validation.get('validation_attempted') and
                  not github_validation.get('version_exists_on_github')):
                stats['github_rejected_recommendations'] += 1

        elif (recommended_version == current_version and
              details.get('already_fixed_cves', 0) > 0):
            stats['packages_already_fixed'] += 1
        else:
            stats['packages_without_fixes'] += 1

        for severity in ['critical', 'high', 'medium', 'low']:
            stats['severity_summary'][severity] += details.get(f'{severity}_count', 0)

        stats['total_malware_cves_excluded'] += details.get('malware_cves_excluded', 0)
        stats['total_beta_cves_excluded'] += details.get('beta_cves_excluded', 0)

    def add_github_rejection(self, package_data: dict[str, Any],
                            critical_high_details: dict[str, Any],
                            all_cves_details: dict[str, Any]) -> None:
        """Add GitHub rejection information."""
        pkg_name = package_data.get('package_name', 'unknown')
        current_pkg_version = package_data.get('package_version', '')

        critical_high_github = critical_high_details.get('github_validation', {})
        all_cves_github = all_cves_details.get('github_validation', {})

        has_rejection = (
            (critical_high_github.get('validation_attempted') and
             not critical_high_github.get('version_exists_on_github')) or
            (all_cves_github.get('validation_attempted') and
             not all_cves_github.get('version_exists_on_github'))
        )

        if has_rejection:
            rejected_info = {
                'package_name': pkg_name,
                'current_version': current_pkg_version,
                'critical_high_approach': self._extract_rejection_info(critical_high_github),
                'all_cves_approach': self._extract_rejection_info(all_cves_github)
            }
            self.stats['github_rejected_packages'].append(rejected_info)

    def _extract_rejection_info(self, github_validation: dict[str, Any]) -> dict[str, Any]:
        """Extract rejection information from GitHub validation results."""
        return {
            'original_recommendation': github_validation.get('original_recommendation'),
            'validation_attempted': github_validation.get('validation_attempted', False),
            'rejected': (github_validation.get('validation_attempted', False) and
                        not github_validation.get('version_exists_on_github', True)),
            'rejection_reason': github_validation.get('rejection_reason', 'N/A')
        }

    def finalize_github_stats(self) -> None:
        """Calculate final GitHub validation statistics."""
        github_stats = self.stats['github_validation_stats']

        github_stats['packages_with_validated_recommendations'] = (
            self.stats['critical_high_only']['github_validated_recommendations'] +
            self.stats['all_cves']['github_validated_recommendations']
        )
        github_stats['packages_with_rejected_recommendations'] = (
            self.stats['critical_high_only']['github_rejected_recommendations'] +
            self.stats['all_cves']['github_rejected_recommendations']
        )

    def get_stats(self) -> dict[str, Any]:
        """Get current statistics."""
        return self.stats


class VulnerabilityAnalysisEngine:
    """Main engine for vulnerability analysis and optimal version finding."""

    def __init__(self):
        self.deduplicator = PackageDeduplicator()
        self.version_finder = OptimalVersionFinder()
        self.statistics = SummaryStatistics()

    def analyze_all_packages(self,
                           data: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Process packages and find optimal versions with GitHub validation."""
        data = self.deduplicator.deduplicate_packages(data)

        packages_with_vulns, packages_without_vulns = self._separate_packages(data)

        results = []
        results.extend(self._process_packages_without_vulnerabilities(packages_without_vulns))
        results.extend(self._process_packages_with_vulnerabilities(packages_with_vulns))

        self.statistics.finalize_github_stats()

        return results, self.statistics.get_stats()

    def _separate_packages(self,
                          data: list[dict[str, Any]]) -> tuple[list[dict], list[dict]]:
        """Separate packages with and without vulnerabilities."""
        packages_with_vulns = []
        packages_without_vulns = []

        for package_data in data:
            vulnerabilities = (package_data.get("vulnerabilties", []) or
                             package_data.get("vulnerabilities", []))

            has_vulnerabilities = bool(vulnerabilities)
            self.statistics.update_package_counts(has_vulnerabilities)

            if has_vulnerabilities:
                packages_with_vulns.append(package_data)
            else:
                packages_without_vulns.append(package_data)

        return packages_with_vulns, packages_without_vulns

    def _process_packages_without_vulnerabilities(self,
                                                packages: list[dict]) -> list[dict]:
        """Process packages that have no vulnerabilities."""
        results = []

        for package_data in packages:
            package_data["first_optimal_version"] = self._create_safe_package_result(package_data)
            package_data["recommendation_method"] = "no_vulnerabilities_found_skipped_processing"

            self.statistics.stats['critical_high_only']['packages_without_vulnerabilities'] += 1
            self.statistics.stats['all_cves']['packages_without_vulnerabilities'] += 1

            results.append(package_data)

        return results

    def _create_safe_package_result(self, package_data: dict[str, Any]) -> dict[str, Any]:
        """Create result structure for packages with no vulnerabilities."""
        safe_result = {
            "recommended_version": package_data.get("package_version", ""),
            "recommendation_details": {
                "message": "No vulnerabilities found for this package",
                "package_name": package_data.get('package_name'),
                "current_version": package_data.get("package_version", ""),
                "recommended_version": package_data.get("package_version", ""),
                "github_validation": {'validation_attempted': False}
            }
        }

        return {
            "High and critical cves": safe_result,
            "All cves": safe_result
        }

    def _process_packages_with_vulnerabilities(self,
                                             packages: list[dict]) -> list[dict]:
        """Process packages that have vulnerabilities."""
        results = []

        for i, package_data in enumerate(packages):
            if i % PROGRESS_INTERVAL == 0:
                self._log_progress(i, len(packages), package_data)

            if self.version_finder.vulnerability_checker.is_malware_package(package_data):
                self._handle_malware_package(package_data)
                results.append(package_data)
                continue

            self._process_vulnerable_package(package_data)
            results.append(package_data)

            time.sleep(GITHUB_API_DELAY)

        return results

    def _log_progress(self, current: int, total: int, package_data: dict[str, Any]) -> None:
        """Log processing progress."""
        package_name = package_data.get('package_name', 'unknown')
        package_version = package_data.get('package_version', 'no-version')
        print(f"Processing vulnerable package {current+1}/{total}: "
              f"{package_name} ({package_version})")

    def _handle_malware_package(self, package_data: dict[str, Any]) -> None:
        """Handle packages identified as malware."""
        self.statistics.update_malware_count()

        malware_result = {
            "recommended_version": None,
            "recommendation_details": {
                "message": f"Package '{package_data.get('package_name', 'unknown')}' contains CVE(s) starting with 'MAL'",
                "malware_package": True,
                "package_excluded": True
            }
        }

        package_data["first_optimal_version"] = {
            "High and critical cves": malware_result,
            "All cves": malware_result
        }
        package_data["recommendation_method"] = "malware_package_excluded_due_to_mal_cve"

    def _process_vulnerable_package(self, package_data: dict[str, Any]) -> None:
        """Process a package with vulnerabilities."""
        current_version = package_data.get("package_version", "")

        if current_version and self.version_finder.version_parser.is_version_range(current_version):
            package_name = package_data.get('package_name', 'unknown')
            print(f"  [VERSION_RANGE] Detected version range: {current_version} for {package_name}")

        critical_high_version, critical_high_details = (
            self.version_finder.find_critical_high_optimal_version(package_data))
        all_cves_version, all_cves_details = (
            self.version_finder.find_all_cves_optimal_version(package_data))

        self.statistics.add_github_rejection(package_data, critical_high_details, all_cves_details)

        first_optimal_version = {
            "High and critical cves": {
                "recommended_version": critical_high_version,
                "recommendation_details": critical_high_details
            },
            "All cves": {
                "recommended_version": all_cves_version,
                "recommendation_details": all_cves_details
            }
        }

        package_data["first_optimal_version"] = first_optimal_version
        package_data["recommendation_method"] = "vulnerability_analysis_with_github_validation"

        self._update_statistics(package_data, critical_high_details, all_cves_details)

    def _update_statistics(self, package_data: dict[str, Any],
                          critical_high_details: dict[str, Any],
                          all_cves_details: dict[str, Any]) -> None:
        """Update summary statistics with analysis results."""
        current_version = package_data.get("package_version", "")

        for approach, approach_name in [("High and critical cves", "critical_high_only"),
                                       ("All cves", "all_cves")]:
            details = (critical_high_details if approach_name == "critical_high_only"
                      else all_cves_details)

            self.statistics.update_github_validation_stats(details)
            self.statistics.update_approach_stats(details, approach_name, current_version)


class ReportGenerator:
    """Generates summary reports for vulnerability analysis results."""

    def generate_summary_report(self, summary: dict[str, Any],
                              output_file_prefix: str) -> None:
        """Generate and save a comprehensive summary report."""
        report = self._build_report_structure(summary)

        summary_file = f"{output_file_prefix}_summary.json"
        with open(summary_file, "w", encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        self._print_summary_report(summary, summary_file)

    def _build_report_structure(self, summary: dict[str, Any]) -> dict[str, Any]:
        """Build the report structure."""
        return {
            'analysis_summary': summary,
            'github_validation_summary': summary['github_validation_stats'],
            'recommendations': {
                'critical_high_only': self._extract_recommendation_stats(
                    summary['critical_high_only']),
                'all_cves': self._extract_recommendation_stats(summary['all_cves'])
            },
            'github_rejected_packages': summary.get('github_rejected_packages', [])
        }

    def _extract_recommendation_stats(self, approach_stats: dict[str, Any]) -> dict[str, Any]:
        """Extract recommendation statistics for an approach."""
        return {
            'packages_needing_updates': approach_stats['packages_with_recommendations'],
            'packages_already_fixed': approach_stats['packages_already_fixed'],
            'github_validated_recommendations': approach_stats['github_validated_recommendations'],
            'github_rejected_recommendations': approach_stats['github_rejected_recommendations'],
            'total_critical_vulns_fixable': approach_stats['severity_summary']['critical'],
            'total_high_vulns_fixable': approach_stats['severity_summary']['high'],
            'total_medium_vulns_fixable': approach_stats['severity_summary']['medium'],
            'total_low_vulns_fixable': approach_stats['severity_summary']['low'],
            'total_malware_cves_excluded': approach_stats['total_malware_cves_excluded'],
            'total_beta_cves_excluded': approach_stats['total_beta_cves_excluded']
        }

    def _print_summary_report(self, summary: dict[str, Any], summary_file: str) -> None:
        """Print summary report to console."""
        print("\n=== ANALYSIS SUMMARY ===")
        print(f"Total packages analyzed: {summary['total_packages']}")
        print(f"Packages with vulnerabilities: {summary['packages_with_vulnerabilities']}")
        print(f"Packages without vulnerabilities: {summary['packages_without_vulnerabilities']}")
        print(f"Malware packages excluded: {summary['malware_packages_excluded']}")

        self._print_github_validation_stats(summary['github_validation_stats'])
        self._print_github_rejections(summary.get('github_rejected_packages', []))
        self._print_approach_stats(summary['critical_high_only'], "CRITICAL/HIGH CVEs ONLY")
        self._print_approach_stats(summary['all_cves'], "ALL CVEs")

        print(f"\nSummary report saved to: {summary_file}")

    def _print_github_validation_stats(self, github_stats: dict[str, Any]) -> None:
        """Print GitHub validation statistics."""
        print("\n--- VERSION VALIDATION STATISTICS ---")
        print(f"Total validation attempts: {github_stats['total_validations_attempted']}")
        print(f"Versions found by validator: {github_stats['versions_found_in_github']}")
        print(f"Versions NOT found by validator: {github_stats['versions_not_found_in_github']}")
        print(f"Packages with validated recommendations: {github_stats['packages_with_validated_recommendations']}")
        print(f"Packages with rejected recommendations: {github_stats['packages_with_rejected_recommendations']}")

        if github_stats['total_validations_attempted'] > 0:
            success_rate = (github_stats['versions_found_in_github'] /
                           github_stats['total_validations_attempted']) * 100
            print(f"Version validation success rate: {success_rate:.1f}%")

    def _print_github_rejections(self, rejected_packages: list[dict]) -> None:
        """Print detailed information about rejected packages."""
        if not rejected_packages:
            return

        print("\n--- GITHUB VALIDATION REJECTIONS ---")
        print(f"Total packages with rejected recommendations: {len(rejected_packages)}")
        print("Detailed rejection information:")
        print("=" * 80)

        for i, pkg_info in enumerate(rejected_packages, 1):
            self._print_package_rejection_details(i, pkg_info)

    def _print_package_rejection_details(self, index: int, pkg_info: dict[str, Any]) -> None:
        """Print rejection details for a specific package."""
        pkg_name = pkg_info['package_name']
        current_version = pkg_info['current_version']

        print(f"\n{index}. {pkg_name} (current: {current_version})")
        print("-" * 60)

        self._print_approach_rejection(pkg_info['critical_high_approach'],
                                     "Critical/High CVEs approach")
        self._print_approach_rejection(pkg_info['all_cves_approach'],
                                     "All CVEs approach")

    def _print_approach_rejection(self, approach_info: dict[str, Any],
                                approach_name: str) -> None:
        """Print rejection information for a specific approach."""
        if approach_info['rejected']:
            print(f"   {approach_name}:")
            print(f"     Recommended: {approach_info['original_recommendation']}")
            print(f"     Reason: {approach_info['rejection_reason']}")
        elif approach_info['validation_attempted']:
            print(f"   {approach_name}:")
            print(f"     Validated: {approach_info['original_recommendation']}")
        else:
            print(f"   {approach_name}: No validation attempted")

    def _print_approach_stats(self, stats: dict[str, Any], title: str) -> None:
        """Print statistics for a specific approach."""
        print(f"\n--- {title} ---")
        print(f"Packages needing updates: {stats['packages_with_recommendations']}")
        print(f"GitHub validated recommendations: {stats['github_validated_recommendations']}")
        print(f"GitHub rejected recommendations: {stats['github_rejected_recommendations']}")
        print(f"Packages already fixed: {stats['packages_already_fixed']}")
        print(f"Packages without available fixes: {stats['packages_without_fixes']}")
        print(f"Total malware CVEs excluded: {stats['total_malware_cves_excluded']}")
        print(f"Total beta CVEs excluded: {stats['total_beta_cves_excluded']}")
        print("Vulnerabilities that can be fixed:")
        print(f"  Critical: {stats['severity_summary']['critical']}")
        print(f"  High: {stats['severity_summary']['high']}")

        if 'medium' in stats['severity_summary']:
            print(f"  Medium: {stats['severity_summary']['medium']}")
            print(f"  Low: {stats['severity_summary']['low']}")


class ExploitEnhancer:
    """Handles exploit enhancement functionality."""

    def enhance_sbom_if_available(self, input_file: str, output_file: str) -> str:
        """
        Enhance SBOM with exploit information if available.

        Returns:
            Path to the file that should be used for analysis
        """
        print("--- Step 1: Enhancing SBOM with Exploit Information ---")

        # Create an instance of ExploitResolver
        exploit_resolver = ExploitResolver()
        exploit_run_success = exploit_resolver.enhance_sbom_file_with_exploits(
            input_file, output_file)

        if not exploit_run_success:
            print("Exploit enhancement failed. Using original file instead.")
            return input_file
        else:
            print(f"Exploit enhancement successful. Enhanced data saved to '{output_file}'")
            return output_file

    def transform_data_for_compatibility(self, data: list[dict[str, Any]],
                                       enhanced_file_used: bool) -> list[dict[str, Any]]:
        """Transform data to ensure key compatibility between modules."""
        if not enhanced_file_used:
            return data

        print("Transforming data to ensure key compatibility...")
        for package in data:
            if 'vulnerabilities' in package and 'vulnerabilties' not in package:
                package['vulnerabilties'] = package['vulnerabilities']
        print("Data transformation complete.")

        return data


class VulnerabilityAnalysisTool:
    """Main tool class for vulnerability analysis operations."""

    def __init__(self):
        self.engine = VulnerabilityAnalysisEngine()
        self.report_generator = ReportGenerator()
        self.enhancer = ExploitEnhancer()

    def run_analysis(self, original_input_file: str, exploit_enhanced_file: str,
                    final_output_file: str, output_prefix: str) -> None:
        """Run the complete vulnerability analysis process."""
        input_file_to_use = self.enhancer.enhance_sbom_if_available(
            original_input_file, exploit_enhanced_file)

        print("-" * 50)
        print(f"--- Step 2: Finding Optimal Versions using '{input_file_to_use}' ---")

        self._check_github_token()

        data = self._load_input_data(input_file_to_use)
        enhanced_file_used = input_file_to_use == exploit_enhanced_file

        data = self.enhancer.transform_data_for_compatibility(data, enhanced_file_used)

        if enhanced_file_used:
            with open(input_file_to_use, "w", encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

        self._print_initial_stats(data, input_file_to_use)

        results, summary = self.engine.analyze_all_packages(data)

        self._save_results(results, final_output_file)
        self.report_generator.generate_summary_report(summary, output_prefix)

        self._print_sample_results(results)
        self._print_file_usage_summary(input_file_to_use, enhanced_file_used,
                                     final_output_file)

    def _check_github_token(self) -> None:
        """Check for GitHub token availability."""
        github_token = os.getenv('GITHUB_TOKEN') or os.getenv('GITHUB_PAT')
        if github_token:
            print("GitHub Personal Access Token found")
        else:
            print("No GitHub PAT found - limited to 60 requests/hour")
            print("Set GITHUB_TOKEN or GITHUB_PAT environment variable for higher rate limits")

    def _load_input_data(self, input_file: str) -> list[dict[str, Any]]:
        """Load input data from JSON file."""
        with open(input_file, encoding='utf-8') as f:
            data = json.load(f)
        return data

    def _print_initial_stats(self, data: list[dict[str, Any]], input_file: str) -> None:
        """Print initial statistics about the loaded data."""
        print(f"Initial data loaded: {len(data)} packages from {input_file}")
        print(f"Processing {len(data)} packages...")
        print("Beta version filtering enabled")
        print("Enhanced version comparison enabled")
        print("Vulnerability analysis with GitHub validation enabled")

    def _save_results(self, results: list[dict[str, Any]], output_file: str) -> None:
        """Save analysis results to output file."""
        with open(output_file, "w", encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\nFull analysis results saved to: {output_file}")

    def _print_sample_results(self, results: list[dict[str, Any]]) -> None:
        """Print sample results for review."""
        print("\nSAMPLE RESULTS:")
        print("=" * 60)

        packages_with_recommendations = self._filter_packages_with_recommendations(results)

        print(f"Packages with validated recommendations: "
              f"{len(packages_with_recommendations)}")

        sample_size = min(5, len(packages_with_recommendations))
        for i, pkg in enumerate(packages_with_recommendations[:sample_size], 1):
            self._print_package_sample(i, pkg)

        if len(packages_with_recommendations) > sample_size:
            remaining = len(packages_with_recommendations) - sample_size
            print(f"\n... and {remaining} more packages with validated recommendations")

        print("\nAnalysis complete! Check the output files for full details.")

    def _filter_packages_with_recommendations(self,
                                            results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Filter packages that have validated recommendations."""
        packages_with_final_recommendations = []

        for pkg in results:
            first_optimal = pkg.get('first_optimal_version', {})
            current_version = pkg.get('package_version', '')

            for approach in ["High and critical cves", "All cves"]:
                if self._has_valid_recommendation(first_optimal, approach, current_version):
                    packages_with_final_recommendations.append(pkg)
                    break

        return packages_with_final_recommendations

    def _has_valid_recommendation(self, first_optimal: dict[str, Any],
                                approach: str, current_version: str) -> bool:
        """Check if an approach has a valid recommendation."""
        if approach not in first_optimal:
            return False

        rec_version = first_optimal[approach].get('recommended_version')
        return rec_version and rec_version != current_version

    def _print_package_sample(self, index: int, pkg: dict[str, Any]) -> None:
        """Print sample information for a package."""
        pkg_name = pkg.get('package_name', 'unknown')
        current_version = pkg.get('package_version', '')

        print(f"\n{index}. {pkg_name} ({current_version})")
        print("-" * 40)

        first_optimal = pkg.get('first_optimal_version', {})

        for approach_key, display_name in [("High and critical cves", "Critical/High"),
                                          ("All cves", "All CVEs")]:
            if approach_key in first_optimal:
                self._print_approach_recommendation(first_optimal[approach_key], display_name)

    def _print_approach_recommendation(self, approach_data: dict[str, Any],
                                     display_name: str) -> None:
        """Print recommendation information for a specific approach."""
        rec_version = approach_data.get('recommended_version')
        details = approach_data.get('recommendation_details', {})
        github_validation = details.get('github_validation', {})

        print(f"   {display_name} -> {rec_version}")

        if github_validation.get('validation_attempted'):
            provider = github_validation.get('validation_provider', 'github')
            if github_validation.get('version_exists_on_github'):
                print(f"     {provider} validated")
            else:
                rejection_reason = github_validation.get('rejection_reason', 'Unknown')
                print(f"     {provider} rejected: {rejection_reason}")
        else:
            print("     No GitHub validation attempted")

    def _print_file_usage_summary(self, input_file: str, enhanced_file_used: bool,
                                 output_file: str) -> None:
        """Print file usage summary."""
        print("\nFILE USAGE SUMMARY:")
        print(f"  Input file used: {input_file}")
        if enhanced_file_used:
            print("  Exploit enhancement was applied")
        else:
            print("  Exploit enhancement was not applied")
        print(f"  Output file: {output_file}")


def main() -> None:
    """Main execution function for the vulnerability analysis tool."""
    original_input_file = "test.json"
    exploit_enhanced_file = "test_with_exploits.json"
    final_output_file = "first_optimal_test.json"
    output_prefix = "vulnerability_analysis_results"

    tool = VulnerabilityAnalysisTool()
    tool.run_analysis(original_input_file, exploit_enhanced_file,
                     final_output_file, output_prefix)


if __name__ == "__main__":
    main()
