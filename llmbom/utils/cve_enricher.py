import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from typing import Any


OSV_API_URL = "https://api.osv.dev/v1/query"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_TIMEOUT_SECONDS = 20
REQUEST_DELAY_SECONDS = 0.15

OSV_ECOSYSTEMS = {
    "npm": "npm",
    "javascript": "npm",
    "node": "npm",
    "nodejs": "npm",
    "pypi": "PyPI",
    "python": "PyPI",
    "maven": "Maven",
    "nuget": "NuGet",
    "cargo": "crates.io",
    "rust": "crates.io",
    "gem": "RubyGems",
    "rubygems": "RubyGems",
    "composer": "Packagist",
    "php": "Packagist",
    "golang": "Go",
    "go": "Go",
    "debian": "Debian",
    "ubuntu": "Ubuntu",
}


def _load_json(path: str) -> Any:
    with open(path, encoding="utf-8-sig") as f:
        return json.load(f)


def _save_json(data: Any, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _request_json(url: str, method: str = "GET", payload: dict[str, Any] | None = None) -> dict[str, Any]:
    data = None
    headers = {"Accept": "application/json", "User-Agent": "LLMBOM-CVE-Enricher/1.0"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=DEFAULT_TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8"))


def _clean_version(version: Any) -> str:
    if version is None:
        return ""

    version_str = str(version).strip()
    if not version_str or version_str.lower() in {"unknown", "none", "n/a"}:
        return ""

    # OSV needs a concrete version. For ranges, use the boundary version as the
    # best static approximation while preserving the original version elsewhere.
    version_str = re.sub(r"^[<>=~^!]+", "", version_str).strip()
    return version_str


def _severity_from_score(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _score_from_osv(vuln: dict[str, Any]) -> tuple[float | None, str]:
    severities = vuln.get("severity") or []
    for severity in severities:
        score = severity.get("score")
        if not score:
            continue
        match = re.search(r"(\d+(?:\.\d+)?)", str(score))
        if match:
            parsed = float(match.group(1))
            return parsed, _severity_from_score(parsed)

    database_specific = vuln.get("database_specific") or {}
    severity = str(database_specific.get("severity", "unknown")).lower()
    return None, severity


def _fixed_version_from_osv(vuln: dict[str, Any], package_name: str) -> str:
    fixed_versions = []
    for affected in vuln.get("affected") or []:
        package = affected.get("package") or {}
        affected_name = package.get("name")
        if affected_name and affected_name.lower() != package_name.lower():
            continue
        for affected_range in affected.get("ranges") or []:
            for event in affected_range.get("events") or []:
                fixed = event.get("fixed")
                if fixed:
                    fixed_versions.append(str(fixed))
        for version in affected.get("versions") or []:
            # Some records only list affected versions. Do not treat these as fixes.
            _ = version

    return sorted(set(fixed_versions))[-1] if fixed_versions else ""


def _normalize_osv_vulnerability(vuln: dict[str, Any], package_name: str) -> dict[str, Any]:
    score, severity = _score_from_osv(vuln)
    references = [
        {"url": ref.get("url"), "type": ref.get("type", "")}
        for ref in (vuln.get("references") or [])
        if ref.get("url")
    ]

    aliases = vuln.get("aliases") or []
    cve_id = next((alias for alias in aliases if str(alias).startswith("CVE-")), vuln.get("id", ""))

    return {
        "cve_id": cve_id,
        "source_id": vuln.get("id", ""),
        "severity": severity,
        "score": score or 0,
        "summary": vuln.get("summary", ""),
        "description": vuln.get("details", ""),
        "fixed_location": _fixed_version_from_osv(vuln, package_name),
        "references": references,
        "source": {"name": "OSV", "url": "https://osv.dev/"},
    }


def _score_from_nvd(cve: dict[str, Any]) -> tuple[float | None, str]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key) or []
        if not metric_list:
            continue
        metric = metric_list[0].get("cvssData") or {}
        score = metric.get("baseScore")
        severity = metric.get("baseSeverity") or metric_list[0].get("baseSeverity")
        if score is not None:
            return float(score), str(severity or _severity_from_score(float(score))).lower()
    return None, "unknown"


def _normalize_nvd_vulnerability(item: dict[str, Any]) -> dict[str, Any]:
    cve = item.get("cve") or {}
    score, severity = _score_from_nvd(cve)
    descriptions = cve.get("descriptions") or []
    description = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
    references = [
        {"url": ref.get("url"), "type": ",".join(ref.get("tags") or [])}
        for ref in (cve.get("references", {}).get("referenceData") or cve.get("references") or [])
        if isinstance(ref, dict) and ref.get("url")
    ]

    return {
        "cve_id": cve.get("id", ""),
        "severity": severity,
        "score": score or 0,
        "summary": description[:240],
        "description": description,
        "fixed_location": "",
        "references": references,
        "source": {"name": "NVD", "url": "https://nvd.nist.gov/"},
    }


class CveEnricher:
    def __init__(self, max_nvd_queries: int = 250):
        self.max_nvd_queries = max_nvd_queries
        self.cache: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
        self.stats = Counter()

    def enrich_file(self, input_file: str, output_file: str) -> dict[str, Any]:
        packages = _load_json(input_file)
        if not isinstance(packages, list):
            raise ValueError("CVE enrichment input must be a package list")

        enriched = [self.enrich_package(dict(package)) for package in packages]
        _save_json(enriched, output_file)
        stats = dict(self.stats)
        stats["total_packages"] = len(enriched)
        stats["packages_with_vulnerabilities"] = sum(
            1 for package in enriched
            if package.get("vulnerabilties") or package.get("vulnerabilities")
        )
        return stats

    def enrich_package(self, package: dict[str, Any]) -> dict[str, Any]:
        package_name = str(package.get("package_name") or "").strip()
        raw_version = package.get("package_version")
        version = _clean_version(raw_version)
        ecosystem = self._detect_osv_ecosystem(package)

        package.setdefault("vulnerabilities", [])
        package.setdefault("vulnerabilties", [])

        if package.get("vulnerabilities") or package.get("vulnerabilties"):
            self.stats["already_had_vulnerabilities"] += 1
            return package

        if not package_name:
            self._mark_lookup(package, "skipped", "missing package name")
            self.stats["skipped_missing_name"] += 1
            return package

        if not version:
            self._mark_lookup(package, "skipped", "missing concrete version")
            self.stats["skipped_missing_version"] += 1
            return package

        vulnerabilities = []
        if ecosystem:
            vulnerabilities = self._query_osv(package_name, version, ecosystem)

        if not vulnerabilities and self.stats["nvd_queries"] < self.max_nvd_queries:
            vulnerabilities = self._query_nvd(package_name, version)

        vulnerabilities = self._deduplicate_vulnerabilities(vulnerabilities)
        package["vulnerabilities"] = vulnerabilities
        package["vulnerabilties"] = vulnerabilities

        status = "found" if vulnerabilities else "not_found"
        self._mark_lookup(package, status, "", ecosystem)
        if vulnerabilities:
            self.stats["packages_enriched"] += 1
        else:
            self.stats["packages_without_findings"] += 1

        return package

    def _detect_osv_ecosystem(self, package: dict[str, Any]) -> str:
        purl = str(package.get("purl") or package.get("purl_prefix") or "").lower()
        if purl.startswith("pkg:"):
            purl_type = purl[4:].split("/", 1)[0]
            return OSV_ECOSYSTEMS.get(purl_type, "")

        candidates = [
            package.get("project_type"),
            package.get("source_category"),
            package.get("source_sbom"),
            package.get("type"),
            package.get("vendor"),
        ]
        joined = " ".join(str(c or "").lower() for c in candidates)
        for marker, ecosystem in OSV_ECOSYSTEMS.items():
            if marker in joined:
                return ecosystem

        return ""

    def _query_osv(self, package_name: str, version: str, ecosystem: str) -> list[dict[str, Any]]:
        key = ("osv", ecosystem, f"{package_name}@{version}")
        if key in self.cache:
            return self.cache[key]

        payload = {"version": version, "package": {"name": package_name, "ecosystem": ecosystem}}
        try:
            self.stats["osv_queries"] += 1
            response = _request_json(OSV_API_URL, method="POST", payload=payload)
            vulnerabilities = [
                _normalize_osv_vulnerability(vuln, package_name)
                for vuln in response.get("vulns", [])
            ]
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            self.stats["osv_errors"] += 1
            vulnerabilities = []

        self.cache[key] = vulnerabilities
        time.sleep(REQUEST_DELAY_SECONDS)
        return vulnerabilities

    def _query_nvd(self, package_name: str, version: str) -> list[dict[str, Any]]:
        key = ("nvd", "keyword", f"{package_name}@{version}")
        if key in self.cache:
            return self.cache[key]

        query = f"{package_name} {version}"
        params = urllib.parse.urlencode({"keywordSearch": query})
        url = f"{NVD_API_URL}?{params}"
        try:
            self.stats["nvd_queries"] += 1
            response = _request_json(url)
            vulnerabilities = [
                _normalize_nvd_vulnerability(item)
                for item in response.get("vulnerabilities", [])
            ]
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            self.stats["nvd_errors"] += 1
            vulnerabilities = []

        self.cache[key] = vulnerabilities
        time.sleep(REQUEST_DELAY_SECONDS)
        return vulnerabilities

    def _deduplicate_vulnerabilities(self, vulnerabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_id = {}
        for vulnerability in vulnerabilities:
            cve_id = vulnerability.get("cve_id") or vulnerability.get("source_id")
            if not cve_id:
                continue
            by_id.setdefault(cve_id, vulnerability)
        return sorted(by_id.values(), key=lambda item: item.get("cve_id", ""))

    def _mark_lookup(
        self,
        package: dict[str, Any],
        status: str,
        reason: str = "",
        ecosystem: str = "",
    ) -> None:
        package["cve_lookup"] = {
            "status": status,
            "reason": reason,
            "ecosystem": ecosystem,
            "sources": ["OSV", "NVD"],
        }


def enrich_cve_input(input_file: str, output_file: str, stats_file: str | None = None) -> dict[str, Any]:
    enricher = CveEnricher()
    stats = enricher.enrich_file(input_file, output_file)
    if stats_file:
        _save_json(stats, stats_file)
    return stats
