import json
import os
from typing import Any

from llmbom.core.schema import NodeType


def generate_sbom_from_graph(graph_dict: dict[str, Any], tool_name: str = "LLMBOM") -> dict[str, Any]:
    """Generate a simple SBOM dictionary from an LLMBOM graph output."""
    if graph_dict is None:
        return {"components": []}

    if isinstance(graph_dict, dict) and "graph" in graph_dict:
        graph_dict = graph_dict["graph"]

    nodes = graph_dict.get("nodes", []) if isinstance(graph_dict, dict) else []
    components = []

    for node in nodes:
        if node.get("type") != NodeType.LIBRARY:
            continue

        metadata = node.get("metadata", {}) or {}
        component = {
            "type": "library",
            "name": node.get("name", ""),
            "version": metadata.get("version", ""),
            "publisher": metadata.get("vendor") or metadata.get("publisher", ""),
            "purl": metadata.get("purl", ""),
            "file": metadata.get("file", ""),
            "vulnerabilities": metadata.get("vulnerabilities", []) or metadata.get("vulnerabilties", []),
        }
        components.append(component)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "tools": [
                {
                    "vendor": "LLMBOM",
                    "name": tool_name,
                    "version": "1.0"
                }
            ]
        },
        "components": components,
    }
    return bom


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _first_present(data: dict[str, Any], keys: tuple[str, ...], default: Any = "") -> Any:
    for key in keys:
        value = data.get(key)
        if value is not None:
            return value
    return default


def _flatten_component_buckets(sbom_data: Any) -> list[dict[str, Any]]:
    """Return package-like dicts from CycloneDX, LLMBOM, or Gauntlet bucket JSON."""
    if isinstance(sbom_data, dict):
        if "components" in sbom_data and isinstance(sbom_data["components"], list):
            return [c for c in sbom_data["components"] if isinstance(c, dict)]

        if "nodes" in sbom_data and isinstance(sbom_data["nodes"], list):
            return [
                {
                    "name": node.get("name"),
                    "version": node.get("metadata", {}).get("version", ""),
                    "type": node.get("type"),
                    **(node.get("metadata", {}) or {}),
                }
                for node in sbom_data["nodes"]
                if node.get("type") == NodeType.LIBRARY
            ]

        packages = []
        for key, value in sbom_data.items():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        component = dict(item)
                        component.setdefault("source_category", key)
                        packages.append(component)
        return packages or [sbom_data]

    if isinstance(sbom_data, list):
        packages = []
        for item in sbom_data:
            if isinstance(item, dict):
                packages.extend(_flatten_component_buckets(item))
        return packages

    raise ValueError("Unsupported SBOM format for CVE normalization")


def normalize_sbom_for_cve(sbom_data: Any) -> list[dict[str, Any]]:
    """Normalize SBOM data into a CVE-compatible package list."""
    if sbom_data is None:
        return []

    if isinstance(sbom_data, str):
        with open(sbom_data, encoding="utf-8") as f:
            sbom_data = json.load(f)

    packages = _flatten_component_buckets(sbom_data)

    normalized = []
    for component in packages:
        package_name = _first_present(component, ("package_name", "name", "package"))
        package_version = _first_present(component, ("package_version", "version", "pkg_version", "resolved_version"))
        vulnerabilities = _as_list(component.get("vulnerabilities") or component.get("vulnerabilties"))

        if not package_name:
            continue

        normalized.append({
            "package_name": package_name,
            "package_version": str(package_version or ""),
            "vendor": component.get("vendor") or component.get("publisher", ""),
            "purl": component.get("purl", ""),
            "type": component.get("type", "library"),
            "repo_name": component.get("repo_name", ""),
            "project_type": (
                component.get("project_type", "")
                or component.get("source_category", "")
                or component.get("source_sbom", "")
            ),
            "file": component.get("file", ""),
            "source_sbom": component.get("source_sbom", component.get("source_category", "")),
            "vulnerabilities": vulnerabilities,
            "vulnerabilties": vulnerabilities,
        })

    return normalized


def save_json(data: Any, file_path: str) -> None:
    """Save JSON data to a file."""
    os.makedirs(os.path.dirname(file_path) or ".", exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
