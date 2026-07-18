"""Target-specific CycloneDX 1.7 SBOM generation."""

from __future__ import annotations

import base64
import binascii
import json
import re
import tomllib
import urllib.parse
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcpradar.supply.deps import Dependency, extract_dependencies


def generate_sbom(target: str | Path = ".") -> dict[str, Any]:
    """Generate a CycloneDX 1.7 BOM for the scanned source target."""
    root = Path(target).resolve()
    identity = _target_identity(root)
    dependencies = extract_dependencies(root)
    components = [_component(dependency) for dependency in dependencies]
    components.sort(key=lambda item: (str(item["name"]).lower(), str(item["version"])))

    root_ref = str(identity["bom-ref"])
    ref_by_name = {
        dependency.name.lower(): str(_component(dependency)["bom-ref"])
        for dependency in dependencies
    }
    direct_names = _direct_dependency_names(root)
    relationships: list[dict[str, object]] = [
        {
            "ref": root_ref,
            "dependsOn": sorted(
                ref_by_name[dependency.name.lower()]
                for dependency in dependencies
                if dependency.direct or dependency.name.lower() in direct_names
            ),
        }
    ]
    component_by_ref = {str(component["bom-ref"]): component for component in components}
    for dependency in dependencies:
        reference = ref_by_name.get(dependency.name.lower())
        if reference is None or reference not in component_by_ref:
            continue
        relationships.append(
            {
                "ref": reference,
                "dependsOn": sorted(
                    ref_by_name[name.lower()]
                    for name in dependency.dependencies
                    if name.lower() in ref_by_name
                ),
            }
        )

    provenance = _read_provenance(root)
    serial_seed = json.dumps(
        {
            "root": root_ref,
            "components": [component["bom-ref"] for component in components],
            "provenance": provenance,
        },
        sort_keys=True,
    )
    metadata: dict[str, Any] = {
        "timestamp": datetime.now(UTC).isoformat(),
        "component": identity,
        "tools": {
            "components": [
                {
                    "type": "application",
                    "name": "mcpradar",
                    "version": _mcpradar_version(),
                }
            ]
        },
    }
    if provenance:
        metadata["properties"] = [
            {"name": f"mcpradar:provenance:{key}", "value": str(value)}
            for key, value in sorted(provenance.items())
        ]

    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, serial_seed)}",
        "version": 1,
        "metadata": metadata,
        "components": components,
        "dependencies": relationships,
    }


def _component(dependency: Dependency) -> dict[str, Any]:
    ecosystem = "npm" if dependency.ecosystem == "npm" else "pypi"
    quoted_name = urllib.parse.quote(dependency.name, safe="@/")
    purl = f"pkg:{ecosystem}/{quoted_name}@{dependency.version}"
    component: dict[str, Any] = {
        "type": "library",
        "bom-ref": purl,
        "name": dependency.name,
        "version": dependency.version,
        "purl": purl,
        "properties": [
            {
                "name": "mcpradar:dependency:scope",
                "value": "direct" if dependency.direct else "transitive",
            },
            {"name": "mcpradar:dependency:source", "value": dependency.source},
        ],
    }
    parsed_hash = _parse_integrity(dependency.integrity)
    if parsed_hash:
        algorithm, content = parsed_hash
        component["hashes"] = [{"alg": algorithm, "content": content}]
    if dependency.license:
        component["licenses"] = [{"license": {"name": dependency.license}}]
    return component


def _target_identity(root: Path) -> dict[str, Any]:
    name = root.name or "mcp-server"
    version = "unknown"
    ecosystem = "generic"
    license_name = ""
    package_json = root / "package.json"
    pyproject = root / "pyproject.toml"
    try:
        package = json.loads(package_json.read_text(encoding="utf-8"))
        name = str(package.get("name") or name)
        version = str(package.get("version") or version)
        license_name = str(package.get("license") or "")
        ecosystem = "npm"
    except (OSError, json.JSONDecodeError):
        try:
            project = tomllib.loads(pyproject.read_text(encoding="utf-8")).get("project", {})
            name = str(project.get("name") or name)
            version = str(project.get("version") or version)
            license_value = project.get("license", "")
            license_name = (
                str(license_value.get("text", ""))
                if isinstance(license_value, dict)
                else str(license_value)
            )
            ecosystem = "pypi"
        except (OSError, tomllib.TOMLDecodeError):
            pass
    quoted_name = urllib.parse.quote(name, safe="@/")
    purl = f"pkg:{ecosystem}/{quoted_name}@{version}"
    component: dict[str, Any] = {
        "type": "application",
        "bom-ref": purl,
        "name": name,
        "version": version,
        "purl": purl,
    }
    if license_name:
        component["licenses"] = [{"license": {"name": license_name}}]
    return component


def _direct_dependency_names(root: Path) -> set[str]:
    names: set[str] = set()
    try:
        package = json.loads((root / "package.json").read_text(encoding="utf-8"))
        for key in ("dependencies", "optionalDependencies"):
            values = package.get(key, {})
            if isinstance(values, dict):
                names.update(str(name).lower() for name in values)
    except (OSError, json.JSONDecodeError):
        pass
    try:
        project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        for requirement in project.get("project", {}).get("dependencies", []) or []:
            if isinstance(requirement, str):
                match = re.match(r"[A-Za-z0-9._-]+", requirement)
                if match:
                    names.add(match.group(0).lower())
    except (OSError, tomllib.TOMLDecodeError):
        pass
    return names


def _parse_integrity(value: str) -> tuple[str, str] | None:
    if not value:
        return None
    normalized = value.replace(":", "-", 1) if ":" in value and "-" not in value else value
    try:
        algorithm, digest = normalized.split("-", 1)
    except (ValueError, binascii.Error):
        return None
    algorithm_name = algorithm.upper().replace("SHA", "SHA-")
    if algorithm_name not in {"SHA-1", "SHA-256", "SHA-384", "SHA-512"}:
        return None
    if all(character in "0123456789abcdefABCDEF" for character in digest):
        return algorithm_name, digest.lower()
    try:
        return algorithm_name, base64.b64decode(digest + "===").hex()
    except ValueError:
        return None


def _read_provenance(root: Path) -> dict[str, object]:
    candidates = (root / ".mcpradar-provenance.json", root.parent / ".mcpradar-provenance.json")
    for candidate in candidates:
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict):
            return payload
    return {}


def _mcpradar_version() -> str:
    from mcpradar import __version__

    return __version__


def export_sbom(target: str | Path = ".", path: str | None = None) -> str:
    """Generate a target SBOM and optionally write it to a file."""
    document = generate_sbom(target)
    json_text = json.dumps(document, indent=2, ensure_ascii=False)
    if path:
        Path(path).write_text(json_text, encoding="utf-8")
    return json_text
