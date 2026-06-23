"""CycloneDX 1.5 SBOM generator — zero external dependencies."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any


def generate_sbom() -> dict[str, Any]:
    """Generate a CycloneDX 1.5 SBOM in JSON format.

    Enumerates all installed packages via importlib.metadata and
    produces a standards-compliant SBOM document.
    """
    from importlib.metadata import distributions, version

    packages: list[dict[str, Any]] = []
    for dist in distributions():
        try:
            name = dist.metadata["Name"]
            pkg_version = dist.metadata["Version"]
        except KeyError:
            continue

        packages.append(
            {
                "type": "library",
                "name": name,
                "version": pkg_version,
                "purl": f"pkg:pypi/{name}@{pkg_version}",
            }
        )

    # Sort alphabetically by name for deterministic output
    packages.sort(key=lambda p: p["name"].lower())

    mcpradar_version = version("mcpradar")

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{_make_uuid()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "component": {
                "type": "application",
                "name": "mcpradar",
                "version": mcpradar_version,
                "purl": f"pkg:pypi/mcpradar@{mcpradar_version}",
            },
        },
        "components": packages,
    }


def _make_uuid() -> str:
    """Generate a random UUID v4 string without uuid module dependency."""
    import random
    import string

    hex_chars = string.hexdigits.lower()[:16]
    uuid_str = "".join(random.choices(hex_chars, k=32))
    return f"{uuid_str[:8]}-{uuid_str[8:12]}-4{uuid_str[13:16]}-{uuid_str[16:20]}-{uuid_str[20:]}"


def export_sbom(path: str | None = None) -> str:
    """Generate SBOM and optionally write to a file.

    Args:
        path: File path to write. If None, only returns the JSON string.

    Returns:
        The SBOM as a formatted JSON string.
    """
    sbom = generate_sbom()
    json_str = json.dumps(sbom, indent=2, ensure_ascii=False)
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(json_str)
    return json_str
