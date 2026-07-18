"""Target-specific CycloneDX SBOM tests."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from mcpradar.output.sbom import generate_sbom


def test_sbom_describes_target_not_scanner_environment(tmp_path: Path) -> None:
    integrity = base64.b64encode(hashlib.sha512(b"axios artifact").digest()).decode()
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "demo-mcp",
                "version": "1.2.3",
                "license": "MIT",
                "dependencies": {"axios": "0.21.4"},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "": {"dependencies": {"axios": "0.21.4"}},
                    "node_modules/axios": {
                        "version": "0.21.4",
                        "integrity": f"sha512-{integrity}",
                        "license": "MIT",
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    sbom = generate_sbom(tmp_path)
    assert sbom["specVersion"] == "1.7"
    assert sbom["metadata"]["component"]["name"] == "demo-mcp"
    assert [component["name"] for component in sbom["components"]] == ["axios"]
    assert sbom["components"][0]["hashes"][0]["alg"] == "SHA-512"
    assert sbom["dependencies"][0]["dependsOn"] == ["pkg:npm/axios@0.21.4"]


def test_sbom_serial_is_deterministic_for_same_inventory(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("httpx==0.28.1\n", encoding="utf-8")
    first = generate_sbom(tmp_path)
    second = generate_sbom(tmp_path)
    assert first["serialNumber"] == second["serialNumber"]


def test_fetch_provenance_is_attached_to_metadata(tmp_path: Path) -> None:
    (tmp_path / ".mcpradar-provenance.json").write_text(
        json.dumps({"kind": "npm", "digest": "sha512:abc"}), encoding="utf-8"
    )
    properties = generate_sbom(tmp_path)["metadata"]["properties"]
    assert {item["name"] for item in properties} >= {
        "mcpradar:provenance:kind",
        "mcpradar:provenance:digest",
    }
