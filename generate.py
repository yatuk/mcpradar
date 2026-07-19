"""Regenerate public leaderboard artifacts from validation results.

This remains as a convenient docs entrypoint; all scoring, deduplication, and
badge behavior lives in :mod:`mcpradar.leaderboard`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_SCRIPT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_SCRIPT_ROOT / "src"))

from mcpradar import __version__  # noqa: E402
from mcpradar.leaderboard import generate_leaderboard  # noqa: E402

_RESULTS = _SCRIPT_ROOT / "validation/results"
_OUTPUTS = (
    _SCRIPT_ROOT / "docs/data.json",
    _SCRIPT_ROOT / "docs/leaderboard/data.json",
)


def _registry_entry(row: dict[str, Any]) -> dict[str, Any]:
    server_name = (
        row["server"]
        .replace("@modelcontextprotocol/", "io.modelcontextprotocol/")
        .replace("@anthropic/", "io.anthropic/")
        .replace("@playwright/", "com.microsoft.playwright/")
        .replace("@", "io.github.")
    )
    return {
        "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
        "name": server_name,
        "version": row.get("version") or "unknown",
        "_meta": {
            "com.github.yatuk.mcpradar/security": {
                "risk_score": row.get("risk_score"),
                "scoring_model": row["scoring_model"],
                "grade": row["grade"],
                "confidence": row.get("confidence"),
                "findings": row["findings"],
                "by_severity": row["by_severity"],
                "last_scanned": row["last_scanned"],
                "scanner_version": row["scanner_version"],
                "scan_coverage": row.get("scan_coverage"),
                "tool_hash": row["tool_hash"],
                "status": row["status"],
            }
        },
    }


def main() -> None:
    summaries = [
        generate_leaderboard(_RESULTS, output, scanner_version=__version__) for output in _OUTPUTS
    ]
    rows = summaries[-1].rows
    registry = [_registry_entry(row) for row in rows]
    payload = json.dumps(registry, indent=2, ensure_ascii=False)
    for output in (
        _SCRIPT_ROOT / "docs/servers.json",
        _SCRIPT_ROOT / "docs/leaderboard/servers.json",
    ):
        output.write_text(payload, encoding="utf-8")
    print(
        f"Generated {len(rows)} leaderboard rows, {len(registry)} registry entries, "
        f"and {summaries[-1].badge_count} badges"
    )


if __name__ == "__main__":
    main()
