"""Generate data.json for the leaderboard from validation results.

Usage: python docs/leaderboard/generate.py
Reads: validation/results/*.json
Writes: docs/leaderboard/data.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow importing from src/ when run from repo root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

RESULTS_DIR = Path("validation/results")
OUTPUT = Path("docs/leaderboard/data.json")


def _fallback_entries() -> list[dict]:
    """Generate placeholder entries from known MCP servers.

    When no validation results exist, this ensures the leaderboard
    shows all tracked servers with 'pending' status instead of
    appearing empty.
    """
    from mcpradar.registry.scanner import KNOWN_MPC_SERVERS

    rows: list[dict] = []
    for name, _runner, _cmd in KNOWN_MPC_SERVERS:
        rows.append(
            {
                "server": name,
                "tools": 0,
                "findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "last_scanned": "—",
                "status": "pending",
            }
        )
    return rows


def main() -> None:
    rows: list[dict] = []

    if RESULTS_DIR.exists():
        for fpath in sorted(RESULTS_DIR.glob("*.json")):
            try:
                data = json.loads(fpath.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue

            sev = data.get("findings_by_severity", {})
            rows.append(
                {
                    "server": data.get("name", fpath.stem),
                    "tools": data.get("tools", 0),
                    "findings": data.get("findings", 0),
                    "critical": sev.get("critical", 0),
                    "high": sev.get("high", 0),
                    "medium": sev.get("medium", 0),
                    "low": sev.get("low", 0),
                    "last_scanned": data.get("scanned_at", "")[:10]
                    if data.get("scanned_at")
                    else "—",
                    "status": data.get("status", "unknown"),
                }
            )

    # Fallback: bilinen sunuculari placeholder olarak goster
    if not rows:
        rows = _fallback_entries()

    rows.sort(key=lambda r: r["findings"], reverse=True)
    OUTPUT.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Generated {OUTPUT} with {len(rows)} entries")


if __name__ == "__main__":
    main()
