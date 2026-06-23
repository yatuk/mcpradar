"""Generate data.json for the leaderboard from validation results.

Usage: python docs/leaderboard/generate.py
Reads: validation/results/*.json
Writes: docs/leaderboard/data.json
"""

from __future__ import annotations

import json
from pathlib import Path

RESULTS_DIR = Path("validation/results")
OUTPUT = Path("docs/leaderboard/data.json")


def main() -> None:
    rows: list[dict] = []

    if not RESULTS_DIR.exists():
        OUTPUT.write_text("[]", encoding="utf-8")
        return

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
                "last_scanned": data.get("scanned_at", "")[:10] if data.get("scanned_at") else "—",
                "status": data.get("status", "unknown"),
            }
        )

    rows.sort(key=lambda r: r["findings"], reverse=True)
    OUTPUT.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Generated {OUTPUT} with {len(rows)} entries")


if __name__ == "__main__":
    main()
