"""Scan the day's most popular MCP servers and fold them into the leaderboard.

Ranks the registry by combined popularity (npm + PyPI + GitHub — see
``mcpradar.registry.popularity``), then for each top-N server:

  1. Runs a live scan (``mcpradar scan`` in a subprocess, best-effort). Many
     popular servers need API keys or arguments and won't fully enumerate — a
     partial scan is fine.
  2. Always enriches from the published package (fetch → dependency CVEs +
     source rules), so even a server that could not be launched still gets a
     dependency/source-based grade rather than an empty "pending" row.

The result JSON is written to ``validation/results/`` in the same shape the
leaderboard reader expects, so ``leaderboard generate`` picks the trending
servers up alongside the curated corpus.

Usage:
    python validation/run_trending.py [--top 10] [--timeout 120]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

VALIDATION_DIR = Path(__file__).parent
RESULTS_DIR = VALIDATION_DIR / "results"


def _slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("_")


def _scan_command_for(registry_type: str, identifier: str) -> str | None:
    rtype = (registry_type or "").lower()
    if rtype == "npm":
        return f"npx -y {identifier}"
    if rtype in ("pypi", "pip"):
        return f"uvx {identifier}"
    return None


def _live_scan(cmd: str, timeout: int) -> dict | None:
    """Run ``mcpradar scan`` and return the parsed to_dict, or None on failure."""
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "mcpradar", "scan", cmd, "-t", "stdio", "--json", "-s", "low"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            cwd=str(VALIDATION_DIR.parent),
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    raw = (proc.stdout or "").strip()
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan the day's most popular MCP servers")
    parser.add_argument("--top", type=int, default=10, help="How many popular servers to scan")
    parser.add_argument("--timeout", type=int, default=120, help="Per-server live-scan timeout (s)")
    parser.add_argument(
        "--search-size", type=int, default=80, help="npm search candidates to consider"
    )
    args = parser.parse_args()

    from mcpradar.enrich import enrich_result
    from mcpradar.registry.popularity import discover_popular_servers

    print("Discovering the most popular MCP servers (npm search)…")
    ranked = discover_popular_servers(top_n=args.top, search_size=args.search_size)
    print(f"Top {len(ranked)} by popularity:")
    for i, r in enumerate(ranked, 1):
        print(f"  {i:2}. {r.entry.name}  (score {r.score})")

    RESULTS_DIR.mkdir(exist_ok=True)
    written = 0
    for r in ranked:
        pkg = next(
            (p for p in r.entry.packages if _scan_command_for(p.registry_type, p.identifier)),
            None,
        )
        if pkg is None:
            print(f"  skip {r.entry.name}: no npm/pip package")
            continue
        cmd = _scan_command_for(pkg.registry_type, pkg.identifier)
        assert cmd is not None

        data = _live_scan(cmd, args.timeout)
        live_ok = data is not None
        if data is None:
            # Live scan failed (needs keys/args or won't launch) — fall back to
            # grading it from its package alone (dependencies + source).
            data = {
                "name": r.entry.name,
                "target": cmd,
                "transport": "stdio",
                "version": r.entry.version,
                "tools": [],
                "findings": [],
                "scanned_at": datetime.now(UTC).isoformat(),
            }
        else:
            data["name"] = r.entry.name
            data.setdefault("target", cmd)
            data.setdefault("scanned_at", datetime.now(UTC).isoformat())

        data["popularity"] = {
            "score": r.score,
            "npm_downloads": r.signals.npm_downloads,
            "pypi_downloads": r.signals.pypi_downloads,
            "github_stars": r.signals.github_stars,
        }
        data["trending"] = True

        try:
            ok, note = enrich_result(data)
            print(f"  {r.entry.name}: {'enriched — ' + note if ok else 'no enrichment'}")
        except Exception as exc:  # noqa: BLE001 - enrichment is best-effort
            print(f"  {r.entry.name}: enrichment error: {exc}")

        # A server we could neither launch nor learn anything about from its
        # package is genuinely unknown — mark it incomplete so it is not graded
        # as a clean A. If we have tools or any findings, it is scorable.
        if not live_ok and not data.get("tools") and not data.get("findings"):
            data["incomplete"] = True
            data["incomplete_reason"] = "could not launch headless; no package findings"

        out = RESULTS_DIR / f"trending_{_slug(r.entry.name)}.json"
        out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        written += 1

    print(f"\nWrote {written} trending result(s) to {RESULTS_DIR}")
    print("Run 'mcpradar leaderboard generate' next.")


if __name__ == "__main__":
    main()
