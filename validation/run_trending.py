"""Refresh pending leaderboard entries and the daily Registry top ten.

The official MCP Registry does not expose a popularity order. MCPRadar first
intersects npm's popularity-aware MCP search with packages published in the
official Registry, then ranks that bounded set using weekly downloads and
GitHub stars. Only Registry-listed packages can become daily trending rows.

Untrusted stdio packages are launched in disposable containers by default.
Package installation needs temporary container egress; the server still runs
as a non-root user with a read-only root filesystem, no capabilities, bounded
resources, and no host mounts. ``--allow-host-exec`` is an explicit opt-out.

Usage::

    python validation/run_trending.py --pending --top 10 --sandbox
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

import yaml

VALIDATION_DIR = Path(__file__).parent
PROJECT_ROOT = VALIDATION_DIR.parent
RESULTS_DIR = VALIDATION_DIR / "results"
TARGETS_FILE = VALIDATION_DIR / "targets.yaml"
_NPM_IDENTIFIER = re.compile(r"^(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+$")
_PYPI_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.-]+$")
_VERSION = re.compile(r"^[A-Za-z0-9_.+-]+$")
_PIP_PIPELINE = re.compile(
    r"^(?:python\s+-m\s+)?pip(?:3)?\s+install\s+([A-Za-z0-9_.-]+)\s*&&\s*.+$"
)
_PIPX_PIPELINE = re.compile(r"^pipx\s+install\s+([A-Za-z0-9_.-]+)\s*&&\s*.+$")


@dataclass(frozen=True)
class ScanTarget:
    """One server command and its stable result destination."""

    name: str
    command: str
    output: Path
    version: str = ""
    trending: bool = False
    popularity: dict[str, int | float | None | str] | None = None


@dataclass(frozen=True)
class ScanAttempt:
    """Subprocess outcome without exposing unbounded process output."""

    data: dict[str, Any] | None
    error: str = ""


@dataclass(frozen=True)
class RefreshResult:
    """Persisted refresh outcome used for progress and exit summaries."""

    name: str
    coverage: Literal["live", "package-only", "incomplete"]
    tools: int
    findings: int
    output: Path


def _slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("_")


def _server_name(data: dict[str, Any], fallback: str) -> str:
    name = data.get("name")
    if isinstance(name, str) and name:
        return name
    target = str(data.get("target", ""))
    return next((token for token in target.split() if token.startswith("@")), fallback)


def _normalize_target_command(command: str) -> str:
    """Turn historical install-then-run recipes into one-shot package runners."""
    stripped = command.strip()
    for pattern in (_PIP_PIPELINE, _PIPX_PIPELINE):
        match = pattern.fullmatch(stripped)
        if match:
            return f"uvx {match.group(1)}"
    return stripped


def _has_scan_evidence(data: dict[str, Any]) -> bool:
    """Mirror leaderboard generation's definition of a completed scan."""
    if data.get("incomplete"):
        return False
    tools = data.get("tools")
    tool_count = len(tools) if isinstance(tools, list) else 0
    summary = data.get("summary")
    if isinstance(summary, dict) and isinstance(summary.get("total_tools"), int):
        tool_count = max(tool_count, summary["total_tools"])
    return bool(tool_count or data.get("scan_id") or data.get("id") or data.get("scanned_at"))


def load_target_commands(path: Path = TARGETS_FILE) -> dict[str, str]:
    """Load name-to-command mappings, accepting the historical key alias."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    servers = raw.get("servers", []) if isinstance(raw, dict) else []
    commands: dict[str, str] = {}
    for item in servers:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        command = item.get("scan") or item.get("command")
        if isinstance(name, str) and name and isinstance(command, str) and command.strip():
            commands.setdefault(name, _normalize_target_command(command))
    return commands


def _retry_due(data: dict[str, Any], retry_after_days: int, now: datetime) -> bool:
    if not data.get("incomplete") or retry_after_days <= 0:
        return True
    stamp = data.get("last_attempted_at") or data.get("scanned_at")
    if not isinstance(stamp, str) or not stamp:
        return True
    try:
        attempted = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return True
    if attempted.tzinfo is None:
        attempted = attempted.replace(tzinfo=UTC)
    return attempted <= now - timedelta(days=retry_after_days)


def collect_pending_targets(
    results_dir: Path = RESULTS_DIR,
    targets_file: Path = TARGETS_FILE,
    *,
    retry_after_days: int = 7,
    now: datetime | None = None,
) -> tuple[list[ScanTarget], list[str]]:
    """Return unresolved leaderboard rows with a known safe launch recipe.

    Duplicate result files are grouped by server name. If any copy has real
    scan evidence, stale pending copies are ignored rather than re-executed.
    """
    grouped: dict[str, list[tuple[Path, dict[str, Any]]]] = {}
    for path in sorted(results_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(data, dict):
            continue
        name = _server_name(data, path.stem)
        grouped.setdefault(name, []).append((path, data))

    commands = load_target_commands(targets_file)
    current = now or datetime.now(UTC)
    pending: list[ScanTarget] = []
    unmapped: list[str] = []
    for name, copies in grouped.items():
        if any(_has_scan_evidence(data) for _path, data in copies):
            continue
        # A stale duplicate stub must not bypass the cooldown recorded by a
        # newer incomplete copy for the same logical server.
        if any(
            data.get("incomplete") and not _retry_due(data, retry_after_days, current)
            for _path, data in copies
        ):
            continue
        eligible = copies
        # Prefer a registry stub as the canonical file, then use lexical order.
        output, seed = min(
            eligible,
            key=lambda pair: (pair[1].get("status") != "registry-pending", pair[0].name),
        )
        embedded = seed.get("target") or seed.get("command")
        command = embedded.strip() if isinstance(embedded, str) else ""
        command = command or commands.get(name, "")
        if not command:
            unmapped.append(name)
            continue
        pending.append(
            ScanTarget(
                name=name,
                command=command,
                output=output,
                version=str(seed.get("version", "")),
            )
        )
    pending.sort(key=lambda target: target.name.casefold())
    return pending, sorted(unmapped, key=str.casefold)


def _package_command(registry_type: str, identifier: str, version: str = "") -> str | None:
    """Build a shell-safe, version-pinned command from Registry metadata."""
    kind = (registry_type or "").lower()
    clean_version = version if version and _VERSION.fullmatch(version) else ""
    if kind == "npm" and _NPM_IDENTIFIER.fullmatch(identifier):
        spec = f"{identifier}@{clean_version}" if clean_version else identifier
        return f"npx -y {spec}"
    if kind in {"pypi", "pip"} and _PYPI_IDENTIFIER.fullmatch(identifier):
        spec = f"{identifier}=={clean_version}" if clean_version else identifier
        return f"uvx {spec}"
    return None


def _json_from_stdout(raw: str) -> dict[str, Any] | None:
    raw = raw.strip()
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass
    decoder = json.JSONDecoder()
    for index, char in enumerate(raw):
        if char != "{":
            continue
        try:
            parsed, _end = decoder.raw_decode(raw[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _short_error(proc: subprocess.CompletedProcess[str]) -> str:
    raw = (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()
    return re.sub(r"\s+", " ", raw)[-500:]


def _live_scan(command: str, timeout: int, *, allow_host_exec: bool) -> ScanAttempt:
    args = [
        sys.executable,
        "-m",
        "mcpradar",
        "scan",
        command,
        "-t",
        "stdio",
        "--format",
        "json",
        "-s",
        "low",
        "--no-save",
    ]
    if allow_host_exec:
        args.append("--allow-host-exec")
    else:
        args.extend(
            [
                "--sandbox",
                "--sandbox-network",
                "bridge",
                "--allow-unrestricted-egress",
            ]
        )
        if command.split(maxsplit=1)[0].lower().removesuffix(".exe") == "uvx":
            args.extend(["--sandbox-image", "ghcr.io/astral-sh/uv:python3.12-bookworm-slim"])
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            cwd=str(PROJECT_ROOT),
        )
    except subprocess.TimeoutExpired:
        return ScanAttempt(None, f"timeout after {timeout}s")
    except (FileNotFoundError, OSError) as exc:
        return ScanAttempt(None, str(exc)[:500])
    if proc.returncode != 0:
        return ScanAttempt(None, _short_error(proc))
    data = _json_from_stdout(proc.stdout or "")
    if data is None:
        return ScanAttempt(None, "scanner returned no JSON result")
    return ScanAttempt(data)


def _atomic_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def scan_target(target: ScanTarget, timeout: int, *, allow_host_exec: bool) -> RefreshResult:
    """Live-scan one target, enrich its package, and persist honest coverage."""
    from mcpradar.enrich import enrich_result

    attempted_at = datetime.now(UTC).isoformat()
    attempt = _live_scan(target.command, timeout, allow_host_exec=allow_host_exec)
    live_ok = attempt.data is not None
    data = attempt.data or {
        "transport": "stdio",
        "tools": [],
        "findings": [],
        "summary": {"total_tools": 0},
    }
    data["name"] = target.name
    data["target"] = target.command
    data["version"] = str(data.get("version") or target.version)
    data["scanned_at"] = str(data.get("scanned_at") or attempted_at)
    data["last_attempted_at"] = attempted_at
    data["trending"] = target.trending
    if target.popularity is not None:
        data["popularity"] = target.popularity
    live_scan: dict[str, Any] = {"ok": live_ok}
    if attempt.error:
        live_scan["error"] = attempt.error
    data["live_scan"] = live_scan

    enrichment_ok = False
    enrichment_note = ""
    try:
        enrichment_ok, enrichment_note = enrich_result(data)
    except Exception as exc:  # noqa: BLE001 - one package must not stop the batch
        enrichment_note = f"enrichment error: {exc}"[:500]
    data["package_scan"] = {"ok": enrichment_ok, "note": enrichment_note}

    raw_tools = data.get("tools")
    tools: list[Any] = raw_tools if isinstance(raw_tools, list) else []
    raw_findings = data.get("findings")
    findings: list[Any] = raw_findings if isinstance(raw_findings, list) else []
    raw_summary = data.get("summary")
    summary: dict[str, Any] = raw_summary if isinstance(raw_summary, dict) else {}
    summary["total_tools"] = len(tools)
    data["summary"] = summary

    if live_ok:
        coverage: Literal["live", "package-only", "incomplete"] = "live"
        data["status"] = "scanned"
        data.pop("incomplete", None)
        data.pop("incomplete_reason", None)
    elif findings:
        coverage = "package-only"
        data["status"] = "scanned"
        data["scan_coverage"] = "package-only"
        data.pop("incomplete", None)
        data.pop("incomplete_reason", None)
    else:
        coverage = "incomplete"
        data["status"] = "incomplete"
        data["incomplete"] = True
        reasons = [attempt.error or "live handshake failed"]
        if enrichment_note:
            reasons.append(enrichment_note)
        data["incomplete_reason"] = "; ".join(reasons)[:500]

    _atomic_json(target.output, data)
    return RefreshResult(target.name, coverage, len(tools), len(findings), target.output)


def scan_targets(
    targets: list[ScanTarget],
    timeout: int,
    *,
    allow_host_exec: bool,
    max_workers: int,
) -> list[RefreshResult]:
    """Scan a bounded batch concurrently and print completion progress."""
    results: list[RefreshResult] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(
                scan_target,
                target,
                timeout,
                allow_host_exec=allow_host_exec,
            ): target
            for target in targets
        }
        for future in as_completed(futures):
            target = futures[future]
            try:
                result = future.result()
            except Exception as exc:  # noqa: BLE001 - preserve the rest of the batch
                print(f"  FAIL {target.name}: {str(exc)[:300]}", flush=True)
                continue
            results.append(result)
            print(
                f"  {result.coverage.upper():12} {result.name} "
                f"({result.tools} tools, {result.findings} findings)",
                flush=True,
            )
    return results


def discover_trending_targets(
    top: int,
    search_size: int,
    results_dir: Path = RESULTS_DIR,
) -> list[ScanTarget]:
    """Discover an official-Registry-only popularity top list."""
    from mcpradar.registry.popularity import discover_popular_registry_servers

    ranked = discover_popular_registry_servers(top_n=top, search_size=search_size)
    if len(ranked) < top:
        raise RuntimeError(
            f"Registry popularity discovery returned {len(ranked)} of {top} required servers"
        )

    targets: list[ScanTarget] = []
    for ranked_server in ranked:
        package = next(
            (
                package
                for package in ranked_server.entry.packages
                if _package_command(
                    package.registry_type,
                    package.identifier,
                    package.version,
                )
            ),
            None,
        )
        if package is None:
            continue
        command = _package_command(package.registry_type, package.identifier, package.version)
        assert command is not None
        popularity: dict[str, int | float | None | str] = {
            "method": "registry-packages/npm-pypi-github",
            "score": ranked_server.score,
            "npm_downloads": ranked_server.signals.npm_downloads,
            "pypi_downloads": ranked_server.signals.pypi_downloads,
            "github_stars": ranked_server.signals.github_stars,
        }
        targets.append(
            ScanTarget(
                name=ranked_server.entry.name,
                command=command,
                version=ranked_server.entry.version,
                output=results_dir / f"trending_{_slug(ranked_server.entry.name)}.json",
                trending=True,
                popularity=popularity,
            )
        )
    if len(targets) < top:
        raise RuntimeError(f"Only {len(targets)} of the Registry top {top} are executable packages")
    return targets


def retire_old_trending(current_names: set[str], results_dir: Path = RESULTS_DIR) -> int:
    """Keep old scans but remove their top-ten marker once they fall out."""
    retired = 0
    for path in results_dir.glob("trending_*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(data, dict) or not data.get("trending"):
            continue
        if _server_name(data, path.stem) in current_names:
            continue
        data["trending"] = False
        _atomic_json(path, data)
        retired += 1
    return retired


def _summary(results: list[RefreshResult]) -> str:
    counts: dict[str, int] = dict.fromkeys(("live", "package-only", "incomplete"), 0)
    for result in results:
        counts[result.coverage] += 1
    return (
        f"{counts['live']} live, {counts['package-only']} package-only, "
        f"{counts['incomplete']} incomplete"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Refresh pending and popular leaderboard servers")
    parser.add_argument("--top", type=int, default=10, help="Registry popularity rows to refresh")
    parser.add_argument("--pending", action="store_true", help="Also scan unresolved rows")
    parser.add_argument("--pending-limit", type=int, default=0, help="Max pending rows (0 = all)")
    parser.add_argument("--timeout", type=int, default=120, help="Per-server timeout in seconds")
    parser.add_argument("--search-size", type=int, default=250, help="npm candidates to intersect")
    parser.add_argument("--workers", type=int, default=3, help="Concurrent isolated scans")
    parser.add_argument("--dry-run", action="store_true", help="Discover and list without writing")
    parser.add_argument(
        "--retry-incomplete-days",
        type=int,
        default=7,
        help="Cooldown before retrying an incomplete result",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--sandbox", action="store_true", help="Use disposable containers (default)")
    mode.add_argument(
        "--allow-host-exec",
        action="store_true",
        help="Explicitly run untrusted stdio packages on the host",
    )
    args = parser.parse_args()
    if args.top < 0 or args.pending_limit < 0 or args.timeout < 1 or args.workers < 1:
        parser.error("top/pending-limit must be non-negative; timeout/workers must be positive")

    all_results: list[RefreshResult] = []
    if args.pending:
        pending, unmapped = collect_pending_targets(
            retry_after_days=args.retry_incomplete_days,
        )
        if args.pending_limit:
            pending = pending[: args.pending_limit]
        print(f"Pending: {len(pending)} runnable, {len(unmapped)} without a command", flush=True)
        for name in unmapped:
            print(f"  UNMAPPED     {name}", flush=True)
        if args.dry_run:
            for target in pending:
                print(f"  WOULD SCAN   {target.name}: {target.command}", flush=True)
        else:
            all_results.extend(
                scan_targets(
                    pending,
                    args.timeout,
                    allow_host_exec=args.allow_host_exec,
                    max_workers=args.workers,
                )
            )

    if args.top:
        print("Discovering the official Registry popularity top list...", flush=True)
        trending = discover_trending_targets(args.top, args.search_size)
        for index, target in enumerate(trending, 1):
            score = target.popularity.get("score") if target.popularity else "-"
            print(f"  {index:2}. {target.name} (score {score})", flush=True)
        if not args.dry_run:
            retired = retire_old_trending({target.name for target in trending})
            if retired:
                print(f"Retired {retired} old trending marker(s)", flush=True)
            all_results.extend(
                scan_targets(
                    trending,
                    args.timeout,
                    allow_host_exec=args.allow_host_exec,
                    max_workers=args.workers,
                )
            )

    print(f"Refresh complete: {_summary(all_results)}", flush=True)
    print("Run 'python docs/leaderboard/generate.py' to regenerate public artifacts.", flush=True)


if __name__ == "__main__":
    main()
