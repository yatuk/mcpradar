"""Enrich a leaderboard result with source-level findings.

A leaderboard result file holds the *schema* findings from a live scan. This
module derives the server's published package from its launch command, fetches
it (no install), and runs the dependency-CVE (D001) and source (S-rules) scanners
over it — merging their findings back so a server's vulnerable dependencies or
Description-Code Inconsistency affect its grade, not just its tool schemas.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Any

from mcpradar.fetch import FetchError, resolve_source

# Launchers whose first package argument is an installable package, and the OSV
# / fetch ecosystem they map to.
_NPM_RUNNERS = {"npx", "npm", "pnpm", "yarn", "bunx"}
_PIP_RUNNERS = {"uvx", "pipx"}
_RUNNER_FLAGS = {"-y", "--yes", "-p", "--package", "exec", "run", "tool", "dlx", "--", "-c"}


def package_ref_from_target(target: str) -> str | None:
    """Derive an ``npm:``/``pip:`` package reference from a launch command.

    ``npx -y @scope/pkg`` → ``npm:@scope/pkg``; ``uvx mcp-server-git`` →
    ``pip:mcp-server-git``. Returns None for local scripts or unknown launchers.
    """
    parts = target.split()
    if not parts:
        return None
    runner = Path(parts[0]).name.lower().removesuffix(".exe")
    if runner in _NPM_RUNNERS:
        eco = "npm"
    elif runner in _PIP_RUNNERS:
        eco = "pip"
    else:
        return None
    for tok in parts[1:]:
        if tok in _RUNNER_FLAGS or tok.startswith("-"):
            continue
        pkg = tok.split("@", 1)[0] if not tok.startswith("@") else tok
        # strip an @version on scoped names (@scope/name@1.2.3)
        if pkg.startswith("@") and pkg.count("@") > 1:
            scope, _, rest = pkg.partition("/")
            pkg = f"{scope}/{rest.split('@', 1)[0]}"
        return f"{eco}:{pkg}"
    return None


def enrich_result(
    result: dict[str, Any],
    *,
    run_deps: bool = True,
    run_source: bool = True,
) -> tuple[bool, str]:
    """Fetch the server's package and merge deps/source findings into ``result``.

    Returns ``(enriched, note)``. Findings are appended to ``result["findings"]``
    and de-duplicated by (rule_id, target). Network/fetch failures are non-fatal.
    """
    target = str(result.get("target", ""))
    ref = package_ref_from_target(target)
    if not ref:
        return False, "no package ref"

    workdir = Path(tempfile.mkdtemp(prefix="mcpradar-enrich-"))
    try:
        try:
            src = resolve_source(ref, workdir=workdir)
        except FetchError as exc:
            return False, f"fetch failed: {exc}"[:120]

        new: list[dict[str, Any]] = []
        if run_deps:
            new += _run_deps(src)
        if run_source:
            new += _run_source(src)

        existing = result.get("findings") or []
        seen = {(f.get("rule_id"), f.get("target")) for f in existing}
        added = 0
        for f in new:
            key = (f.get("rule_id"), f.get("target"))
            if key not in seen:
                seen.add(key)
                existing.append(f)
                added += 1
        result["findings"] = existing
        result["enriched"] = True
        result["enriched_ref"] = ref
        return True, f"+{added} findings from {ref}"
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _run_deps(src: Path) -> list[dict[str, Any]]:
    from mcpradar.supply import scan_dependencies

    try:
        _deps, findings = scan_dependencies(src)
    except Exception:
        return []
    return [_finding_dict(f) for f in findings]


def _run_source(src: Path) -> list[dict[str, Any]]:
    from mcpradar.source import analyze_path

    try:
        result = analyze_path(src)
    except Exception:
        return []
    return [_finding_dict(f) for f in result.findings]


def _finding_dict(f: Any) -> dict[str, Any]:
    from mcpradar.scoring.confidence import confidence_for

    return {
        "rule_id": f.rule_id,
        "title": f.title,
        "description": f.description,
        "severity": f.severity.value,
        "target": f.target,
        "location": f.location,
        "evidence": f.evidence,
        "detail": f.detail,
        "confidence": confidence_for(f.rule_id),
    }
