"""Dependency extraction + OSV vulnerability matching for MCP server source.

Parses the common package manifests (npm and Python) into a normalized
dependency list, then batch-queries OSV.dev for known vulnerabilities. Each
vulnerable dependency becomes a D001 finding whose severity is derived from the
advisory's CVSS score.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from mcpradar.scanner.report import Finding, Severity

if TYPE_CHECKING:
    from mcpradar.cvefeed.osv import OSVClient

# Manifest filenames we know how to parse, in preference order per ecosystem
# (lockfiles first — they carry exact resolved versions).
_MANIFESTS = (
    "package-lock.json",
    "package.json",
    "uv.lock",
    "poetry.lock",
    "pyproject.toml",
    "requirements.txt",
)

_SKIP_DIRS = {".venv", "venv", "node_modules", ".git", "__pycache__", "dist", "build"}


@dataclass(frozen=True)
class Dependency:
    ecosystem: str  # "npm" or "PyPI" (OSV ecosystem names)
    name: str
    version: str
    source: str  # manifest filename the dep came from


def _clean_version(spec: str) -> str | None:
    """Reduce an npm/pip version spec to a concrete version to query.

    "^1.2.3" -> "1.2.3", ">=2.31.0,<3" -> "2.31.0", "*"/"latest" -> None.
    OSV matches this against the advisory's affected ranges.
    """
    spec = spec.strip().strip('"').strip("'")
    if not spec or spec in ("*", "latest", "x"):
        return None
    m = re.search(r"\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.]+)?", spec)
    return m.group(0) if m else None


def _parse_package_lock(data: dict[str, Any]) -> list[Dependency]:
    out: list[Dependency] = []
    # npm lockfile v2/v3: "packages" maps path -> {version}
    pkgs = data.get("packages")
    if isinstance(pkgs, dict):
        for path, info in pkgs.items():
            if not path or not isinstance(info, dict):
                continue  # "" is the root project
            name = path.split("node_modules/")[-1]
            ver = info.get("version")
            if name and isinstance(ver, str):
                out.append(Dependency("npm", name, ver, "package-lock.json"))
        if out:
            return out
    # v1: "dependencies" maps name -> {version}
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        for name, info in deps.items():
            ver = info.get("version") if isinstance(info, dict) else None
            if isinstance(ver, str):
                out.append(Dependency("npm", name, ver, "package-lock.json"))
    return out


def _parse_package_json(data: dict[str, Any]) -> list[Dependency]:
    out: list[Dependency] = []
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        block = data.get(key)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            if not isinstance(spec, str):
                continue
            ver = _clean_version(spec)
            if ver:
                out.append(Dependency("npm", name, ver, "package.json"))
    return out


def _parse_requirements(text: str) -> list[Dependency]:
    out: list[Dependency] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9._-]+)\s*(.*)$", line)
        if not m:
            continue
        name, spec = m.group(1), m.group(2)
        ver = _clean_version(spec)
        if ver:
            out.append(Dependency("PyPI", name, ver, "requirements.txt"))
    return out


def _parse_pyproject(data: dict[str, Any]) -> list[Dependency]:
    out: list[Dependency] = []
    project = data.get("project", {})
    for spec in project.get("dependencies", []) or []:
        if not isinstance(spec, str):
            continue
        m = re.match(r"^([A-Za-z0-9._-]+)\s*(.*)$", spec)
        if not m:
            continue
        ver = _clean_version(m.group(2))
        if ver:
            out.append(Dependency("PyPI", m.group(1), ver, "pyproject.toml"))
    # Poetry style
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name, spec in poetry.items() if isinstance(poetry, dict) else []:
        if name.lower() == "python":
            continue
        if isinstance(spec, str):
            version_spec = spec
        elif isinstance(spec, dict):
            version_spec = spec.get("version", "")
        else:
            version_spec = ""
        ver = _clean_version(version_spec or "")
        if ver:
            out.append(Dependency("PyPI", name, ver, "pyproject.toml"))
    return out


def _parse_uv_lock(data: dict[str, Any]) -> list[Dependency]:
    out: list[Dependency] = []
    for pkg in data.get("package", []) or []:
        name = pkg.get("name")
        ver = pkg.get("version")
        if isinstance(name, str) and isinstance(ver, str):
            out.append(Dependency("PyPI", name, ver, "uv.lock"))
    return out


def _dedupe(deps: list[Dependency]) -> list[Dependency]:
    seen: set[tuple[str, str, str]] = set()
    out: list[Dependency] = []
    for d in deps:
        key = (d.ecosystem, d.name.lower(), d.version)
        if key not in seen:
            seen.add(key)
            out.append(d)
    return out


def _find_manifests(path: Path) -> list[Path]:
    if path.is_file():
        return [path] if path.name in _MANIFESTS else []
    found: list[Path] = []
    for name in _MANIFESTS:
        for p in path.rglob(name):
            if not any(part in _SKIP_DIRS for part in p.parts):
                found.append(p)
    return found


def extract_dependencies(path: Path) -> list[Dependency]:
    """Resolve a path's dependency list from its manifests.

    Prefers lockfiles (exact versions). If a lockfile exists for an ecosystem,
    the looser manifest for that same ecosystem is skipped.
    """
    manifests = _find_manifests(path)
    npm: list[Dependency] = []
    pypi: list[Dependency] = []
    npm_locked = pypi_locked = False

    for m in manifests:
        try:
            if m.name == "package-lock.json":
                npm = _parse_package_lock(json.loads(m.read_text(encoding="utf-8")))
                npm_locked = True
            elif m.name == "package.json" and not npm_locked:
                npm += _parse_package_json(json.loads(m.read_text(encoding="utf-8")))
            elif m.name in ("uv.lock", "poetry.lock"):
                # Both are TOML with a top-level [[package]] name/version array.
                pypi = _parse_uv_lock(tomllib.loads(m.read_text(encoding="utf-8")))
                pypi_locked = True
            elif m.name == "pyproject.toml" and not pypi_locked:
                pypi += _parse_pyproject(tomllib.loads(m.read_text(encoding="utf-8")))
            elif m.name == "requirements.txt" and not pypi_locked:
                pypi += _parse_requirements(m.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, tomllib.TOMLDecodeError, OSError, ValueError):
            continue

    return _dedupe(npm + pypi)


def _severity_from_score(score: float | None) -> Severity:
    if score is None:
        return Severity.MEDIUM
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def scan_dependencies(
    path: Path,
    client: OSVClient | None = None,
    max_deps: int = 500,
) -> tuple[list[Dependency], list[Finding]]:
    """Extract dependencies under ``path`` and match them against OSV.

    Returns (dependencies, findings). Each vulnerable dependency yields one
    D001 finding at a severity derived from the advisory CVSS score.
    """
    from mcpradar.cvefeed.osv import OSVClient

    deps = extract_dependencies(path)[:max_deps]
    if not deps:
        return [], []

    client = client or OSVClient()
    queries: list[tuple[str, str, str | None]] = [(d.ecosystem, d.name, d.version) for d in deps]
    # querybatch returns only ids; hydrate full details (severity/summary/fix)
    # once per unique id via /vulns/{id}.
    by_name = client.query_batch(queries)
    detail: dict[str, object] = {}
    for vulns in by_name.values():
        for v in vulns:
            if v.id and v.id not in detail:
                detail[v.id] = client.get_vuln(v.id) or v

    findings: list[Finding] = []
    for dep in deps:
        stubs = by_name.get(dep.name) or []
        for stub in stubs:
            v = detail.get(stub.id) or stub  # type: ignore[assignment]
            cve = next((a for a in v.aliases if a.startswith("CVE-")), v.id)
            sev = _severity_from_score(v.severity_score)
            fix = f"; fixed in {v.fixed_version}" if v.fixed_version else ""
            findings.append(
                Finding(
                    rule_id="D001",
                    title="Known-vulnerable dependency (OSV)",
                    description=(
                        f"{dep.name}@{dep.version} ({dep.ecosystem}) is affected by "
                        f"{cve}: {v.summary or v.id}{fix}"
                    ),
                    severity=sev,
                    target=f"{dep.name}@{dep.version}",
                    location=dep.source,
                    detail={
                        "package": dep.name,
                        "version": dep.version,
                        "ecosystem": dep.ecosystem,
                        "osv_id": v.id,
                        "cve": cve,
                        "cvss": v.severity_score,
                        "cwe_ids": v.cwe_ids,
                        "fixed_version": v.fixed_version,
                        "references": v.references[:3],
                    },
                )
            )
    return deps, findings
