"""Popularity ranking for MCP registry servers.

The official registry does not rank servers, so "most popular" has to come from
external usage signals. We combine three, each best-effort:

  - npm weekly downloads      (api.npmjs.org)          — for npm packages
  - PyPI weekly downloads     (pypistats.org)          — for pip packages
  - GitHub stargazers         (api.github.com)         — from the repo URL

The three live on wildly different scales (downloads in the millions, stars in
the thousands), so a raw sum would be dominated by downloads. We combine them on
a **log scale** and sum the evidence:

    score = log10(npm+1) + log10(pypi+1) + log10(stars+1)

This rewards a server that is popular across *multiple* signals and keeps any
single signal from swamping the others. Missing signals contribute 0, so a
package present in only one ecosystem is still ranked on what we can observe.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import quote, urlparse

if TYPE_CHECKING:
    from mcpradar.registry.client import RegistryEntry

_NPM_DOWNLOADS = "https://api.npmjs.org/downloads/point/last-week/"
_NPM_SEARCH = "https://registry.npmjs.org/-/v1/search"
_PYPI_RECENT = "https://pypistats.org/api/packages/{pkg}/recent"
_GH_REPO = "https://api.github.com/repos/{owner}/{repo}"

# The MCP registry holds tens of thousands of servers with no popularity order,
# so scoring all of them daily is impractical. npm's search API already returns
# MCP servers ranked by a popularity-aware score in one call, so we use it to
# *discover* the popular candidates, then score that bounded set on all signals.
# Substrings that mark a package as a library/adapter rather than a server.
_NON_SERVER_SUBSTR = ("sdk", "adapter", "transport", "harness", "framework", "-ts-core")
_NON_SERVER_NAMES = {"ai", "@modelcontextprotocol/sdk", "metaharness", "agentic-flow"}


@dataclass
class Signals:
    """Raw popularity signals for one server (None = not applicable/unknown)."""

    npm_downloads: int | None = None
    pypi_downloads: int | None = None
    github_stars: int | None = None

    @property
    def score(self) -> float:
        total = 0.0
        for v in (self.npm_downloads, self.pypi_downloads, self.github_stars):
            if v and v > 0:
                total += math.log10(v + 1)
        return round(total, 4)


@dataclass
class RankedServer:
    entry: RegistryEntry
    signals: Signals
    score: float = field(default=0.0)


def npm_weekly_downloads(pkg: str, timeout: float = 10.0) -> int | None:
    data = _get_json(_NPM_DOWNLOADS + pkg, timeout)
    if isinstance(data, dict) and isinstance(data.get("downloads"), int):
        return int(data["downloads"])
    return None


def pypi_weekly_downloads(pkg: str, timeout: float = 10.0) -> int | None:
    data = _get_json(_PYPI_RECENT.format(pkg=pkg), timeout)
    if isinstance(data, dict):
        d = data.get("data")
        if isinstance(d, dict) and isinstance(d.get("last_week"), int):
            return int(d["last_week"])
    return None


def github_stars(repo_url: str, timeout: float = 10.0) -> int | None:
    owner_repo = _github_owner_repo(repo_url)
    if owner_repo is None:
        return None
    owner, repo = owner_repo
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = _get_json(_GH_REPO.format(owner=owner, repo=repo), timeout, headers=headers)
    if isinstance(data, dict) and isinstance(data.get("stargazers_count"), int):
        return int(data["stargazers_count"])
    return None


def _github_owner_repo(repo_url: str) -> tuple[str, str] | None:
    if not repo_url:
        return None
    parsed = urlparse(repo_url)
    if "github.com" not in parsed.netloc:
        return None
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return None
    return parts[0], parts[1].removesuffix(".git")


def download_signals(entry: RegistryEntry, timeout: float = 10.0) -> Signals:
    """Gather the cheap download signals (npm + PyPI) for one entry.

    Download APIs have no tight rate limit, so these are safe to fetch for the
    whole registry. GitHub stars are added later, only for the top candidates.
    """
    sig = Signals()
    for pkg in entry.packages:
        rtype = (pkg.registry_type or "").lower()
        if rtype == "npm" and sig.npm_downloads is None:
            sig.npm_downloads = npm_weekly_downloads(pkg.identifier, timeout)
        elif rtype in ("pypi", "pip") and sig.pypi_downloads is None:
            sig.pypi_downloads = pypi_weekly_downloads(pkg.identifier, timeout)
    return sig


def collect_signals(entry: RegistryEntry, timeout: float = 10.0) -> Signals:
    """Gather every applicable popularity signal, including GitHub stars."""
    sig = download_signals(entry, timeout)
    if entry.repository_url:
        sig.github_stars = github_stars(entry.repository_url, timeout)
    return sig


def rank_servers(
    entries: list[RegistryEntry],
    top_n: int = 10,
    timeout: float = 10.0,
    max_workers: int = 12,
    star_top_k: int | None = None,
) -> list[RankedServer]:
    """Rank registry entries by combined popularity, highest first.

    Two phases keep it fast and within GitHub's unauthenticated rate limit:

      1. Fetch the cheap download signals (npm + PyPI) for *every* candidate
         concurrently, and rank by that preliminary score.
      2. Fetch GitHub stars only for the top ``star_top_k`` of that ranking,
         then re-score and take the final ``top_n``.

    Only entries with at least one installable package and a positive score are
    returned (a server with no observable signal cannot be called popular).
    """
    from concurrent.futures import ThreadPoolExecutor

    candidates = [e for e in entries if e.packages]

    # Phase 1 — downloads only (no tight rate limit; safe for the whole pool).
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        dl = list(pool.map(lambda e: download_signals(e, timeout), candidates))
    prelim = [(e, s) for e, s in zip(candidates, dl, strict=True) if s.score > 0]
    prelim.sort(key=lambda es: es[1].score, reverse=True)

    # Phase 2 — stars for the top slice only (bounded to respect GitHub's
    # 60 req/hr unauthenticated limit; a GITHUB_TOKEN lifts it in CI).
    k = star_top_k if star_top_k is not None else max(top_n * 3, 30)
    top_slice = prelim[:k]
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        stars = list(pool.map(lambda es: github_stars(es[0].repository_url, timeout), top_slice))

    ranked: list[RankedServer] = []
    for (entry, sig), star in zip(top_slice, stars, strict=True):
        sig.github_stars = star
        ranked.append(RankedServer(entry=entry, signals=sig, score=sig.score))
    ranked.sort(key=lambda r: r.score, reverse=True)
    return ranked[:top_n]


def _is_server_package(name: str, keywords: list[str]) -> bool:
    """Heuristic: keep MCP *servers*, drop SDKs / adapters / libraries."""
    low = name.lower()
    if low in _NON_SERVER_NAMES:
        return False
    kws = {k.lower() for k in keywords}
    looks_server = "mcp-server" in kws or "mcp" in low or "server" in low
    # A library name like "@mcp-b/webmcp-ts-sdk" contains "mcp" but is not a
    # server; exclude the tell-tale substrings unless "server" is explicit.
    is_library = "server" not in low and any(s in low for s in _NON_SERVER_SUBSTR)
    return looks_server and not is_library


def _npm_search(query: str, size: int, timeout: float) -> list[dict[str, object]]:
    data = _get_json(f"{_NPM_SEARCH}?text={quote(query)}&size={size}", timeout)
    if not isinstance(data, dict):
        return []
    objs = data.get("objects")
    return objs if isinstance(objs, list) else []


def discover_popular_servers(
    top_n: int = 10,
    search_size: int = 80,
    timeout: float = 10.0,
    max_workers: int = 12,
) -> list[RankedServer]:
    """Discover the most popular MCP *servers* via npm search, scored on all signals.

    npm's search API returns MCP servers already ordered by a popularity-aware
    score, so it is the candidate source (the MCP registry has no ranking and is
    far too large to score daily). The bounded candidate set is then re-scored on
    the real signals — npm weekly downloads, PyPI downloads, GitHub stars —
    exactly like :func:`rank_servers`, and the top ``top_n`` are returned.

    Note: discovery is npm-based, so a *PyPI-only* server that publishes no npm
    package will not appear here (PyPI offers no popularity search); such servers
    are still covered by the curated corpus.
    """
    from concurrent.futures import ThreadPoolExecutor

    from mcpradar.registry.client import PackageRef, RegistryEntry

    seen: set[str] = set()
    candidates: list[tuple[str, str]] = []  # (npm name, repo url)
    for query in ("keywords:mcp-server", "keywords:mcp"):
        for obj in _npm_search(query, search_size, timeout):
            pkg = obj.get("package") if isinstance(obj, dict) else None
            if not isinstance(pkg, dict):
                continue
            name = str(pkg.get("name", ""))
            keywords = pkg.get("keywords") or []
            if not name or name in seen or not isinstance(keywords, list):
                continue
            if not _is_server_package(name, keywords):
                continue
            seen.add(name)
            links = pkg.get("links") if isinstance(pkg.get("links"), dict) else {}
            repo = str(links.get("repository", "")) if links else ""
            repo = repo.replace("git+", "").replace("git://", "https://").removesuffix(".git")
            candidates.append((name, repo))

    def _score(nr: tuple[str, str]) -> Signals:
        name, repo = nr
        sig = Signals()
        sig.npm_downloads = npm_weekly_downloads(name, timeout)
        sig.pypi_downloads = pypi_weekly_downloads(name, timeout)
        if repo:
            sig.github_stars = github_stars(repo, timeout)
        return sig

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        sigs = list(pool.map(_score, candidates))

    ranked: list[RankedServer] = []
    for (name, repo), sig in zip(candidates, sigs, strict=True):
        if sig.score <= 0:
            continue
        entry = RegistryEntry(
            name=name,
            title=name,
            description="",
            version="",
            packages=[
                PackageRef(registry_type="npm", identifier=name, version="", transport="stdio")
            ],
            repository_url=repo,
        )
        ranked.append(RankedServer(entry=entry, signals=sig, score=sig.score))
    ranked.sort(key=lambda r: r.score, reverse=True)
    return ranked[:top_n]


def _get_json(url: str, timeout: float, headers: dict[str, str] | None = None) -> object | None:
    try:
        import httpx

        resp = httpx.get(url, timeout=timeout, headers=headers, follow_redirects=True)
    except Exception:
        return None
    if resp.status_code != 200:
        return None
    try:
        data: object = resp.json()
    except Exception:
        return None
    return data
