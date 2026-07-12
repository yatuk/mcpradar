"""Typosquatting detection for MCP server / package names.

A user means to install a legitimate MCP server but installs a lookalike
(``twittter-mcp`` for ``twitter-mcp``, ``@modelcontextprotocol/...`` for the
official scope). This module compares a name against a curated list of popular
MCP packages by Levenshtein distance and flags near-misses (rule T001).
"""

from __future__ import annotations

from dataclasses import dataclass

from mcpradar.scanner.report import Finding, Severity

# Curated list of popular / official MCP package names to protect. A name that
# is *close but not equal* to one of these is a likely typosquat.
KNOWN_PACKAGES: frozenset[str] = frozenset(
    {
        # Official @modelcontextprotocol reference servers (npm)
        "@modelcontextprotocol/server-filesystem",
        "@modelcontextprotocol/server-memory",
        "@modelcontextprotocol/server-everything",
        "@modelcontextprotocol/server-sequential-thinking",
        "@modelcontextprotocol/server-git",
        "@modelcontextprotocol/server-github",
        "@modelcontextprotocol/server-gitlab",
        "@modelcontextprotocol/server-slack",
        "@modelcontextprotocol/server-postgres",
        "@modelcontextprotocol/server-sqlite",
        "@modelcontextprotocol/server-puppeteer",
        "@modelcontextprotocol/server-brave-search",
        "@modelcontextprotocol/server-google-maps",
        "@modelcontextprotocol/server-everart",
        "@modelcontextprotocol/server-fetch",
        "@modelcontextprotocol/server-redis",
        "@modelcontextprotocol/server-sentry",
        "@modelcontextprotocol/server-gdrive",
        "@modelcontextprotocol/inspector",
        # Official Python servers (PyPI)
        "mcp-server-git",
        "mcp-server-time",
        "mcp-server-fetch",
        "mcp-server-sqlite",
        # Popular community servers
        "@playwright/mcp",
        "@browsermcp/mcp",
        "@notionhq/notion-mcp-server",
        "@upstash/context7-mcp",
        "@wonderwhy-er/desktop-commander",
        "chrome-devtools-mcp",
        "firecrawl-mcp",
        "tavily-mcp",
        "exa-mcp-server",
        "duckduckgo-mcp-server",
        "mcp-server-kubernetes",
        "blender-mcp",
        "figma-developer-mcp",
        # Common brand names that MCP servers wrap (typosquat lures)
        "twitter-mcp",
        "stripe-mcp",
        "github-mcp",
        "slack-mcp",
        "notion-mcp",
        "postmark-mcp",
    }
)

# Scopes/orgs worth protecting from lookalike scopes.
KNOWN_SCOPES: frozenset[str] = frozenset(
    {"@modelcontextprotocol", "@playwright", "@notionhq", "@upstash", "@browsermcp"}
)


@dataclass(frozen=True)
class TyposquatHit:
    name: str
    suspected: str
    distance: int


def _levenshtein(a: str, b: str, max_dist: int = 2) -> int:
    """Bounded Levenshtein distance; returns max_dist + 1 if it exceeds the cap."""
    if abs(len(a) - len(b)) > max_dist:
        return max_dist + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i]
        best = i
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            cur.append(v)
            best = min(best, v)
        if best > max_dist:
            return max_dist + 1
        prev = cur
    return prev[-1]


def _scope_of(name: str) -> str:
    return name.split("/", 1)[0] if name.startswith("@") and "/" in name else ""


def check_typosquat(name: str) -> TyposquatHit | None:
    """Return a TyposquatHit if ``name`` closely resembles — but does not equal —
    a known package, else None."""
    name = name.strip().lower()
    if not name or name in {k.lower() for k in KNOWN_PACKAGES}:
        return None

    best: TyposquatHit | None = None
    for known in KNOWN_PACKAGES:
        kl = known.lower()
        # Ignore trivially short names to avoid noise.
        if min(len(name), len(kl)) < 5:
            continue
        dist = _levenshtein(name, kl)
        # 1-2 edits and a small edit ratio → likely a deliberate lookalike.
        if (
            1 <= dist <= 2
            and dist <= max(1, int(0.34 * len(kl)))
            and (best is None or dist < best.distance)
        ):
            best = TyposquatHit(name=name, suspected=known, distance=dist)
    if best:
        return best

    # Lookalike scope with an otherwise-plausible package (@modelcontextprotocol/...).
    scope = _scope_of(name)
    if scope and scope not in {s.lower() for s in KNOWN_SCOPES}:
        for known_scope in KNOWN_SCOPES:
            if 1 <= _levenshtein(scope, known_scope.lower()) <= 2:
                return TyposquatHit(name=name, suspected=f"{known_scope}/…", distance=1)
    return None


def typosquat_finding(hit: TyposquatHit, target: str, location: str = "config") -> Finding:
    return Finding(
        rule_id="T001",
        title="Possible typosquatting package name",
        description=(
            f"'{hit.name}' closely resembles the known package '{hit.suspected}' "
            f"(edit distance {hit.distance}); verify this is the intended package "
            "and not a lookalike"
        ),
        severity=Severity.HIGH,
        target=target,
        location=location,
        detail={"name": hit.name, "suspected": hit.suspected, "distance": hit.distance},
    )
