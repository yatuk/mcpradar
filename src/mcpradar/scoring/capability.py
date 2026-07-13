"""Agentic capability layer for AIVSS scoring.

OWASP AIVSS composes a security score as ``((CVSS_base + AARS) / 2) × ThM``,
where AARS (the Agentic AI Risk Score) captures how much the agent's *design*
amplifies risk — its autonomy, tool use, and blast radius — independent of any
known vulnerability. MCPRadar previously computed only the finding-derived base
and dropped the AARS term, so a server exposing arbitrary command execution
scored the same as a calculator.

This module tags each tool with capability classes (from its name, description,
and input schema) and derives an AARS from the server's aggregate blast radius.
The per-class weights are the model's only tunable coefficients and are
documented and justified in ``docs/scoring-model.md``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# Capability class -> AARS contribution (0-10). Ordered by blast radius:
# arbitrary code execution is the most dangerous agentic capability, a
# read-only compute tool the least. Justified in docs/scoring-model.md.
CAPABILITY_WEIGHTS: dict[str, float] = {
    "code_exec": 8.0,
    "browser_control": 6.0,
    "db_write": 5.0,
    "fs_write": 4.0,
    "secret_access": 3.0,
    "net_egress": 2.0,
    "fs_read": 1.0,
    "pure_compute": 0.0,
}

_WORD = r"(?:^|[^a-z])"

# High-signal patterns per capability. Matched against
# "<name> <description> <input-property-names>" (lowercased).
_CAPABILITY_PATTERNS: dict[str, re.Pattern[str]] = {
    # Trailing (?![a-z]) so short tokens don't match inside benign words
    # ("eval" not in "evaluate"). Bare "system"/"command"/"cmd" are omitted —
    # "file system", "get command history" etc. are not code execution; a real
    # exec tool uses the verb ("execute", "run command", "shell").
    "code_exec": re.compile(
        rf"{_WORD}(?:execute|exec|eval|shell|bash|powershell|subprocess|spawn|"
        rf"repl)(?![a-z])"
        rf"|{_WORD}run_?(?:command|code|shell|script)"
        rf"|{_WORD}shell_?exec"
    ),
    # Require a browser *action*, not the bare noun "browser" (which appears in
    # "browser-free", "open in browser", …). Real browser-control tools are
    # named browser_navigate / page_click / take_screenshot or use a driver.
    "browser_control": re.compile(
        rf"{_WORD}(?:puppeteer|playwright|selenium|webdriver|screenshot)"
        rf"|(?:browser|page)_(?:navigate|goto|click|type|screenshot|evaluate|"
        rf"snapshot|hover|drag|select|fill)"
        rf"|{_WORD}navigate_to"
    ),
    # Bare "query" omitted — a *search* query / query string is not a DB write;
    # real DB mutation says sql / insert / update / execute_sql.
    "db_write": re.compile(
        rf"{_WORD}(?:sql|insert|update|upsert|drop_?table|execute_?sql|"
        rf"database|db_?(?:write|exec|query)|cursor\.)"
    ),
    "fs_write": re.compile(
        rf"{_WORD}(?:write|create_?file|delete|remove|unlink|edit_?file|move_?file|"
        rf"rename|mkdir|rmdir|save_?file|upload|put_?file|append_?file|patch_?file)"
    ),
    "secret_access": re.compile(
        rf"{_WORD}(?:secret|credential|password|api_?key|access_?token|private_?key|"
        rf"vault|keychain|\.env\b|keyring)"
    ),
    "net_egress": re.compile(
        rf"{_WORD}(?:fetch|http|https|request|download|url|webhook|send_?(?:email|message)|"
        rf"post_?to|curl|wget|api_?call|outbound)"
    ),
    "fs_read": re.compile(
        rf"{_WORD}(?:read_?file|read_?directory|list_?(?:files|directory)|cat_?file|"
        rf"get_?file|open_?file|load_?file|stat_?file|glob)"
    ),
}


@dataclass(frozen=True)
class _ToolView:
    name: str
    description: str
    props: tuple[str, ...]


def _as_view(tool: Any) -> _ToolView:
    """Accept a ToolInfo or a result-file dict."""
    if isinstance(tool, dict):
        name = str(tool.get("name", ""))
        desc = str(tool.get("description", "") or "")
        schema = tool.get("input_schema") or {}
    else:
        name = getattr(tool, "name", "") or ""
        desc = getattr(tool, "description", "") or ""
        schema = getattr(tool, "input_schema", {}) or {}
    props: tuple[str, ...] = ()
    if isinstance(schema, dict) and isinstance(schema.get("properties"), dict):
        props = tuple(schema["properties"].keys())
    return _ToolView(name=name, description=desc, props=props)


def tag_tool(tool: Any) -> set[str]:
    """Return the capability classes a single tool exposes.

    A tool with no recognized side effect is ``{"pure_compute"}``.
    """
    v = _as_view(tool)
    haystack = f" {v.name} {v.description} {' '.join(v.props)} ".lower().replace("-", "_")
    classes = {cap for cap, pat in _CAPABILITY_PATTERNS.items() if pat.search(haystack)}
    # A read verb also matched by a write pattern (edit/create) is a write; drop
    # the weaker fs_read if fs_write is present to avoid double counting reads.
    if "fs_write" in classes:
        classes.discard("fs_read")
    return classes or {"pure_compute"}


def compute_aars(tools: list[Any]) -> float:
    """Aggregate AARS (0-10) for a server from its tools' capabilities.

    The dominant term is the single highest-blast-radius capability present; a
    small breadth bonus is added for each additional distinct non-trivial
    capability class (a server that can both execute code *and* egress data is
    riskier than one that only executes code).
    """
    present: set[str] = set()
    for t in tools:
        present |= tag_tool(t)
    weights = sorted((CAPABILITY_WEIGHTS.get(c, 0.0) for c in present), reverse=True)
    if not weights or weights[0] == 0.0:
        return 0.0
    top = weights[0]
    breadth = sum(0.5 for w in weights[1:] if w >= 2.0)
    return min(10.0, top + breadth)


def dominant_capability(tools: list[Any]) -> str:
    """The highest-blast-radius capability class the server exposes."""
    present: set[str] = set()
    for t in tools:
        present |= tag_tool(t)
    return max(present, key=lambda c: CAPABILITY_WEIGHTS.get(c, 0.0), default="pure_compute")
