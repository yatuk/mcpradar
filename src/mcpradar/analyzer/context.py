"""Cross-server contamination analysis engine.

Detects risks that emerge only when multiple MCP servers are
connected to the same LLM agent — the attack surface of the
combined set, not individual tools.

Rules:
  C001 — Tool name collision (same name in 2+ servers)
  C002 — Tool name shadowing (similar names across servers)
  C003 — Cross-server data exfiltration chain
  C004 — Capability overlap (3+ servers with same capability)
  C005 — Permission gradient (read-only + write-capable mix)
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Any

from mcpradar.analyzer.report import ContextAnalysisReport, CrossFinding
from mcpradar.scanner.report import ScanReport, Severity, ToolInfo
from mcpradar.scanner.rules import _walk_schema_props

# ---------------------------------------------------------------------------
# Attack graph data models
# ---------------------------------------------------------------------------


@dataclass
class AttackGraphNode:
    """(sunucu, tool) ikilisi -- graf dugumu."""

    server: str
    tool_name: str
    tool: ToolInfo

    def __hash__(self) -> int:
        return hash((self.server, self.tool_name))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AttackGraphNode):
            return NotImplemented
        return self.server == other.server and self.tool_name == other.tool_name


@dataclass
class AttackGraphEdge:
    """Tip eslesmesi ile olusan yonlu kenar."""

    source: AttackGraphNode
    target: AttackGraphNode
    match_type: str  # "schema_type_match"
    shared_types: list[str]  # Eslesen JSON Schema tipleri


# ---------------------------------------------------------------------------
# C001 — Tool name collision
# ---------------------------------------------------------------------------


def _check_name_collisions(scans: list[ScanReport]) -> list[CrossFinding]:
    findings: list[CrossFinding] = []
    name_map: dict[str, list[str]] = defaultdict(list)

    for scan in scans:
        for tool in scan.tools:
            name_map[tool.name.lower()].append(scan.target)

    collisions = {k: v for k, v in name_map.items() if len(v) >= 2}
    for name, servers in collisions.items():
        findings.append(
            CrossFinding(
                rule_id="C001",
                title="Tool name collision across servers",
                description=(
                    f"Tool '{name}' exists in {len(servers)} servers: "
                    f"{', '.join(servers[:5])}. LLM may call the wrong one."
                ),
                severity=Severity.CRITICAL,
                servers=servers,
                detail={"tool_name": name, "server_count": len(servers)},
            )
        )

    return findings


# ---------------------------------------------------------------------------
# C002 — Tool name shadowing
# ---------------------------------------------------------------------------


def _check_shadowing(scans: list[ScanReport]) -> list[CrossFinding]:
    findings: list[CrossFinding] = []
    all_names: list[tuple[str, str]] = []
    for scan in scans:
        for tool in scan.tools:
            all_names.append((tool.name, scan.target))

    for i, (name_a, srv_a) in enumerate(all_names):
        for name_b, srv_b in all_names[i + 1 :]:
            if srv_a == srv_b:
                continue
            ratio = SequenceMatcher(None, name_a.lower(), name_b.lower()).ratio()
            if 0.75 <= ratio < 1.0:
                findings.append(
                    CrossFinding(
                        rule_id="C002",
                        title="Tool name shadowing",
                        description=(
                            f"'{name_a}' ({srv_a}) and '{name_b}' ({srv_b}) "
                            f"are {ratio:.0%} similar — LLM may confuse them."
                        ),
                        severity=Severity.HIGH,
                        servers=[srv_a, srv_b],
                        detail={"tool_a": name_a, "tool_b": name_b, "similarity": ratio},
                    )
                )

    return findings


# ---------------------------------------------------------------------------
# C003 — Cross-server data exfiltration chain
# ---------------------------------------------------------------------------

EXFIL_PATTERNS = [
    re.compile(p, re.I)
    for p in [
        r"\b(?:send|post|upload|publish|forward|share|transmit|exfiltrate)\b",
    ]
]
READ_PATTERNS = [
    re.compile(p, re.I)
    for p in [
        r"\b(?:read|get|fetch|download|retrieve|extract|access)\b.*\b(?:file|data|secret|key|token|password|email)\b",
    ]
]


def _check_exfiltration(scans: list[ScanReport]) -> list[CrossFinding]:
    findings: list[CrossFinding] = []
    readers: dict[str, list[str]] = defaultdict(list)  # server → tool names
    senders: dict[str, list[str]] = defaultdict(list)

    for scan in scans:
        for tool in scan.tools:
            text = f"{tool.name} {tool.description}"
            srv = scan.target
            for rp in READ_PATTERNS:
                if rp.search(text):
                    readers[srv].append(tool.name)
                    break
            for sp in EXFIL_PATTERNS:
                if sp.search(text):
                    senders[srv].append(tool.name)
                    break

    for reader_srv in readers:
        for sender_srv in senders:
            if reader_srv == sender_srv:
                continue
            findings.append(
                CrossFinding(
                    rule_id="C003",
                    title="Cross-server data exfiltration chain",
                    description=(
                        f"'{reader_srv}' reads data "
                        f"({', '.join(readers[reader_srv][:3])}), "
                        f"'{sender_srv}' sends out "
                        f"({', '.join(senders[sender_srv][:3])}) — "
                        f"possible exfiltration chain."
                    ),
                    severity=Severity.CRITICAL,
                    servers=[reader_srv, sender_srv],
                    detail={
                        "reader_tools": readers[reader_srv][:5],
                        "sender_tools": senders[sender_srv][:5],
                    },
                )
            )

    return findings


# ---------------------------------------------------------------------------
# C004 — Capability overlap
# ---------------------------------------------------------------------------

CAPABILITY_KEYWORDS = {
    "file_read": [
        r"\b(?:read_file|get_file|read.*file|file.*read)\b",
    ],
    "file_write": [
        r"\b(?:write_file|create_file|save.*file|file.*write|edit_file)\b",
    ],
    "web_fetch": [
        r"\b(?:fetch_url|http_get|web_request|curl|fetch.*url|url.*fetch)\b",
    ],
    "shell_exec": [
        r"\b(?:exec|eval|shell|bash|cmd|subprocess|command)\b",
    ],
    "database": [
        r"\b(?:sql|query|database|postgres|mysql|nosql|table)\b",
    ],
}


def _check_capability_overlap(scans: list[ScanReport]) -> list[CrossFinding]:
    findings: list[CrossFinding] = []

    for cap_name, patterns in CAPABILITY_KEYWORDS.items():
        servers_with_cap: list[str] = []
        for scan in scans:
            for tool in scan.tools:
                text = f"{tool.name} {tool.description}"
                if any(re.search(p, text, re.I) for p in patterns):
                    if scan.target not in servers_with_cap:
                        servers_with_cap.append(scan.target)
                    break

        if len(servers_with_cap) >= 3:
            findings.append(
                CrossFinding(
                    rule_id="C004",
                    title=f"Capability overload: {cap_name}",
                    description=(
                        f"{len(servers_with_cap)} servers expose '{cap_name}' "
                        f"capability — attack surface too wide."
                    ),
                    severity=Severity.MEDIUM,
                    servers=servers_with_cap,
                    detail={"capability": cap_name, "server_count": len(servers_with_cap)},
                )
            )

    return findings


# ---------------------------------------------------------------------------
# C005 — Permission gradient
# ---------------------------------------------------------------------------

WRITE_KEYWORDS = [
    re.compile(p, re.I)
    for p in [
        r"\b(?:write|create|delete|remove|modify|update|exec|run|spawn|shell|sudo)\b",
    ]
]


def _check_permission_gradient(scans: list[ScanReport]) -> list[CrossFinding]:
    findings: list[CrossFinding] = []
    read_only: list[str] = []
    write_capable: list[str] = []

    for scan in scans:
        has_write = False
        has_read = False
        for tool in scan.tools:
            text = f"{tool.name} {tool.description}"
            if any(r.search(text) for r in WRITE_KEYWORDS):
                has_write = True
            if re.search(r"\b(?:read|get|fetch|list|search|query)\b", text, re.I):
                has_read = True

        if has_write:
            write_capable.append(scan.target)
        elif has_read:
            read_only.append(scan.target)

    if read_only and write_capable:
        findings.append(
            CrossFinding(
                rule_id="C005",
                title="Permission gradient — read + write mix",
                description=(
                    f"Read-only servers ({', '.join(read_only[:5])}) coexist with "
                    f"write-capable servers ({', '.join(write_capable[:5])}). "
                    f"Prompt injection on read-only tools may hijack write access."
                ),
                severity=Severity.MEDIUM,
                servers=read_only + write_capable,
                detail={
                    "read_only": read_only[:10],
                    "write_capable": write_capable[:10],
                },
            )
        )

    return findings


# ---------------------------------------------------------------------------
# C006 — Attack path chain (schema type matching)
# ---------------------------------------------------------------------------


def _extract_schema_types(schema: dict[str, Any]) -> set[str]:
    """Walk all JSON Schema properties and collect their 'type' values."""
    types: set[str] = set()
    for _prop_path, prop_schema in _walk_schema_props(schema):
        type_val = prop_schema.get("type")
        if isinstance(type_val, str):
            types.add(type_val)
        elif isinstance(type_val, list):
            for t in type_val:
                if isinstance(t, str):
                    types.add(t)
    return types


def _build_attack_graph(
    scans: list[ScanReport],
) -> tuple[list[AttackGraphNode], list[AttackGraphEdge]]:
    """Construct attack graph from all tools across all servers."""
    nodes: list[AttackGraphNode] = []
    for scan in scans:
        for tool in scan.tools:
            nodes.append(AttackGraphNode(server=scan.target, tool_name=tool.name, tool=tool))

    edges: list[AttackGraphEdge] = []
    for i, node_a in enumerate(nodes):
        types_out = _extract_schema_types(node_a.tool.output_schema)
        if not types_out:
            continue
        for node_b in nodes[i + 1 :]:
            if node_a.server == node_b.server:
                continue
            types_in_b = _extract_schema_types(node_b.tool.input_schema)
            overlap = types_out & types_in_b
            if overlap:
                edges.append(
                    AttackGraphEdge(
                        source=node_a,
                        target=node_b,
                        match_type="schema_type_match",
                        shared_types=sorted(overlap),
                    )
                )
            # Also check reverse direction
            types_in_a = _extract_schema_types(node_a.tool.input_schema)
            types_out_b = _extract_schema_types(node_b.tool.output_schema)
            overlap_rev = types_out_b & types_in_a
            if overlap_rev:
                edges.append(
                    AttackGraphEdge(
                        source=node_b,
                        target=node_a,
                        match_type="schema_type_match",
                        shared_types=sorted(overlap_rev),
                    )
                )

    return nodes, edges


def _check_attack_path_chain(
    scans: list[ScanReport],
    nodes: list[AttackGraphNode],
    edges: list[AttackGraphEdge],
) -> list[CrossFinding]:
    """C006: Detect multi-step attack chains via schema type matching."""
    findings: list[CrossFinding] = []

    # Build adjacency list
    graph: dict[AttackGraphNode, list[AttackGraphNode]] = defaultdict(list)
    for edge in edges:
        graph[edge.source].append(edge.target)

    # BFS from each node to discover chains
    all_chains: set[tuple[str, ...]] = set()
    chain_details: list[tuple[tuple[str, ...], list[AttackGraphNode]]] = []

    for start_node in nodes:
        if start_node not in graph:
            continue
        queue: deque[tuple[AttackGraphNode, tuple[AttackGraphNode, ...]]] = deque()
        queue.append((start_node, (start_node,)))

        while queue:
            current, path = queue.popleft()
            if len(path) > 5:  # max_depth=5
                continue

            for neighbor in graph.get(current, []):
                if neighbor in path:  # cycle detection
                    continue
                new_path = path + (neighbor,)
                if len(new_path) >= 2:
                    dedup_key = tuple(sorted(n.tool_name for n in new_path))
                    if dedup_key not in all_chains:
                        all_chains.add(dedup_key)
                        chain_details.append((dedup_key, list(new_path)))
                queue.append((neighbor, new_path))

    # Classify each chain
    shell_exec_patterns = [
        re.compile(p, re.I)
        for p in [
            r"\b(?:exec|eval|shell|bash|cmd|subprocess|command|spawn|sudo)\b",
        ]
    ]

    for _dedup_key, path_nodes in chain_details:
        source = path_nodes[0]
        last = path_nodes[-1]
        source_text = f"{source.tool_name} {source.tool.description}"
        last_text = f"{last.tool_name} {last.tool.description}"

        is_reader = any(p.search(source_text) for p in READ_PATTERNS)
        is_sender = any(p.search(last_text) for p in EXFIL_PATTERNS)
        source_has_input = any(kw in source.tool.description.lower() for kw in ("input", "receive"))
        last_is_exec = any(p.search(last_text) for p in shell_exec_patterns)

        servers = list({n.server for n in path_nodes})
        path_desc = " -> ".join(f"{n.server}:{n.tool_name}" for n in path_nodes)

        if is_reader and is_sender:
            findings.append(
                CrossFinding(
                    rule_id="C006",
                    title="Veri sizdirma zinciri (Attack path chain)",
                    description=f"Veri sizdirma zinciri: {path_desc}",
                    severity=Severity.CRITICAL,
                    servers=servers,
                    detail={
                        "chain_length": len(path_nodes),
                        "path": [f"{n.server}:{n.tool_name}" for n in path_nodes],
                        "chain_type": "exfiltration",
                    },
                )
            )
        elif source_has_input and last_is_exec:
            findings.append(
                CrossFinding(
                    rule_id="C006",
                    title="Komut enjeksiyon zinciri (Attack path chain)",
                    description=f"Komut enjeksiyon zinciri: {path_desc}",
                    severity=Severity.CRITICAL,
                    servers=servers,
                    detail={
                        "chain_length": len(path_nodes),
                        "path": [f"{n.server}:{n.tool_name}" for n in path_nodes],
                        "chain_type": "command_injection",
                    },
                )
            )
        elif len(path_nodes) >= 3:
            findings.append(
                CrossFinding(
                    rule_id="C006",
                    title=f"Uzun saldiri zinciri ({len(path_nodes)} adim)",
                    description=f"Uzun saldiri zinciri ({len(path_nodes)} adim): {path_desc}",
                    severity=Severity.HIGH,
                    servers=servers,
                    detail={
                        "chain_length": len(path_nodes),
                        "path": [f"{n.server}:{n.tool_name}" for n in path_nodes],
                        "chain_type": "long_chain",
                    },
                )
            )
        elif len(path_nodes) == 2:
            findings.append(
                CrossFinding(
                    rule_id="C006",
                    title="Kisa saldiri zinciri",
                    description=f"Kisa saldiri zinciri: {path_desc}",
                    severity=Severity.MEDIUM,
                    servers=servers,
                    detail={
                        "chain_length": 2,
                        "path": [f"{n.server}:{n.tool_name}" for n in path_nodes],
                        "chain_type": "short_chain",
                    },
                )
            )

    return findings


# ---------------------------------------------------------------------------
# C007 — Privilege escalation
# ---------------------------------------------------------------------------


def _check_privilege_escalation(
    scans: list[ScanReport],
    nodes: list[AttackGraphNode],
    edges: list[AttackGraphEdge],
) -> list[CrossFinding]:
    """C007: Detect privilege escalation from read-only to write/exec tools."""
    findings: list[CrossFinding] = []

    read_name_pat = re.compile(r"^(get|list|read|fetch|search|query|browse|show|describe)", re.I)

    read_only_nodes: list[AttackGraphNode] = []
    write_exec_nodes: list[AttackGraphNode] = []

    for node in nodes:
        text = f"{node.tool_name} {node.tool.description}"
        has_write = any(p.search(text) for p in WRITE_KEYWORDS)
        has_exec = any(kw in text.lower() for kw in ("exec", "shell", "spawn", "sudo", "cmd"))

        if has_write or has_exec:
            write_exec_nodes.append(node)
        elif read_name_pat.search(node.tool_name) and not has_write:
            read_only_nodes.append(node)

    # Build adjacency list
    graph: dict[AttackGraphNode, list[AttackGraphNode]] = defaultdict(list)
    for edge in edges:
        graph[edge.source].append(edge.target)

    seen_pairs: set[tuple[str, str, str, str]] = set()

    for read_node in read_only_nodes:
        for write_node in write_exec_nodes:
            if read_node.server == write_node.server:
                continue

            pair_key = (
                read_node.server,
                read_node.tool_name,
                write_node.server,
                write_node.tool_name,
            )
            if pair_key in seen_pairs:
                continue

            # Check direct edge
            if write_node in graph.get(read_node, []):
                seen_pairs.add(pair_key)
                findings.append(
                    CrossFinding(
                        rule_id="C007",
                        title="Dogrudan yetki yukseltme (Privilege escalation)",
                        description=(
                            f"Salt okunur '{read_node.server}:{read_node.tool_name}' araci "
                            f"dogrudan yazma/yurutme yetkili "
                            f"'{write_node.server}:{write_node.tool_name}' "
                            f"aracina baglaniyor -- yetki yukseltme riski."
                        ),
                        severity=Severity.CRITICAL,
                        servers=[read_node.server, write_node.server],
                        detail={
                            "read_tool": f"{read_node.server}:{read_node.tool_name}",
                            "write_tool": f"{write_node.server}:{write_node.tool_name}",
                            "escalation_type": "direct",
                        },
                    )
                )
                continue

            # Check multi-step path via BFS (max_depth=3)
            queue: deque[tuple[AttackGraphNode, list[AttackGraphNode]]] = deque()
            queue.append((read_node, [read_node]))
            found_path = False

            while queue and not found_path:
                current, path = queue.popleft()
                if len(path) > 3:
                    continue

                for neighbor in graph.get(current, []):
                    if neighbor in path:
                        continue
                    if neighbor == write_node:
                        found_path = True
                        full_path = path + [neighbor]
                        path_desc = " -> ".join(f"{n.server}:{n.tool_name}" for n in full_path)
                        seen_pairs.add(pair_key)
                        findings.append(
                            CrossFinding(
                                rule_id="C007",
                                title="Zincirleme yetki yukseltme (Privilege escalation chain)",
                                description=(
                                    f"Salt okunur '{read_node.server}:{read_node.tool_name}' "
                                    f"aracindan yazma/yurutme yetkili "
                                    f"'{write_node.server}:{write_node.tool_name}' "
                                    f"aracina {len(path)} adimda ulasilabiliyor: {path_desc}"
                                ),
                                severity=Severity.CRITICAL,
                                servers=list({n.server for n in [read_node, write_node] + path}),
                                detail={
                                    "read_tool": f"{read_node.server}:{read_node.tool_name}",
                                    "write_tool": f"{write_node.server}:{write_node.tool_name}",
                                    "escalation_type": "chain",
                                    "path_length": len(path),
                                    "path": [f"{n.server}:{n.tool_name}" for n in full_path],
                                },
                            )
                        )
                        break
                    new_path = path + [neighbor]
                    queue.append((neighbor, new_path))

    return findings


# ---------------------------------------------------------------------------
# Risk score & DOT graph
# ---------------------------------------------------------------------------


def _calculate_risk_score(report: ContextAnalysisReport) -> int:
    """Calculate aggregate risk score (0--100) from all cross-server findings."""
    score = 0
    for finding in report.findings:
        weight = {"critical": 25, "high": 15, "medium": 8, "low": 3}[finding.severity.value]
        score += weight
    server_factor = min(report.server_count / 5.0, 1.0)
    score += int(10 * server_factor)
    tools_per_server = report.tool_count / max(report.server_count, 1)
    if tools_per_server > 20:
        score += 10
    elif tools_per_server > 10:
        score += 5
    return min(score, 100)


def _build_dot(nodes: list[AttackGraphNode], edges: list[AttackGraphEdge]) -> str:
    """Build GraphViz DOT-format attack graph string."""
    lines = ["digraph AttackGraph {", "  rankdir=LR;", "  node [shape=box, style=filled];"]

    # Group nodes by server
    servers: dict[str, list[AttackGraphNode]] = defaultdict(list)
    for node in nodes:
        servers[node.server].append(node)

    server_colors = [
        "#e8eaf6",
        "#fce4ec",
        "#e8f5e9",
        "#fff3e0",
        "#e0f7fa",
        "#f3e5f5",
        "#efebe9",
        "#e0e0e0",
    ]

    read_name_pat = re.compile(r"^(get|list|read|fetch|search|query|browse|show|describe)", re.I)

    def _sanitize(s: str) -> str:
        for ch in ":/.- ":
            s = s.replace(ch, "_")
        return s

    for idx, (server, server_nodes) in enumerate(sorted(servers.items())):
        color = server_colors[idx % len(server_colors)]
        server_id = _sanitize(server)
        lines.append(f"  subgraph cluster_{server_id} {{")
        lines.append(f'    label="{server}";')
        lines.append("    style=filled;")
        lines.append(f'    fillcolor="{color}";')

        for node in server_nodes:
            node_id = _sanitize(f"{server}_{node.tool_name}")
            text = f"{node.tool_name} {node.tool.description}"

            has_write = any(p.search(text) for p in WRITE_KEYWORDS)
            has_exec = any(kw in text.lower() for kw in ("exec", "shell", "spawn", "sudo", "cmd"))
            is_read = bool(read_name_pat.search(node.tool_name)) and not has_write

            if has_write or has_exec:
                fillcolor = "#ffcdd2"  # red
            elif is_read:
                fillcolor = "#c8e6c9"  # green
            else:
                fillcolor = "#ffffff"  # white

            lines.append(f'    {node_id} [label="{node.tool_name}", fillcolor="{fillcolor}"];')

        lines.append("  }")

    # Edges
    for edge in edges:
        src_id = _sanitize(f"{edge.source.server}_{edge.source.tool_name}")
        tgt_id = _sanitize(f"{edge.target.server}_{edge.target.tool_name}")
        types_str = ", ".join(edge.shared_types)
        lines.append(f'  "{src_id}" -> "{tgt_id}" [label="{types_str}"];')

    lines.append("}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


class ContextAnalyzer:
    def __init__(self, scans: list[ScanReport], deep: bool = False) -> None:
        self.scans = scans
        self.deep = deep

    def analyze(self) -> ContextAnalysisReport:
        report = ContextAnalysisReport(
            server_count=len(self.scans),
            tool_count=sum(len(s.tools) for s in self.scans),
            scans=self.scans,
        )

        for check in [
            _check_name_collisions,
            _check_shadowing,
            _check_exfiltration,
            _check_capability_overlap,
            _check_permission_gradient,
        ]:
            for f in check(self.scans):
                report.add_finding(f)

        # Deep analysis: attack graph, path chains, privilege escalation
        if self.deep:
            nodes, edges = _build_attack_graph(self.scans)
            for f in _check_attack_path_chain(self.scans, nodes, edges):
                report.add_finding(f)
            for f in _check_privilege_escalation(self.scans, nodes, edges):
                report.add_finding(f)
            report.attack_graph_dot = _build_dot(nodes, edges)

        # Risk score (always calculated)
        report.risk_score = _calculate_risk_score(report)

        # Build risk graph
        for f in report.findings:
            for i, srv_a in enumerate(f.servers):
                for srv_b in f.servers[i + 1 :]:
                    report.risk_graph.setdefault(srv_a, [])
                    if srv_b not in report.risk_graph[srv_a]:
                        report.risk_graph[srv_a].append(srv_b)

        return report
