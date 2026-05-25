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
from collections import defaultdict
from difflib import SequenceMatcher

from mcpradar.analyzer.report import ContextAnalysisReport, CrossFinding
from mcpradar.scanner.report import ScanReport, Severity

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
# Analyzer
# ---------------------------------------------------------------------------


class ContextAnalyzer:
    def __init__(self, scans: list[ScanReport]) -> None:
        self.scans = scans

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

        # Build risk graph
        for f in report.findings:
            for i, srv_a in enumerate(f.servers):
                for srv_b in f.servers[i + 1 :]:
                    report.risk_graph.setdefault(srv_a, [])
                    if srv_b not in report.risk_graph[srv_a]:
                        report.risk_graph[srv_a].append(srv_b)

        return report
