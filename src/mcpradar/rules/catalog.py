"""Single source of truth for MCPRadar rule metadata."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleDescriptor:
    id: str
    title: str
    severity: str
    confidence: float
    help: str
    surfaces: tuple[str, ...]
    cwe: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    status: str = "stable"
    protocol_profiles: tuple[str, ...] = ()

    @property
    def help_uri(self) -> str:
        return (
            f"https://github.com/yatuk/mcpradar/blob/main/docs/detection-rules.md#{self.id.lower()}"
        )


def _rule(
    rule_id: str,
    title: str,
    severity: str,
    confidence: float,
    help_text: str,
    surfaces: tuple[str, ...],
    *,
    cwe: tuple[str, ...] = (),
    owasp: tuple[str, ...] = (),
    status: str = "stable",
    protocol_profiles: tuple[str, ...] = (),
) -> RuleDescriptor:
    return RuleDescriptor(
        rule_id,
        title,
        severity,
        confidence,
        help_text,
        surfaces,
        cwe,
        owasp,
        status,
        protocol_profiles,
    )


_RULES = (
    _rule(
        "R001",
        "Dangerous tool name",
        "critical",
        0.9,
        "Tool name matches a dangerous system command.",
        ("tool",),
        cwe=("CWE-78",),
    ),
    _rule(
        "R101",
        "Hidden Unicode character",
        "high",
        0.9,
        "Zero-width or bidirectional Unicode can conceal tool instructions.",
        ("tool", "prompt", "resource", "resource_template", "server_instructions"),
        cwe=("CWE-116",),
    ),
    _rule(
        "R102",
        "Prompt injection pattern",
        "high",
        0.7,
        "Instruction-override language appears in MCP-controlled metadata.",
        ("tool", "prompt", "resource", "resource_template", "server_instructions"),
        owasp=("MCP05",),
    ),
    _rule(
        "R103",
        "Encoded content blob",
        "medium",
        0.5,
        "Large encoded content can conceal instructions or payloads.",
        ("tool", "prompt", "resource", "resource_template", "server_instructions"),
    ),
    _rule(
        "R104",
        "Hidden HTML or Markdown content",
        "high",
        0.7,
        "Markup attempts to hide agent-visible content from users.",
        ("tool", "prompt", "resource", "resource_template", "server_instructions"),
        cwe=("CWE-79",),
    ),
    _rule(
        "R105",
        "Permission scope mismatch",
        "medium",
        0.5,
        "The declared tool purpose conflicts with its described capability scope.",
        ("tool",),
    ),
    _rule(
        "R106",
        "Secret credential exposure",
        "critical",
        0.9,
        "A credential, token, or connection secret appears in metadata.",
        ("tool", "prompt", "resource", "server_instructions"),
        cwe=("CWE-798",),
    ),
    _rule(
        "R107",
        "Command injection in parameters",
        "critical",
        0.9,
        "Tool parameter defaults or constraints contain command-injection payloads.",
        ("tool",),
        cwe=("CWE-78",),
    ),
    _rule(
        "R108",
        "Supply-chain behavior indicator",
        "medium",
        0.7,
        "Metadata requests dynamic installation or unverified code download.",
        ("tool", "prompt", "server_instructions"),
        cwe=("CWE-494",),
    ),
    _rule(
        "R109",
        "Schema poisoning indicator",
        "high",
        0.7,
        "Input schema structure weakens validation or hides unsafe inputs.",
        ("tool",),
        cwe=("CWE-20",),
    ),
    _rule(
        "R110",
        "Server identity or version anomaly",
        "high",
        0.5,
        "Fingerprint drift indicates rollback, replacement, or unexpected capability change.",
        ("fingerprint",),
    ),
    _rule(
        "R111",
        "Insecure transport",
        "high",
        0.7,
        "Transport lacks current TLS and certificate protections.",
        ("transport",),
        cwe=("CWE-319",),
    ),
    _rule(
        "R112",
        "Authorization hardening",
        "high",
        0.7,
        "OAuth metadata or negotiated protocol violates MCP authorization requirements.",
        ("auth", "transport"),
        cwe=("CWE-346",),
        protocol_profiles=("2025-11-25", "2026-07-28"),
    ),
    _rule(
        "R113",
        "Path traversal risk",
        "medium",
        0.7,
        "Path-like parameters lack traversal and boundary constraints.",
        ("tool",),
        cwe=("CWE-22", "CWE-59"),
    ),
    _rule(
        "R114",
        "Unbounded input",
        "low",
        0.7,
        "String or collection input lacks size or content bounds.",
        ("tool",),
        cwe=("CWE-400",),
    ),
    _rule(
        "C001",
        "Cross-server tool collision",
        "critical",
        0.7,
        "Multiple servers expose the same tool name.",
        ("context",),
    ),
    _rule(
        "C002",
        "Cross-server tool shadowing",
        "high",
        0.5,
        "Similar tool names across servers can misroute agent calls.",
        ("context",),
    ),
    _rule(
        "C003",
        "Cross-server exfiltration chain",
        "critical",
        0.7,
        "Combined server capabilities form a data-exfiltration path.",
        ("context",),
    ),
    _rule(
        "C004",
        "Cross-server capability overlap",
        "medium",
        0.5,
        "Many servers expose overlapping sensitive capabilities.",
        ("context",),
    ),
    _rule(
        "C005",
        "Cross-server permission gradient",
        "high",
        0.5,
        "Read and write capabilities combine into an escalation path.",
        ("context",),
    ),
    _rule(
        "C006",
        "Cross-server attack path",
        "high",
        0.7,
        "Schema-compatible tools form a multi-server attack chain.",
        ("context",),
    ),
    _rule(
        "C007",
        "Cross-server privilege escalation",
        "critical",
        0.7,
        "Read-only output feeds a write or execution sink.",
        ("context",),
    ),
    _rule(
        "S001",
        "Cloud metadata SSRF",
        "critical",
        0.9,
        "Source references a cloud metadata endpoint.",
        ("source",),
        cwe=("CWE-918",),
    ),
    _rule(
        "S002",
        "Dynamic outbound URL",
        "medium",
        0.7,
        "A network sink receives a non-constant URL without proven validation.",
        ("source",),
        cwe=("CWE-918",),
    ),
    _rule(
        "S003",
        "Unsafe deserialization",
        "high",
        0.9,
        "Source uses an unsafe object deserializer.",
        ("source",),
        cwe=("CWE-502",),
    ),
    _rule(
        "S004",
        "Dynamic code execution",
        "critical",
        0.9,
        "Source executes non-literal code.",
        ("source",),
        cwe=("CWE-95",),
    ),
    _rule(
        "S005",
        "SQL injection",
        "high",
        0.9,
        "SQL text is assembled from dynamic string content.",
        ("source",),
        cwe=("CWE-89",),
    ),
    _rule(
        "S006",
        "Shell command execution",
        "high",
        0.9,
        "Source executes a dynamic command through a shell.",
        ("source",),
        cwe=("CWE-78",),
    ),
    _rule(
        "S007",
        "Description-code inconsistency",
        "high",
        0.5,
        "A read-only description conflicts with filesystem or execution behavior.",
        ("source",),
    ),
    _rule(
        "S008",
        "Trojan Source Unicode",
        "critical",
        0.9,
        "Source contains bidirectional or invisible Unicode controls.",
        ("source",),
        cwe=("CWE-116",),
    ),
    _rule(
        "S009",
        "Unrestricted network bind",
        "medium",
        0.9,
        "Server source binds to all network interfaces.",
        ("source",),
        cwe=("CWE-668",),
    ),
    _rule(
        "S010",
        "Token passthrough",
        "high",
        0.7,
        "Caller authorization is forwarded to a downstream service.",
        ("source",),
        cwe=("CWE-441",),
    ),
    _rule(
        "S011",
        "Tool-output injection",
        "medium",
        0.5,
        "Untrusted fetched content is returned directly to the agent.",
        ("source",),
        owasp=("MCP05",),
    ),
    _rule(
        "M001",
        "Download-to-shell config RCE",
        "critical",
        0.7,
        "A config command pipes a network download to a shell.",
        ("config",),
        cwe=("CWE-494",),
    ),
    _rule(
        "M002",
        "Encoded config RCE",
        "critical",
        0.7,
        "A config command decodes and executes an encoded payload.",
        ("config",),
        cwe=("CWE-506",),
    ),
    _rule(
        "M003",
        "Credential exfiltration command",
        "critical",
        0.7,
        "A config command reads credential files and sends data externally.",
        ("config",),
        cwe=("CWE-200",),
    ),
    _rule(
        "M004",
        "Known collector exfiltration",
        "high",
        0.7,
        "A config command sends data to a known collection endpoint.",
        ("config",),
    ),
    _rule(
        "M005",
        "Reverse shell",
        "critical",
        0.7,
        "A config command opens an interactive reverse shell.",
        ("config",),
        cwe=("CWE-78",),
    ),
    _rule(
        "M006",
        "Over-broad agent permission",
        "high",
        0.7,
        "Agent configuration auto-approves a broad command or tool class.",
        ("config",),
        cwe=("CWE-250",),
    ),
    _rule(
        "M007",
        "Destructive launch command",
        "high",
        0.7,
        "MCP server configuration contains a destructive launch command.",
        ("config",),
        cwe=("CWE-78",),
    ),
    _rule(
        "D001",
        "Known-vulnerable dependency",
        "medium",
        0.9,
        "A target dependency matches an authoritative OSV advisory.",
        ("dependency",),
        cwe=("CWE-1395",),
    ),
    _rule(
        "T001",
        "Package typosquatting",
        "high",
        0.7,
        "A launched package name is suspiciously similar to a known MCP package.",
        ("config", "dependency"),
        cwe=("CWE-506",),
    ),
)

RULE_CATALOG: dict[str, RuleDescriptor] = {descriptor.id: descriptor for descriptor in _RULES}


def descriptor_for(rule_id: str) -> RuleDescriptor | None:
    return RULE_CATALOG.get(rule_id)


def render_markdown() -> str:
    """Render the human-facing detection-rule catalog."""
    lines = [
        "# Detection rules",
        "",
        "This file is generated from `mcpradar.rules.catalog`; edit the catalog, not this file.",
        "",
        "Confidence estimates detection specificity (not impact). Protocol profiles are "
        "listed only when a rule is profile-specific.",
        "",
        "| ID | Title | Severity | Confidence | Status | Surfaces | CWE | OWASP |",
        "|---|---|---|---:|---|---|---|---|",
    ]
    for descriptor in RULE_CATALOG.values():
        lines.append(
            "| {id} | {title} | {severity} | {confidence:.1f} | {status} | {surfaces} | "
            "{cwe} | {owasp} |".format(
                id=descriptor.id,
                title=descriptor.title,
                severity=descriptor.severity,
                confidence=descriptor.confidence,
                status=descriptor.status,
                surfaces=", ".join(descriptor.surfaces),
                cwe=", ".join(descriptor.cwe),
                owasp=", ".join(descriptor.owasp),
            )
        )
    lines.extend(["", "## Rule details", ""])
    for descriptor in RULE_CATALOG.values():
        lines.extend(
            [
                f"### {descriptor.id} — {descriptor.title}",
                "",
                descriptor.help,
                "",
                f"- Severity: `{descriptor.severity}`",
                f"- Confidence: `{descriptor.confidence:.1f}`",
                f"- Surfaces: {', '.join(f'`{item}`' for item in descriptor.surfaces)}",
                f"- CWE: {', '.join(descriptor.cwe) or 'not assigned'}",
                f"- OWASP MCP: {', '.join(descriptor.owasp) or 'not assigned'}",
                f"- Protocol profiles: {', '.join(descriptor.protocol_profiles) or 'all'}",
                "",
            ]
        )
    return "\n".join(lines)
