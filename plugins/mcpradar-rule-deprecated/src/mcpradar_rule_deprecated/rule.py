"""Detect deprecated/legacy MCP tool patterns."""

from __future__ import annotations

import re

from mcpradar.scanner.report import Finding, Severity, ToolInfo
from mcpradar.scanner.rules import Rule

_DEPRECATED_PATTERNS = [
    (re.compile(r"\bv1\b", re.I), "v1 API reference"),
    (re.compile(r"\bdeprecated\b", re.I), "explicit deprecated mention"),
    (re.compile(r"\blegacy\b", re.I), "legacy reference"),
    (re.compile(r"\bobsolete\b", re.I), "obsolete reference"),
    (re.compile(r"/v0/|/v1/|api/v1"), "versioned API path"),
]


class DeprecatedPatternRule(Rule):
    rule_id = "X002"
    title = "Deprecated/legacy API pattern tespiti"
    severity = Severity.LOW

    def check(self, tool: ToolInfo) -> list[Finding]:
        findings: list[Finding] = []
        text = f"{tool.name} {tool.description} {str(tool.input_schema)}"
        for pattern, label in _DEPRECATED_PATTERNS:
            for m in pattern.finditer(text):
                findings.append(
                    self._finding(
                        tool.name,
                        f"Deprecated pattern: '{label}'",
                        severity=Severity.LOW,
                        pattern=label,
                        matched=m.group()[:80],
                    )
                )
        return findings
