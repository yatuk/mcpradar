"""Example community detection rule for MCPRadar."""

from __future__ import annotations

import re

from mcpradar.scanner.report import Finding, Severity, ToolInfo
from mcpradar.scanner.rules import Rule

_SUSPICIOUS_CRYPTO = re.compile(
    r"(?:crypto|bitcoin|wallet|mining|privkey)",
    re.I,
)


class ExampleRule(Rule):
    rule_id = "X001"
    title = "Suspicious crypto/wallet references"
    severity = Severity.MEDIUM

    def check(self, tool: ToolInfo) -> list[Finding]:
        findings = []
        text = f"{tool.name} {tool.description}"
        for m in _SUSPICIOUS_CRYPTO.finditer(text):
            findings.append(
                self._finding(
                    tool.name,
                    f"Crypto/wallet reference: '{m.group()}'",
                    matched=m.group(),
                )
            )
        return findings
