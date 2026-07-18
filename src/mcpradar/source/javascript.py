"""JavaScript/TypeScript source analysis with an optional Semgrep backend."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from mcpradar.scanner.report import Finding, Severity

_JS_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"})
_TROJAN = re.compile("[\u202a-\u202e\u2066-\u2069\u200b-\u200f\u2060\ufeff]")
_DYNAMIC_FETCH = re.compile(
    r"(?:fetch|axios\.(?:get|post|request)|https?\.request)\s*\(\s*(?!['\"`])",
    re.I,
)
_DYNAMIC_EXEC = re.compile(r"(?:\beval\s*\(|new\s+Function\s*\()", re.I)
_SHELL_EXEC = re.compile(
    r"(?:child_process\.)?(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?!['\"`])",
    re.I,
)
_SQL_TEMPLATE = re.compile(r"\b(?:query|execute)\s*\(\s*`[^`]*\$\{", re.I)
_TOKEN_FORWARD = re.compile(
    r"(?:authorization|access[_-]?token|bearer).{0,120}(?:fetch|axios|request)\s*\(",
    re.I,
)
_RAW_FETCH_RETURN = re.compile(r"return\s+(?:await\s+)?(?:fetch|axios\.)", re.I)


class JavaScriptAnalyzer:
    """Analyze JS/TS without executing project code."""

    def analyze_file(self, path: Path) -> list[Finding]:
        if path.suffix.lower() not in _JS_SUFFIXES:
            return []
        semgrep = shutil.which("semgrep")
        if semgrep:
            findings = self._analyze_semgrep(path, semgrep)
            if findings is not None:
                return findings + self._unicode_findings(path)
        return self._analyze_builtin(path)

    def _analyze_semgrep(self, path: Path, executable: str) -> list[Finding] | None:
        config = Path(__file__).with_name("semgrep-js.yml")
        try:
            result = subprocess.run(
                [
                    executable,
                    "scan",
                    "--json",
                    "--quiet",
                    "--config",
                    str(config),
                    str(path),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode not in {0, 1}:
            return None
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return None
        findings: list[Finding] = []
        for match in payload.get("results", []):
            check_id = str(match.get("check_id", "")).rsplit(".", 1)[-1]
            metadata = match.get("extra", {}).get("metadata", {})
            severity = str(metadata.get("mcpradar_severity", "medium"))
            findings.append(
                self._finding(
                    check_id,
                    str(match.get("extra", {}).get("message", "JavaScript security finding")),
                    Severity.from_str(severity),
                    path,
                    int(match.get("start", {}).get("line", 1)),
                )
            )
        return findings

    def _analyze_builtin(self, path: Path) -> list[Finding]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        findings = self._unicode_findings(path, text)
        patterns = (
            ("S001", "Cloud metadata SSRF endpoint", Severity.CRITICAL, "169.254.169.254"),
            ("S001", "Cloud metadata SSRF endpoint", Severity.CRITICAL, "metadata.google.internal"),
        )
        for rule_id, title, severity, literal in patterns:
            for line_number, line in enumerate(text.splitlines(), 1):
                if literal in line:
                    findings.append(self._finding(rule_id, title, severity, path, line_number))
        regexes = (
            ("S002", "Dynamic outbound URL", Severity.MEDIUM, _DYNAMIC_FETCH),
            ("S004", "Dynamic JavaScript execution", Severity.CRITICAL, _DYNAMIC_EXEC),
            ("S005", "SQL query built from template interpolation", Severity.HIGH, _SQL_TEMPLATE),
            ("S006", "Dynamic shell command execution", Severity.CRITICAL, _SHELL_EXEC),
            ("S010", "Authorization token forwarded downstream", Severity.HIGH, _TOKEN_FORWARD),
            (
                "S011",
                "Raw fetched content returned to the agent",
                Severity.MEDIUM,
                _RAW_FETCH_RETURN,
            ),
        )
        for rule_id, title, severity, pattern in regexes:
            for match in pattern.finditer(text):
                line_number = text.count("\n", 0, match.start()) + 1
                findings.append(self._finding(rule_id, title, severity, path, line_number))
        for match in re.finditer(r"(?:listen|hostname|host)\s*[:=(,]\s*['\"]0\.0\.0\.0", text):
            line_number = text.count("\n", 0, match.start()) + 1
            findings.append(
                self._finding(
                    "S009",
                    "Server binds to all interfaces",
                    Severity.MEDIUM,
                    path,
                    line_number,
                )
            )
        return _dedupe(findings)

    def _unicode_findings(self, path: Path, text: str | None = None) -> list[Finding]:
        if text is None:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return []
        return [
            self._finding(
                "S008",
                "Trojan Source Unicode control character",
                Severity.CRITICAL,
                path,
                text.count("\n", 0, match.start()) + 1,
            )
            for match in _TROJAN.finditer(text)
        ]

    @staticmethod
    def _finding(
        rule_id: str, title: str, severity: Severity, path: Path, line_number: int
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            title=title,
            description=f"{title} detected in JavaScript/TypeScript source",
            severity=severity,
            target=f"{path}:{line_number}",
            location="source",
            detail={"line": line_number, "language": "javascript"},
        )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str]] = set()
    output: list[Finding] = []
    for finding in findings:
        key = finding.rule_id, finding.target
        if key not in seen:
            seen.add(key)
            output.append(finding)
    return output
