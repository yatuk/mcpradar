"""MCP / agent config poisoning scanner.

Rule IDs use the ``M`` (MCP-config) namespace:

- M001  Download-to-shell RCE (curl|bash) in a config command
- M002  base64-decode-to-shell (obfuscated RCE)
- M003  Credential-file read + network egress (exfiltration)
- M004  Exfiltration to a known collector / paste host
- M005  Reverse shell
- M006  Over-broad agent permission (Bash(*), bypassPermissions)
- M007  Dangerous MCP server launch command (rm -rf, mkfs, shutdown …)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcpradar.scanner.report import Finding, Severity

# Config filenames that declare MCP servers or agent hooks/permissions.
_CONFIG_NAMES = (
    "claude_desktop_config.json",
    ".mcp.json",
    "mcp.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".gemini/settings.json",
    ".windsurf/mcp.json",
)

_SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build"}


@dataclass(frozen=True)
class _Rule:
    rule_id: str
    title: str
    severity: Severity
    pattern: re.Pattern[str]
    message: str


# Command-string poisoning signatures (modeled on real hook/config abuse).
_COMMAND_RULES: tuple[_Rule, ...] = (
    _Rule(
        "M001",
        "Download-to-shell RCE in config command",
        Severity.CRITICAL,
        re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba)?sh\b"),
        "Config command pipes a network download straight into a shell (curl|bash)",
    ),
    _Rule(
        "M002",
        "base64-decode-to-shell (obfuscated RCE)",
        Severity.CRITICAL,
        re.compile(
            r"base64\s+(?:-d|--decode|-D)\b[^\n]*\|\s*(?:ba)?sh\b"
            r"|\|\s*base64\s+(?:-d|--decode)\b[^\n]*\|\s*(?:ba)?sh\b"
            r"|(?:eval|exec)\b[^\n]*base64\s+(?:-d|--decode)",
            re.I,
        ),
        "Config command decodes base64 and executes it (obfuscated RCE)",
    ),
    _Rule(
        "M003",
        "Credential read + network egress (exfiltration)",
        Severity.CRITICAL,
        re.compile(
            r"(?:~/?\.ssh/|/\.ssh/id_|\.aws/credentials|\.aws/config|\.env\b|"
            r"\.npmrc|\.config/gh/|\.docker/config\.json|\.netrc)[^\n]*"
            r"(?:curl|wget|\bnc\b|/dev/tcp|invoke-?webrequest|\biwr\b)"
            r"|(?:curl|wget|\bnc\b|/dev/tcp|invoke-?webrequest|\biwr\b)[^\n]*"
            r"(?:~/?\.ssh/|/\.ssh/id_|\.aws/credentials|\.env\b|\.npmrc|\.config/gh/|\.netrc)",
            re.I,
        ),
        "Config command reads credential files and sends them over the network",
    ),
    _Rule(
        "M004",
        "Exfiltration to a known collector host",
        Severity.HIGH,
        re.compile(
            r"(?:curl|wget|invoke-?webrequest|\biwr\b)\b[^\n]*\b"
            r"(?:pastebin\.com|webhook\.site|requestbin|ngrok\.io|burpcollaborator|"
            r"interactsh|oast\.|\.onion)\b",
            re.I,
        ),
        "Config command exfiltrates to an external collector / paste host",
    ),
    _Rule(
        "M005",
        "Reverse shell",
        Severity.CRITICAL,
        re.compile(
            r"/dev/tcp/\d"
            r"|\b(?:ba)?sh\s+-i\b[^\n]*(?:/dev/tcp|\bnc\b|>&)"
            r"|\bnc\b[^\n]*\s-e\b"
            r"|mkfifo\b[^\n]*\|[^\n]*\b(?:ba)?sh\b"
            r"|python[0-9.]*\b[^\n]*socket[^\n]*subprocess",
            re.I,
        ),
        "Config command opens a reverse shell",
    ),
    _Rule(
        "M007",
        "Dangerous MCP server launch command",
        Severity.HIGH,
        re.compile(
            r"\brm\s+-[a-z]*r[a-z]*f\b|\bmkfs\b|\bshutdown\b|\breboot\b"
            r"|\bdd\s+if=|:\(\)\s*\{|\bchmod\s+-R\s+777\b",
            re.I,
        ),
        "MCP server is launched via a destructive shell command",
    ),
)

# Over-broad permission grants in agent settings files.
_BAD_PERMISSIONS = re.compile(r"^(?:Bash\(\*\)|Bash\(:\*\)|.*\(\*\)|\*)$", re.I)


@dataclass
class ConfigScanResult:
    files_scanned: int = 0
    findings: list[Finding] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.findings is None:
            self.findings = []


class ConfigScanner:
    """Scans MCP/agent config files for poisoned commands and permissions."""

    def scan_file(self, path: Path) -> list[Finding]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        if not isinstance(data, dict):
            return []

        loc = path.name
        findings: list[Finding] = []
        findings += self._scan_mcp_servers(data, loc)
        findings += self._scan_hooks(data, loc)
        findings += self._scan_permissions(data, loc)
        return findings

    # --- MCP server launch commands ---
    def _scan_mcp_servers(self, data: dict[str, Any], loc: str) -> list[Finding]:
        servers = data.get("mcpServers") or data.get("servers") or {}
        if not isinstance(servers, dict):
            return []
        found: list[Finding] = []
        for name, spec in servers.items():
            if not isinstance(spec, dict):
                continue
            parts: list[str] = []
            if isinstance(spec.get("command"), str):
                parts.append(spec["command"])
            args = spec.get("args")
            if isinstance(args, list):
                parts += [a for a in args if isinstance(a, str)]
            env = spec.get("env")
            if isinstance(env, dict):
                parts += [str(v) for v in env.values() if isinstance(v, str)]
            command = " ".join(parts)
            found += self._match_command(command, loc, f"mcpServers.{name}")
            # Typosquat check on the launched package (npx/uvx <pkg>).
            pkg = _launched_package(spec.get("command"), args)
            if pkg:
                from mcpradar.supply.typosquat import check_typosquat, typosquat_finding

                hit = check_typosquat(pkg)
                if hit:
                    found.append(typosquat_finding(hit, f"{loc}:mcpServers.{name}"))
        return found

    # --- .claude/settings.json hooks ---
    def _scan_hooks(self, data: dict[str, Any], loc: str) -> list[Finding]:
        hooks = data.get("hooks")
        if not isinstance(hooks, dict):
            return []
        found: list[Finding] = []
        for event, entries in hooks.items():
            for cmd in _iter_hook_commands(entries):
                found += self._match_command(cmd, loc, f"hooks.{event}")
        return found

    # --- permissions ---
    def _scan_permissions(self, data: dict[str, Any], loc: str) -> list[Finding]:
        perms = data.get("permissions")
        found: list[Finding] = []
        if isinstance(perms, dict):
            if str(perms.get("defaultMode", "")).lower() == "bypasspermissions":
                found.append(
                    self._f(
                        "M006",
                        "Over-broad agent permission",
                        Severity.HIGH,
                        loc,
                        "permissions.defaultMode",
                        "Agent config sets defaultMode=bypassPermissions (auto-approves all)",
                    )
                )
            for entry in perms.get("allow", []) or []:
                if isinstance(entry, str) and _BAD_PERMISSIONS.match(entry.strip()):
                    found.append(
                        self._f(
                            "M006",
                            "Over-broad agent permission",
                            Severity.HIGH,
                            loc,
                            "permissions.allow",
                            f"Wildcard permission grant '{entry}' auto-approves a whole tool class",
                        )
                    )
        return found

    def _match_command(self, command: str, loc: str, where: str) -> list[Finding]:
        if not command.strip():
            return []
        out: list[Finding] = []
        for rule in _COMMAND_RULES:
            if rule.pattern.search(command):
                out.append(
                    self._f(
                        rule.rule_id,
                        rule.title,
                        rule.severity,
                        loc,
                        where,
                        f"{rule.message} [{where}]",
                        command=command[:200],
                    )
                )
        return out

    @staticmethod
    def _f(
        rule_id: str,
        title: str,
        severity: Severity,
        loc: str,
        where: str,
        description: str,
        **detail: object,
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            title=title,
            description=description,
            severity=severity,
            target=f"{loc}:{where}",
            location="config",
            detail={"where": where, **detail},
        )


_RUNNERS = {"npx", "npm", "pnpm", "yarn", "bunx", "uvx", "pipx", "uv"}
# npx flags that take no package name, to skip when finding the package token.
_RUNNER_FLAGS = {"-y", "--yes", "-p", "--package", "exec", "run", "tool", "dlx", "-c", "--"}


def _launched_package(command: object, args: object) -> str | None:
    """Extract the package a runner (npx/uvx/…) launches, for typosquat checks."""
    if not isinstance(command, str):
        return None
    runner = Path(command).name.lower().removesuffix(".exe")
    if runner not in _RUNNERS:
        return None
    tokens = [a for a in args if isinstance(a, str)] if isinstance(args, list) else []
    for tok in tokens:
        if tok in _RUNNER_FLAGS or tok.startswith("-"):
            continue
        # first non-flag token is the package (strip an @version suffix)
        base = tok
        if base.startswith("@"):
            scope, _, rest = base.partition("/")
            rest = rest.split("@", 1)[0]
            return f"{scope}/{rest}" if rest else scope
        return base.split("@", 1)[0]
    return None


def _iter_hook_commands(entries: object) -> list[str]:
    """Extract command strings from a Claude hooks entry (nested list/dict)."""
    out: list[str] = []
    if isinstance(entries, list):
        for e in entries:
            out += _iter_hook_commands(e)
    elif isinstance(entries, dict):
        if isinstance(entries.get("command"), str):
            out.append(entries["command"])
        for v in entries.values():
            if isinstance(v, (list, dict)):
                out += _iter_hook_commands(v)
    return out


def scan_config_path(path: Path) -> ConfigScanResult:
    """Scan a single config file or every known config file under a directory."""
    scanner = ConfigScanner()
    result = ConfigScanResult()
    if path.is_file():
        files = [path]
    else:
        matches: set[Path] = set()
        for name in _CONFIG_NAMES:
            for p in path.rglob(Path(name).name):
                if any(part in _SKIP_DIRS for part in p.parts):
                    continue
                # Nested names (".claude/settings.json") must match the tail of
                # the path; flat names match on basename alone.
                rel = str(p).replace("\\", "/")
                if "/" in name:
                    if rel.endswith(name):
                        matches.add(p)
                else:
                    matches.add(p)
        files = sorted(matches)
    for f in files:
        result.findings.extend(scanner.scan_file(f))
        result.files_scanned += 1
    return result
