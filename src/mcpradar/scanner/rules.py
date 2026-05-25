"""Detection rule engine — plugin tarzi, kolayca yeni kural eklenebilir."""

from __future__ import annotations

import base64
import contextlib
import re
import string
from typing import Any

from mcpradar.scanner.report import Finding, Severity, ToolInfo

# ---------------------------------------------------------------------------
# Rule base
# ---------------------------------------------------------------------------


class Rule:
    rule_id: str = ""
    title: str = ""
    severity: Severity = Severity.MEDIUM

    def check(self, tool: ToolInfo) -> list[Finding]:
        raise NotImplementedError

    def _finding(
        self, tool_name: str, description: str, *, severity: Severity | None = None, **detail: Any
    ) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            description=description,
            severity=severity if severity is not None else self.severity,
            target=tool_name,
            location="tool",
            detail=detail,
        )


# ---------------------------------------------------------------------------
# ZWSP / zero-width detection
# ---------------------------------------------------------------------------

ZERO_WIDTH_CHARS = re.compile("[​‌‍‎‏‪‫‬‭‮⁠⁡⁢⁣⁤﻿￹￺￻]")

ZERO_WIDTH_NAMES: dict[str, str] = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "‎": "LEFT-TO-RIGHT MARK",
    "‏": "RIGHT-TO-LEFT MARK",
    "‪": "LEFT-TO-RIGHT EMBEDDING",
    "‫": "RIGHT-TO-LEFT EMBEDDING",
    "‬": "POP DIRECTIONAL FORMATTING",
    "‭": "LEFT-TO-RIGHT OVERRIDE",
    "‮": "RIGHT-TO-LEFT OVERRIDE",
    "⁠": "WORD JOINER",
    "⁢": "INVISIBLE TIMES",
    "⁣": "INVISIBLE SEPARATOR",
    "﻿": "BYTE ORDER MARK (BOM)",
}


class ZeroWidthDetection(Rule):
    rule_id = "R101"
    title = "Zero-width Unicode karakter tespiti"
    severity = Severity.HIGH

    def check(self, tool: ToolInfo) -> list[Finding]:
        fields = {
            "name": tool.name,
            "description": tool.description,
            "input_schema": str(tool.input_schema),
            "output_schema": str(tool.output_schema),
        }
        found: list[Finding] = []
        for field_name, text in fields.items():
            for m in ZERO_WIDTH_CHARS.finditer(text):
                char = m.group()
                char_name = ZERO_WIDTH_NAMES.get(char, f"U+{ord(char):04X}")
                # Tool isminde ZWSP neredeyse her zaman saldırıdır
                sev = Severity.CRITICAL if field_name == "name" else Severity.HIGH
                found.append(
                    self._finding(
                        tool.name,
                        f"'{field_name}' alaninda gizli Unicode: {char_name} (U+{ord(char):04X})",
                        severity=sev,
                        field=field_name,
                        char=char_name,
                        codepoint=f"U+{ord(char):04X}",
                        position=m.start(),
                    )
                )
        return found


# ---------------------------------------------------------------------------
# Prompt injection patterns
# ---------------------------------------------------------------------------

PI = re.compile  # shorthand

PROMPT_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str, Severity]] = [
    (
        PI(
            r"ignore\s+(?:all\s+)?(?:previous|prior|above)"
            r"\s+(?:instructions?|prompts?|directives?)",
            re.I,
        ),
        "ignore previous instructions",
        Severity.CRITICAL,
    ),
    (
        PI(r"(?:you\s+must|you\s+are\s+(?:now|required|compelled))", re.I),
        "you must / you are now",
        Severity.HIGH,
    ),
    (
        PI(r"system\s*:\s*(?!hostname|time|info|status)", re.I),
        "system: directive injection",
        Severity.CRITICAL,
    ),
    (
        PI(r"(?:as\s+an?\s+AI|pretend\s+(?:you\s+are|to\s+be))", re.I),
        "role-playing / pretend directive",
        Severity.HIGH,
    ),
    (
        PI(r"<\|im_start\|>|<\|im_end\|>|<\/?\s*\|?\s*im_\w+\s*\|?\s*>?", re.I),
        "IM start/end delimiter injection",
        Severity.CRITICAL,
    ),
    (
        PI(r"\[/?INST\]|<<SYS>>|\[/?SYS\]", re.I),
        "Llama instruction tag injection",
        Severity.HIGH,
    ),
    (
        PI(
            r"do\s+not\s+(?:follow|obey|listen|trust)\s+"
            r"(?:your|the)\s+(?:instructions?|system|prompt)",
            re.I,
        ),
        "don't follow your instructions",
        Severity.HIGH,
    ),
    (
        PI(
            r"(?:override|overwrite|replace)\s+"
            r"(?:the\s+)?(?:system\s+)?(?:prompt|instructions?)",
            re.I,
        ),
        "override system prompt",
        Severity.CRITICAL,
    ),
    (
        PI(
            r"you\s+are\s+a\s+(?:helpful\s+)?"
            r"(?:jailbreak|exploit|hacker|pentest)",
            re.I,
        ),
        "jailbreak role assignment",
        Severity.CRITICAL,
    ),
    (
        PI(
            r"disregard\s+(?:all\s+)?(?:safety|security|ethical|content)"
            r"\s+(?:guidelines?|policies?|restrictions?)",
            re.I,
        ),
        "disregard safety guidelines",
        Severity.CRITICAL,
    ),
]


class PromptInjectionDetection(Rule):
    rule_id = "R102"
    title = "Prompt injection pattern tespiti"
    severity = Severity.HIGH

    def check(self, tool: ToolInfo) -> list[Finding]:
        text = f"{tool.name}\n{tool.description}\n{str(tool.input_schema)}"
        found: list[Finding] = []

        for pattern, label, severity in PROMPT_INJECTION_PATTERNS:
            for m in pattern.finditer(text):
                found.append(
                    self._finding(
                        tool.name,
                        f"Prompt injection deseni: '{label}'",
                        severity=severity,
                        pattern=label,
                        matched=m.group()[:120],
                    )
                )
        return found


# ---------------------------------------------------------------------------
# Base64 / hex blob detection
# ---------------------------------------------------------------------------

BASE64_RE = re.compile(
    r"(?:^|[^a-zA-Z0-9+/=])"
    r"([A-Za-z0-9+/]{40,}={0,2})"
    r"(?:[^a-zA-Z0-9+/=]|$)"
)
HEX_RE = re.compile(r"(?:0x)?([0-9a-fA-F]{32,})")


class EncodedBlobDetection(Rule):
    rule_id = "R103"
    title = "Base64 / hex blob tespiti"
    severity = Severity.MEDIUM

    def check(self, tool: ToolInfo) -> list[Finding]:
        found: list[Finding] = []

        for m in BASE64_RE.finditer(tool.description):
            blob = m.group(1).rstrip("=")
            if len(blob) < 40:
                continue

            decoded = ""
            with contextlib.suppress(Exception):
                decoded = base64.b64decode(blob, validate=True).decode("utf-8", errors="replace")

            sev = Severity.HIGH if decoded and _is_printable(decoded) else Severity.MEDIUM
            f = self._finding(
                tool.name,
                f"Description icinde base64 blob ({len(blob)} chars)",
                severity=sev,
                blob_length=len(blob),
                decoded_preview=decoded[:80] if decoded else "(decode edilemedi)",
            )
            f.severity = sev
            found.append(f)

        for m in HEX_RE.finditer(tool.description):
            blob = m.group(1)
            decoded = ""
            with contextlib.suppress(Exception):
                decoded = bytes.fromhex(blob).decode("utf-8", errors="replace")

            if decoded and _is_printable(decoded):
                found.append(
                    self._finding(
                        tool.name,
                        f"Description icinde hex blob ({len(blob)} chars) — decode: {decoded[:60]}",
                        severity=Severity.HIGH,
                        blob_length=len(blob),
                        decoded_preview=decoded[:80],
                    )
                )

        return found


def _is_printable(s: str) -> bool:
    ratio = sum(c in string.printable for c in s) / max(len(s), 1)
    return ratio > 0.8


# ---------------------------------------------------------------------------
# Hidden HTML / Markdown detection
# ---------------------------------------------------------------------------

HIDDEN_HTML_RE = re.compile(
    r"<(?:span|div|p|a|font|label)\b[^>]*\b"
    r"(?:style\s*=\s*\"[^\"]*"
    r"(?:display\s*:\s*none|visibility\s*:\s*hidden"
    r"|opacity\s*:\s*0|font-size\s*:\s*0"
    r"|color\s*:\s*transparent|width\s*:\s*0|height\s*:\s*0)"
    r"[^\"]*\")[^>]*>",
    re.I,
)
HIDDEN_LINK_RE = re.compile(
    r"<a\b[^>]*\bhref\s*=\s*\"[^\"]*\"[^>]*>"
    r"\s*(?:click\s*here|here|more|\.{2,}|.{0,2})\s*</a>",
    re.I,
)
ZERO_FONT_RE = re.compile(r"<font\s+size\s*=\s*[\"']?\s*0\s*[\"']?[^>]*>", re.I)
HIDDEN_MD_LINK_RE = re.compile(r"\[(?:.{0,2}|click here|here|more)\]\([^)]+\)", re.I)


class HiddenContentDetection(Rule):
    rule_id = "R104"
    title = "Gizli HTML / Markdown content tespiti"
    severity = Severity.HIGH

    def check(self, tool: ToolInfo) -> list[Finding]:
        text = f"{tool.description}\n{str(tool.input_schema)}"
        found: list[Finding] = []

        checks: list[tuple[re.Pattern[str], str]] = [
            (HIDDEN_HTML_RE, "CSS ile gizlenmis HTML elementi"),
            (ZERO_FONT_RE, "font-size:0 (gorunmez metin)"),
            (HIDDEN_LINK_RE, "Aldatici baglanti metni"),
            (HIDDEN_MD_LINK_RE, "Aldatici Markdown link"),
        ]

        for pattern, label in checks:
            for m in pattern.finditer(text):
                found.append(
                    self._finding(
                        tool.name,
                        f"{label} tespit edildi",
                        pattern=label,
                        matched=m.group()[:120],
                    )
                )
        return found


# ---------------------------------------------------------------------------
# Permission scope mismatch
# ---------------------------------------------------------------------------

SCOPE_PAIRS: list[tuple[re.Pattern[str], re.Pattern[str], str, str]] = [
    (
        re.compile(r"\b(?:file|filesystem|read_file|write_file|fs|disk)\b", re.I),
        re.compile(
            r"\b(?:network|internet|http|https|api|remote|fetch|url|curl|socket)\b",
            re.I,
        ),
        "file",
        "network",
    ),
    (
        re.compile(r"\b(?:db|database|sql|nosql|query|table)\b", re.I),
        re.compile(
            r"\b(?:file|filesystem|disk|rm\b|delete|remove\b"
            r"|exec|spawn|shell)\b",
            re.I,
        ),
        "database",
        "filesystem/shell",
    ),
    (
        re.compile(r"\b(?:read|get|fetch|list|search|query)\b", re.I),
        re.compile(
            r"\b(?:write|delete|create|update|exec|run|shell|spawn|sudo)\b",
            re.I,
        ),
        "read-only",
        "write/exec",
    ),
]


class PermissionScopeMismatch(Rule):
    rule_id = "R105"
    title = "Permission scope mismatch"
    severity = Severity.MEDIUM

    def check(self, tool: ToolInfo) -> list[Finding]:
        found: list[Finding] = []

        for name_pat, desc_pat, scope_name, desc_name in SCOPE_PAIRS:
            name_match = name_pat.search(tool.name)
            desc_match = desc_pat.search(tool.description)
            if name_match and desc_match:
                # Eger description'da HEM name scope HEM desc scope geciyorsa,
                # bu meşru bir köprü aracı olabilir (örn: "fetch URL and save to file")
                both_in_desc = name_pat.search(tool.description) is not None
                sev = Severity.LOW if both_in_desc else Severity.MEDIUM
                found.append(
                    self._finding(
                        tool.name,
                        f"Tool ismi '{scope_name}' kapsaminda ama description "
                        f"'{desc_name}' operasyonlarindan bahsediyor",
                        severity=sev,
                        name_scope=scope_name,
                        description_scope=desc_name,
                        both_in_description=both_in_desc,
                        name_matched=name_match.group(),
                        desc_matched=desc_match.group(),
                    )
                )
        return found


# ---------------------------------------------------------------------------
# Dangerous tool name (R001)
# ---------------------------------------------------------------------------

DANGEROUS_NAMES = {
    "eval",
    "exec",
    "system",
    "shell",
    "bash",
    "cmd",
    "subprocess",
    "os",
    "rm",
    "del",
    "delete",
    "drop",
    "truncate",
    "kill",
    "shutdown",
    "reboot",
    "sudo",
    "su",
    "chmod",
    "chown",
    "wget",
    "curl",
}


class DangerousNameDetection(Rule):
    rule_id = "R001"
    title = "Tehlikeli tool ismi"
    severity = Severity.CRITICAL

    def check(self, tool: ToolInfo) -> list[Finding]:
        if tool.name.lower() in DANGEROUS_NAMES:
            return [
                self._finding(
                    tool.name,
                    f"'{tool.name}' potansiyel tehlikeli sistem komutuyla eslesiyor",
                    matched_name=tool.name.lower(),
                )
            ]
        return []


# ---------------------------------------------------------------------------
# Rule engine — collects and runs all rules
# ---------------------------------------------------------------------------


def _discover_plugins() -> list[Rule]:
    """Discover community rules via entry_points(group='mcpradar.rules')."""
    import logging

    try:
        from importlib.metadata import entry_points
    except ImportError:
        return []

    logger = logging.getLogger("mcpradar.plugins")
    discovered: list[Rule] = []

    try:
        eps = entry_points(group="mcpradar.rules")
    except TypeError:
        # Python 3.11 compat
        eps = entry_points().get("mcpradar.rules", [])  # type: ignore[arg-type]

    for ep in eps:
        try:
            rule_cls = ep.load()
            instance = rule_cls()
            if not isinstance(instance, Rule):
                logger.warning(
                    "Plugin %s does not inherit from Rule, skipping", ep.name
                )
                continue
            discovered.append(instance)
            logger.debug("Loaded plugin: %s → %s", ep.name, instance.rule_id)
        except Exception as exc:
            logger.warning("Failed to load plugin %s: %s", ep.name, exc)

    return discovered


class RuleEngine:
    def __init__(
        self,
        min_severity: Severity = Severity.MEDIUM,
        disabled_rules: list[str] | None = None,
    ) -> None:
        self.min_severity = min_severity
        self._disabled: set[str] = set(disabled_rules or [])

        builtins: list[Rule] = [
            DangerousNameDetection(),
            ZeroWidthDetection(),
            PromptInjectionDetection(),
            EncodedBlobDetection(),
            HiddenContentDetection(),
            PermissionScopeMismatch(),
        ]

        self._rules = [r for r in builtins if r.rule_id not in self._disabled]

        # Discover community plugins
        for plugin in _discover_plugins():
            if not isinstance(plugin, Rule):
                continue
            if plugin.rule_id not in self._disabled:
                self._rules.append(plugin)

    @property
    def loaded_rules(self) -> list[dict[str, str]]:
        """Return metadata for all loaded rules."""
        return [
            {
                "rule_id": r.rule_id,
                "title": r.title,
                "severity": r.severity.value,
                "source": "built-in" if isinstance(r, (
                    DangerousNameDetection, ZeroWidthDetection,
                    PromptInjectionDetection, EncodedBlobDetection,
                    HiddenContentDetection, PermissionScopeMismatch,
                )) else "plugin",
            }
            for r in self._rules
        ]

    def register(self, rule: Rule) -> None:
        self._rules.append(rule)

    def disable(self, rule_id: str) -> bool:
        """Disable a rule by ID. Returns True if found."""
        self._disabled.add(rule_id)
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.rule_id not in self._disabled]
        return len(self._rules) < before

    def analyze(self, tool: ToolInfo) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self._rules:
            findings.extend(rule.check(tool))
        return [f for f in findings if f.severity >= self.min_severity]
