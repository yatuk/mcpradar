"""Detection rule engine -- plugin-style, easily extensible with new rules."""

from __future__ import annotations

import base64
import contextlib
import math
import re
import string
from collections.abc import Iterator
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
    "‮": "RIGHT-TO-RIGHT OVERRIDE",
    "⁠": "WORD JOINER",
    "⁢": "INVISIBLE TIMES",
    "⁣": "INVISIBLE SEPARATOR",
    "﻿": "BYTE ORDER MARK (BOM)",
}


class ZeroWidthDetection(Rule):
    rule_id = "R101"
    title = "Zero-width Unicode character detection"
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
                # ZWSP in tool name is almost always an attack
                sev = Severity.CRITICAL if field_name == "name" else Severity.HIGH
                found.append(
                    self._finding(
                        tool.name,
                        f"Hidden Unicode in '{field_name}' field: {char_name} (U+{ord(char):04X})",
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
    title = "Prompt injection pattern detection"
    severity = Severity.HIGH

    def check(self, tool: ToolInfo) -> list[Finding]:
        text = f"{tool.name}\n{tool.description}\n{str(tool.input_schema)}"
        found: list[Finding] = []

        for pattern, label, severity in PROMPT_INJECTION_PATTERNS:
            for m in pattern.finditer(text):
                found.append(
                    self._finding(
                        tool.name,
                        f"Prompt injection pattern: '{label}'",
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
    title = "Base64 / hex blob detection"
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
                f"Base64 blob in description ({len(blob)} chars)",
                severity=sev,
                blob_length=len(blob),
                decoded_preview=decoded[:80] if decoded else "(could not decode)",
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
                        f"Hex blob in description ({len(blob)} chars); decoded: {decoded[:60]}",
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
# Helper functions -- entropy, name decomposition, schema walk
# ---------------------------------------------------------------------------


def _shannon_entropy(s: str) -> float:
    """Shannon entropy calculation for secret detection. Returns 0 for len < 3."""
    if len(s) < 3:
        return 0.0
    freq: dict[str, float] = {}
    for c in s:
        freq[c] = freq.get(c, 0.0) + 1.0
    length = float(len(s))
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _decompose_name(name: str) -> set[str]:
    """Split tool names on underscores, camelCase boundaries, and hyphens.

    Returns lowercase set of word tokens.
    """
    # Normalize hyphens and underscores to spaces
    s = re.sub(r"[-_]", " ", name)
    # Split camelCase: "getUserData" → "get User Data"
    s = re.sub(r"(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", " ", s)
    return {t.lower() for t in s.split() if t}


def _walk_schema_props(
    schema: dict[str, Any], path: str = "", depth: int = 0
) -> Iterator[tuple[str, dict[str, Any]]]:
    """Recursively walk JSON Schema properties.

    Yields (path, prop_schema) for each property found.
    Also recurses into nested properties, items.properties, and anyOf/oneOf arrays.
    Max depth: 10.
    """
    if depth > 10 or not isinstance(schema, dict):
        return
    props = schema.get("properties")
    if not isinstance(props, dict):
        return
    for prop_name, prop_schema in props.items():
        if not isinstance(prop_schema, dict):
            continue
        full_path = f"{path}.{prop_name}" if path else prop_name
        yield (full_path, prop_schema)
        # Recurse into nested properties of this property
        yield from _walk_schema_props(prop_schema, full_path, depth + 1)
        # Handle items.properties for array-type properties
        items = prop_schema.get("items")
        if isinstance(items, dict):
            yield from _walk_schema_props(items, f"{full_path}.items", depth + 1)
        # Handle anyOf/oneOf sub-schemas
        for key in ("anyOf", "oneOf"):
            sub_schemas = prop_schema.get(key)
            if isinstance(sub_schemas, list):
                for idx, sub in enumerate(sub_schemas):
                    if isinstance(sub, dict):
                        yield from _walk_schema_props(sub, f"{full_path}[{idx}]", depth + 1)


def _collect_all_texts(tool: ToolInfo) -> list[tuple[str, str]]:
    """Collect all text surfaces from a tool for scanning.

    Returns list of (source_label, text) tuples.
    """
    texts: list[tuple[str, str]] = [
        ("name", tool.name),
        ("description", tool.description),
        ("input_schema", str(tool.input_schema)),
        ("output_schema", str(tool.output_schema)),
    ]
    # Collect default values from input schema properties
    for prop_path, prop_schema in _walk_schema_props(tool.input_schema):
        default_val = prop_schema.get("default")
        if isinstance(default_val, str):
            texts.append((f"input.default.{prop_path}", str(default_val)))
    return texts


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
    title = "Hidden HTML / Markdown content detection"
    severity = Severity.HIGH

    def check(self, tool: ToolInfo) -> list[Finding]:
        text = f"{tool.description}\n{str(tool.input_schema)}"
        found: list[Finding] = []

        checks: list[tuple[re.Pattern[str], str]] = [
            (HIDDEN_HTML_RE, "CSS-hidden HTML element"),
            (ZERO_FONT_RE, "font-size:0 (invisible text)"),
            (HIDDEN_LINK_RE, "Deceptive link text"),
            (HIDDEN_MD_LINK_RE, "Deceptive Markdown link"),
        ]

        for pattern, label in checks:
            for m in pattern.finditer(text):
                found.append(
                    self._finding(
                        tool.name,
                        f"{label} detected",
                        pattern=label,
                        matched=m.group()[:120],
                    )
                )
        return found


# ---------------------------------------------------------------------------
# Secret exposure patterns (R106)
# ---------------------------------------------------------------------------

SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"sk-[a-zA-Z0-9]{32,}"), "OpenAI API key"),
    (re.compile(r"sk-proj-[a-zA-Z0-9]{32,}"), "OpenAI project key"),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "GitHub personal access token"),
    (re.compile(r"gho_[a-zA-Z0-9]{36}"), "GitHub OAuth token"),
    (re.compile(r"xox[bpras]-[a-zA-Z0-9-]+"), "Slack token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key ID"),
    (
        re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
        "JWT token",
    ),
    (re.compile(r"AIza[0-9A-Za-z_-]{35}"), "Google API key"),
    (
        re.compile(r"(?:mongodb|postgresql|mysql|redis)://[^\s]{10,}"),
        "Database connection string",
    ),
    (re.compile(r"github_pat_[a-zA-Z0-9_]{36,}"), "GitHub fine-grained token"),
    (re.compile(r"hf_[a-zA-Z0-9]{34}"), "HuggingFace token"),
    (re.compile(r"tpt_[a-zA-Z0-9]{32,}"), "Teleport token"),
    (re.compile(r"key-[a-zA-Z0-9]{32,}"), "Generic API key prefix"),
    (re.compile(r"secret-[a-zA-Z0-9]{32,}"), "Generic secret prefix"),
    (re.compile(r"token-[a-zA-Z0-9]{32,}"), "Generic token prefix"),
]

# Heuristic pattern: base64 alphabet includes '/', so URL paths and readable
# slug chains match too. Only reported when the match passes the entropy gate,
# and at HIGH (not CRITICAL) since there is no known secret format to confirm.
GENERIC_BASE64_RE = re.compile(r"[a-zA-Z0-9+/]{40,}={0,2}")
GENERIC_BASE64_LABEL = "Generic base64-like (entropy check applied)"


class SecretExposureDetection(Rule):
    rule_id = "R106"
    title = "Secret credential / token exposure"
    severity = Severity.CRITICAL

    def check(self, tool: ToolInfo) -> list[Finding]:
        found: list[Finding] = []
        seen: set[str] = set()
        for source, text in _collect_all_texts(tool):
            for pattern, label in SECRET_PATTERNS:
                for m in pattern.finditer(text):
                    matched = m.group()
                    if matched in seen:
                        continue
                    seen.add(matched)
                    found.append(
                        self._finding(
                            tool.name,
                            f"'{label}' detected in {source} field",
                            format=label,
                            source=source,
                            matched=matched[:80],
                        )
                    )
            for m in GENERIC_BASE64_RE.finditer(text):
                matched = m.group()
                if matched in seen or _shannon_entropy(matched) <= 4.5:
                    continue
                seen.add(matched)
                found.append(
                    self._finding(
                        tool.name,
                        f"'{GENERIC_BASE64_LABEL}' detected in {source} field",
                        severity=Severity.HIGH,
                        format=GENERIC_BASE64_LABEL,
                        source=source,
                        matched=matched[:80],
                    )
                )
        # Entropy-only scan for unknown secrets
        # Split text into space/newline-separated tokens
        for source, text in _collect_all_texts(tool):
            for token in re.split(r"\s+", text):
                token = token.strip("\"'`,;:{}[]()")
                if len(token) < 16 or token in seen:
                    continue
                ent = _shannon_entropy(token)
                if ent > 4.5:
                    seen.add(token)
                    found.append(
                        self._finding(
                            tool.name,
                            f"High-entropy string ({ent:.1f}) in {source} field",
                            severity=Severity.HIGH,
                            entropy=round(ent, 1),
                            source=source,
                            matched=token[:80],
                        )
                    )
        return found


# ---------------------------------------------------------------------------
# Command injection risk patterns (R107)
# ---------------------------------------------------------------------------

SHELL_METACHAR_RE = re.compile(
    r"\$\(|`|\|\||&&|;\s*(?:nc|netcat|curl|wget)\b|>>|>\s*/dev/null|2>&1|>\s*\("
)

# Matched as a case-insensitive prefix of the default value, so variants like
# "rm -rf /tmp/cache" or "DROP TABLE users" are caught, not just exact strings.
DANGEROUS_DEFAULT_RE = re.compile(
    r"^\s*(?:"
    r"rm\s+-[a-z]*r[a-z]*f|rm\s+-[a-z]*f[a-z]*r"
    r"|drop\s+(?:table|database)\b"
    r"|shutdown\b"
    r"|reboot\b"
    r"|halt\b"
    r"|mkfs\b"
    r"|dd\s+if="
    r"|/bin/(?:ba)?sh\b"
    r"|cmd\.exe\b"
    r"|powershell(?:\.exe)?\b"
    r"|(?:curl|wget)\s+\S+\s*\|\s*(?:ba)?sh\b"
    r")",
    re.IGNORECASE,
)

OVERLY_BROAD_REGEX_RE = re.compile(
    r"^\.\*|\.\+$|\\[wWdDsS]\*.*\\[wWdDsS]\*|\[\.\*\][\+\*]|\(\.\*\)"
)

COMMAND_LIKE_ENUM_VALUES: set[str] = {
    "bash",
    "sh",
    "zsh",
    "cmd",
    "powershell",
    "python -c",
    "eval",
    "exec",
    "execute",
    "system",
    "shell",
    "/bin/bash",
    "/bin/sh",
    "cmd.exe",
}


class CommandInjectionDetection(Rule):
    rule_id = "R107"
    title = "Command injection risk in tool parameters"
    severity = Severity.CRITICAL

    def check(self, tool: ToolInfo) -> list[Finding]:
        found: list[Finding] = []
        for prop_path, prop_schema in _walk_schema_props(tool.input_schema):
            # Check shell metacharacters in text fields
            for field in ("description", "example", "default"):
                val = prop_schema.get(field)
                if isinstance(val, str) and SHELL_METACHAR_RE.search(val):
                    found.append(
                        self._finding(
                            tool.name,
                            f"Shell metacharacter: '{prop_path}.{field}' = '{val[:60]}'",
                            property=prop_path,
                            field=field,
                            matched=val[:120],
                        )
                    )
            # Check dangerous default values
            default_val = prop_schema.get("default")
            if isinstance(default_val, str) and DANGEROUS_DEFAULT_RE.search(default_val):
                found.append(
                    self._finding(
                        tool.name,
                        f"Dangerous default value: '{prop_path}.default' = '{default_val[:60]}'",
                        severity=Severity.CRITICAL,
                        property=prop_path,
                        matched=default_val[:120],
                    )
                )
            # Check overly broad regex in pattern/regex fields
            for regex_field in ("pattern", "regex"):
                pattern_val = prop_schema.get(regex_field)
                if isinstance(pattern_val, str) and OVERLY_BROAD_REGEX_RE.search(pattern_val):
                    found.append(
                        self._finding(
                            tool.name,
                            f"Overly broad regex: '{prop_path}.{regex_field}' = "
                            f"'{pattern_val[:60]}'",
                            severity=Severity.HIGH,
                            property=prop_path,
                            field=regex_field,
                            matched=pattern_val[:120],
                        )
                    )
            # Check command-like enum values
            enum_vals = prop_schema.get("enum")
            if isinstance(enum_vals, list):
                for val in enum_vals:
                    if isinstance(val, str) and val.lower().strip() in COMMAND_LIKE_ENUM_VALUES:
                        found.append(
                            self._finding(
                                tool.name,
                                f"Command-like enum value: '{prop_path}' enum = '{val}'",
                                severity=Severity.HIGH,
                                property=prop_path,
                                matched=val,
                            )
                        )
        # Also scan output_schema
        for prop_path, prop_schema in _walk_schema_props(tool.output_schema):
            for field in ("description", "example", "default"):
                val = prop_schema.get(field)
                if isinstance(val, str) and SHELL_METACHAR_RE.search(val):
                    found.append(
                        self._finding(
                            tool.name,
                            f"Shell metacharacter (output): '{prop_path}.{field}'",
                            property=prop_path,
                            field=field,
                            matched=val[:120],
                        )
                    )
        return found


# ---------------------------------------------------------------------------
# Supply chain risk patterns (R108)
# ---------------------------------------------------------------------------

SUPPLY_CHAIN_PATTERNS: list[tuple[re.Pattern[str], str, Severity]] = [
    (re.compile(r"curl\s+.*\|.*(?:bash|sh|zsh)"), "curl-to-shell pipe", Severity.HIGH),
    (re.compile(r"wget\s+.*-O\s*-\s*\|.*(?:bash|sh)"), "wget-to-shell pipe", Severity.HIGH),
    (re.compile(r"\b(?:pip|pip3)\s+install\b"), "pip install", Severity.MEDIUM),
    (re.compile(r"\b(?:npm|yarn|pnpm)\s+(?:install|add)\b"), "npm/yarn install", Severity.MEDIUM),
    (re.compile(r"\bcargo\s+(?:install|add)\b"), "cargo install", Severity.MEDIUM),
    (
        re.compile(r"\bimportlib\.(?:import_module|load_source)\b"),
        "dynamic import",
        Severity.MEDIUM,
    ),
    (
        re.compile(r"\b(?:eval|exec|__import__)\s*\(", re.I),
        "dynamic code execution",
        Severity.HIGH,
    ),
    (re.compile(r'\brequire\s*\(\s*["\']'), "Node.js require()", Severity.MEDIUM),
    (re.compile(r"\bnpx\s+"), "npx execution", Severity.HIGH),
    (re.compile(r"\b(?:gem|cpan|composer)\s+install\b"), "other pkg manager", Severity.LOW),
]


def _is_install_docs(text: str, label: str) -> bool:
    """Return True if this match appears to be setup documentation, not malicious."""
    if label in ("pip install", "npm/yarn install", "npx execution"):
        desc_lower = text.lower()
        # Pattern: install instructions for the server itself, not payload delivery
        if any(
            kw in desc_lower
            for kw in (
                "setup",
                "install the server",
                "getting started",
                "quick start",
                "configuration",
                "usage",
            )
        ):
            return True
    return False


class SupplyChainRiskDetection(Rule):
    rule_id = "R108"
    title = "Supply chain risk indicator"
    severity = Severity.MEDIUM

    def check(self, tool: ToolInfo) -> list[Finding]:
        text = f"{tool.description}\n{str(tool.input_schema)}"
        found: list[Finding] = []
        for pattern, label, sev in SUPPLY_CHAIN_PATTERNS:
            for m in pattern.finditer(text):
                # Skip if this appears to be setup/install documentation
                if _is_install_docs(text, label):
                    continue
                found.append(
                    self._finding(
                        tool.name,
                        f"Supply chain risk: '{label}'",
                        severity=sev,
                        pattern=label,
                        matched=m.group()[:120],
                    )
                )
        return found


# ---------------------------------------------------------------------------
# Schema poisoning detection (R109)
# ---------------------------------------------------------------------------


class SchemaPoisoningDetection(Rule):
    rule_id = "R109"
    title = "Schema poisoning indicator"
    severity = Severity.HIGH

    def check(self, tool: ToolInfo) -> list[Finding]:
        found: list[Finding] = []
        for schema_name, schema in [
            ("input_schema", tool.input_schema),
            ("output_schema", tool.output_schema),
        ]:
            if not schema or not isinstance(schema, dict):
                continue
            # additionalProperties: true
            if schema.get("additionalProperties") is True:
                found.append(
                    self._finding(
                        tool.name,
                        f"{schema_name}: additionalProperties: true; open to arbitrary injection",
                        schema=schema_name,
                        issue="additional_properties_true",
                    )
                )
            props = schema.get("properties", {})
            if props:
                # No required fields
                required = schema.get("required", [])
                if not required:
                    found.append(
                        self._finding(
                            tool.name,
                            f"{schema_name}: no required fields; empty input acceptable",
                            severity=Severity.MEDIUM,
                            schema=schema_name,
                            issue="no_required_fields",
                        )
                    )
                # Missing type constraints
                for prop_name, prop_schema in props.items():
                    if isinstance(prop_schema, dict) and "type" not in prop_schema:
                        found.append(
                            self._finding(
                                tool.name,
                                f"{schema_name}.{prop_name}: missing type constraint",
                                severity=Severity.MEDIUM,
                                schema=schema_name,
                                property=prop_name,
                                issue="missing_type",
                            )
                        )
                # Excessive maxLength/maxItems
                for prop_name, prop_schema in props.items():
                    if isinstance(prop_schema, dict):
                        max_len = prop_schema.get("maxLength")
                        if isinstance(max_len, (int, float)) and max_len > 1_000_000:
                            found.append(
                                self._finding(
                                    tool.name,
                                    f"{schema_name}.{prop_name}: excessive maxLength = {max_len} "
                                    f"(buffer overflow risk)",
                                    severity=Severity.MEDIUM,
                                    schema=schema_name,
                                    property=prop_name,
                                    max_length=int(max_len),
                                    issue="excessive_max_length",
                                )
                            )
                        max_items = prop_schema.get("maxItems")
                        if isinstance(max_items, (int, float)) and max_items > 100_000:
                            found.append(
                                self._finding(
                                    tool.name,
                                    f"{schema_name}.{prop_name}: excessive maxItems = {max_items} "
                                    f"(buffer overflow risk)",
                                    severity=Severity.MEDIUM,
                                    schema=schema_name,
                                    property=prop_name,
                                    max_items=int(max_items),
                                    issue="excessive_max_items",
                                )
                            )
        return found


# ---------------------------------------------------------------------------
# Version Anomaly (R110)
# ---------------------------------------------------------------------------


class VersionAnomalyDetection(Rule):
    """Fingerprint-based: detects version rollback, unexpected upgrades, tool changes."""

    rule_id = "R110"
    title = "Server version anomaly"
    severity = Severity.HIGH

    def check(self, tool: ToolInfo) -> list[Finding]:
        # R110 operates on fingerprint diffs, not individual tools
        # Findings are generated via RuleEngine.pre_scan_check()
        return []


# ---------------------------------------------------------------------------
# Insecure Transport (R111)
# ---------------------------------------------------------------------------


class InsecureTransportDetection(Rule):
    """Transport-layer: detects plain HTTP, old TLS, bad certs, missing HSTS."""

    rule_id = "R111"
    title = "Insecure transport"
    severity = Severity.HIGH

    def check(self, tool: ToolInfo) -> list[Finding]:
        # R111 operates on transport-level checks, not individual tools
        # Findings are generated during scan via TransportChecker
        return []


# ---------------------------------------------------------------------------
# Authorization Hardening (R112)
# ---------------------------------------------------------------------------


class AuthorizationHardeningDetection(Rule):
    """Detects missing authorization hardening per MCP 2026-07-28 spec.

    Per the spec RC (May 2026, final July 2026):
    - Clients MUST validate the ``iss`` parameter per RFC 9207
    - Dynamic Client Registration requires ``application_type``
    - Client credentials must be bound to the issuing authorization server

    This rule operates at the server-metadata level, not per-tool.
    Findings are generated during scan via check_server_auth().
    """

    rule_id = "R112"
    title = "Authorization hardening for 2026-07-28 spec compliance"
    severity = Severity.HIGH

    def check(self, tool: ToolInfo) -> list[Finding]:
        # R112 operates at the auth metadata level, not per-tool.
        # Findings are generated via check_server_auth() called from the scanner.
        return []


def check_server_auth(
    target: str,
    transport: str,
    has_iss: bool | None = None,
    has_app_type: bool | None = None,
    uses_session_id: bool = False,
) -> list[Finding]:
    """Generate R112 findings from server authorization metadata.

    Called post-scan when auth metadata is available (e.g. from
    OAuth discovery endpoints or response headers).

    Args:
        target: The server URL/endpoint.
        transport: Transport type (http/sse/stdio).
        has_iss: Whether the authorization server includes ``iss`` in responses.
            None means not checked (e.g. server doesn't use OAuth).
        has_app_type: Whether Dynamic Client Registration declares
            ``application_type``. None means not checked.
        uses_session_id: Whether the server still returns ``Mcp-Session-Id``
            header (deprecated in 2026-07-28 spec).
    """
    findings: list[Finding] = []

    # R112-1: Missing iss parameter (RFC 9207 requirement)
    if has_iss is False:
        findings.append(
            Finding(
                rule_id="R112",
                title="Missing iss parameter in authorization response",
                description=(
                    "The 2026-07-28 MCP spec requires authorization servers to "
                    "include the ``iss`` parameter per RFC 9207 to prevent "
                    "mix-up attacks. Servers without ``iss`` are vulnerable to "
                    "token redirection between authorization servers."
                ),
                severity=Severity.HIGH,
                target=target,
                location="auth",
                detail={"requirement": "RFC 9207", "spec": "2026-07-28"},
            )
        )

    # R112-2: Missing application_type in DCR
    if has_app_type is False:
        findings.append(
            Finding(
                rule_id="R112",
                title="Missing application_type in Dynamic Client Registration",
                description=(
                    "The 2026-07-28 MCP spec requires clients to declare "
                    "``application_type`` during Dynamic Client Registration "
                    "to avoid authorization server defaults (e.g. defaulting "
                    "a CLI client to 'web' and rejecting localhost redirects)."
                ),
                severity=Severity.MEDIUM,
                target=target,
                location="auth",
                detail={"requirement": "SEP-837", "spec": "2026-07-28"},
            )
        )

    # R112-3: Session ID usage (deprecated protocol)
    if uses_session_id:
        findings.append(
            Finding(
                rule_id="R112",
                title="Server uses deprecated Mcp-Session-Id header",
                description=(
                    "The 2026-07-28 MCP spec removes the ``Mcp-Session-Id`` "
                    "header and protocol-level sessions. This server still "
                    "uses the deprecated session-based protocol. Sessions "
                    "force sticky routing and prevent horizontal scaling."
                ),
                severity=Severity.MEDIUM,
                target=target,
                location="transport",
                detail={"deprecated": "Mcp-Session-Id", "spec": "2026-07-28"},
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Path Traversal Detection (R113)
# ---------------------------------------------------------------------------


class PathTraversalDetection(Rule):
    """Detects path traversal vulnerability indicators in tool schemas.

    Covers CWE-22 (Path Traversal) and CWE-59 (Symlink Attacks).
    """

    rule_id = "R113"
    title = "Path traversal / directory traversal risk"
    severity = Severity.MEDIUM

    PATH_PARAM_NAMES: set[str] = {
        "path",
        "file",
        "filepath",
        "filename",
        "source",
        "dest",
        "destination",
        "directory",
        "dir",
        "target",
        "output",
    }

    TRAVERSAL_PATTERNS: list[re.Pattern[str]] = [
        re.compile(r"\.\.[/\\]", re.I),  # ../ or ..\
        re.compile(r"\bpath\s*(?:traversal|injection|bypass|escape)\b", re.I),
        re.compile(r"\b(?:symlink|symbolic\s*link)\b", re.I),
    ]

    def check(self, tool: ToolInfo) -> list[Finding]:
        found: list[Finding] = []

        # Check description for traversal risk language. Defensive documentation
        # ("protects against path traversal", "does not follow symlinks") is not
        # an indicator, so matches preceded by protective language are skipped —
        # unless that language is itself negated ("does not prevent ../").
        protective = re.compile(
            r"\b(?:prevent|protect|reject|den(?:y|ie)|block|sanitiz|validat|"
            r"disallow|forbid|(?:not?|never)\s+follow)\w*",
            re.I,
        )
        negator = re.compile(r"\b(?:not|no|never|doesn'?t|does\s+not|won'?t|without)\s*$", re.I)
        text = f"{tool.description} {str(tool.input_schema)}"
        for pattern in self.TRAVERSAL_PATTERNS:
            for m in pattern.finditer(text):
                context = text[max(0, m.start() - 60) : m.start()]
                guard = protective.search(context)
                if guard and not negator.search(context[: guard.start()].rstrip()):
                    continue
                found.append(
                    self._finding(
                        tool.name,
                        f"Path traversal indicator in description: '{m.group()}'",
                        severity=Severity.HIGH,
                        pattern=m.group(),
                    )
                )

        # Check for path-like params without constraints
        for prop_path, prop_schema in _walk_schema_props(tool.input_schema):
            prop_name = prop_path.split(".")[-1].lower()
            if prop_name not in self.PATH_PARAM_NAMES:
                continue
            if not isinstance(prop_schema, dict):
                continue
            prop_type = prop_schema.get("type", "")
            if prop_type != "string":
                continue

            # Flag if path param has no validation constraints
            has_pattern = "pattern" in prop_schema
            has_format = "format" in prop_schema

            missing = []
            if not has_pattern:
                missing.append("pattern")
            if not has_format:
                missing.append("format")

            if missing:
                # Absence of a schema constraint is a hardening hint, not evidence
                # of traversal — every legitimate file tool omits `pattern` for
                # paths. Keep it informational; write-capable tools get MEDIUM.
                is_write = any(
                    kw in tool.name.lower()
                    for kw in ("write", "create", "edit", "move", "remove", "delete")
                )
                sev = Severity.MEDIUM if is_write else Severity.LOW
                found.append(
                    self._finding(
                        tool.name,
                        f"Path parameter '{prop_path}' ({prop_type}) lacks validation "
                        f"constraints: {', '.join(missing)}. "
                        f"Path traversal risk (CWE-22).",
                        severity=sev,
                        property=prop_path,
                        missing_constraints=missing,
                    )
                )

            # Also check output_schema
        for prop_path, prop_schema in _walk_schema_props(tool.output_schema):
            prop_name = prop_path.split(".")[-1].lower()
            if (
                prop_name in self.PATH_PARAM_NAMES
                and isinstance(prop_schema, dict)
                and prop_schema.get("type") == "string"
                and "pattern" not in prop_schema
            ):
                found.append(
                    self._finding(
                        tool.name,
                        f"Output path parameter '{prop_path}' lacks validation",
                        severity=Severity.LOW,
                        property=prop_path,
                    )
                )

        return found


# ---------------------------------------------------------------------------
# Unbounded Input Detection (R114)
# ---------------------------------------------------------------------------


class UnboundedInputDetection(Rule):
    """Detects string parameters with no size or content constraints.

    Extends R109 which only checks extreme values (>1M maxLength).
    This rule catches the common case of missing constraints entirely.
    """

    rule_id = "R114"
    title = "Unbounded input: no size/content constraints"
    severity = Severity.LOW

    def check(self, tool: ToolInfo) -> list[Finding]:
        found: list[Finding] = []

        for schema_name, schema in [
            ("input_schema", tool.input_schema),
            ("output_schema", tool.output_schema),
        ]:
            if not schema or not isinstance(schema, dict):
                continue
            for prop_path, prop_schema in _walk_schema_props(schema):
                if not isinstance(prop_schema, dict):
                    continue
                if prop_schema.get("type") != "string":
                    continue

                # Check if string has ANY constraints
                has_constraint = any(
                    k in prop_schema
                    for k in (
                        "pattern",
                        "format",
                        "enum",
                        "const",
                        "minLength",
                        "maxLength",
                    )
                )
                if not has_constraint:
                    found.append(
                        self._finding(
                            tool.name,
                            f"String parameter '{prop_path}' in {schema_name} "
                            f"has no validation constraints (no pattern, format, "
                            f"enum, or length limits)",
                            severity=Severity.LOW,
                            property=prop_path,
                            schema=schema_name,
                        )
                    )

        return found


# ---------------------------------------------------------------------------
# Permission scope mismatch -- bridge-aware (R105)
# ---------------------------------------------------------------------------

BRIDGE_KEYWORDS: set[str] = {
    "bridge",
    "proxy",
    "adapter",
    "wrapper",
    "gateway",
    "facade",
    "middleware",
    "connector",
    "relay",
    "translator",
    "integration",
    "orchestrator",
    "manager",
    "handler",
    "provider",
    "service",
    "client",
    "interface",
}

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
    # crypto/wallet -- crypto tools that talk to network
    (
        re.compile(r"\b(?:crypto|wallet|key|sign|encrypt|decrypt)\b", re.I),
        re.compile(
            r"\b(?:network|internet|http|url|api|remote|fetch|send|transfer)\b",
            re.I,
        ),
        "crypto",
        "network",
    ),
    # browser/system -- browser tools accessing filesystem
    (
        re.compile(r"\b(?:browser|tab|window|dom|render|html)\b", re.I),
        re.compile(
            r"\b(?:file|filesystem|disk|process|exec|spawn)\b",
            re.I,
        ),
        "browser",
        "system",
    ),
    # notification/execution -- messaging tools that can execute
    (
        re.compile(r"\b(?:notify|alert|message|chat|send)\b", re.I),
        re.compile(
            r"\b(?:exec|run|shell|spawn|sudo|admin)\b",
            re.I,
        ),
        "notification",
        "execution",
    ),
    # config/remote-exec -- config tools that deploy
    (
        re.compile(r"\b(?:config|setting|env|environment)\b", re.I),
        re.compile(
            r"\b(?:exec|spawn|shell|script|deploy|run)\b",
            re.I,
        ),
        "configuration",
        "remote-exec",
    ),
    # search/write -- readonly tools with write access
    (
        re.compile(r"\b(?:search|find|lookup|locate)\b", re.I),
        re.compile(
            r"\b(?:write|create|delete|update|modify|remove)\b",
            re.I,
        ),
        "search",
        "write",
    ),
    # log/command -- logging tools with cmd execution
    (
        re.compile(r"\b(?:log|audit|monitor|track|observe)\b", re.I),
        re.compile(
            r"\b(?:exec|run|cmd|command|shell)\b",
            re.I,
        ),
        "logging",
        "command execution",
    ),
    # cache/download -- temp storage fetching remote
    (
        re.compile(r"\b(?:cache|temp|tmp|scratch)\b", re.I),
        re.compile(
            r"\b(?:download|fetch|pull|install|load)\b",
            re.I,
        ),
        "cache",
        "download",
    ),
]


class PermissionScopeMismatch(Rule):
    rule_id = "R105"
    title = "Permission scope mismatch"
    severity = Severity.MEDIUM

    def check(self, tool: ToolInfo) -> list[Finding]:
        found: list[Finding] = []
        name_words = _decompose_name(tool.name)

        for name_pat, desc_pat, scope_name, desc_name in SCOPE_PAIRS:
            name_match = name_pat.search(tool.name)
            desc_match = desc_pat.search(tool.description)
            if name_match and desc_match:
                # Suppress if description contains bridge keywords AND
                # at least 2 name words appear in description
                desc_lower = tool.description.lower()
                is_bridge = any(kw in desc_lower for kw in BRIDGE_KEYWORDS)
                name_words_in_desc = sum(1 for w in name_words if w in desc_lower)
                if is_bridge and name_words_in_desc >= 2:
                    continue

                found.append(
                    self._finding(
                        tool.name,
                        f"Tool name is in '{scope_name}' scope but description "
                        f"mentions '{desc_name}' operations",
                        name_scope=scope_name,
                        description_scope=desc_name,
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
    title = "Dangerous tool name"
    severity = Severity.CRITICAL

    def check(self, tool: ToolInfo) -> list[Finding]:
        if tool.name.lower() in DANGEROUS_NAMES:
            return [
                self._finding(
                    tool.name,
                    f"'{tool.name}' matches a potentially dangerous system command",
                    matched_name=tool.name.lower(),
                )
            ]
        return []


# ---------------------------------------------------------------------------
# Rule engine -- collects and runs all rules
# ---------------------------------------------------------------------------


def _discover_plugins() -> list[Rule]:
    """Discover community rules via entry_points(group='mcpradar.rules')."""
    import logging

    try:
        from mcpradar._compat import get_entry_points
    except ImportError:
        return []

    logger = logging.getLogger("mcpradar.plugins")
    discovered: list[Rule] = []

    eps = list(get_entry_points("mcpradar.rules"))

    for ep in eps:
        try:
            rule_cls = ep.load()
            instance = rule_cls()
            if not isinstance(instance, Rule):
                logger.warning("Plugin %s does not inherit from Rule, skipping", ep.name)
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
            SecretExposureDetection(),
            CommandInjectionDetection(),
            SupplyChainRiskDetection(),
            SchemaPoisoningDetection(),
            VersionAnomalyDetection(),
            InsecureTransportDetection(),
            AuthorizationHardeningDetection(),
            PathTraversalDetection(),
            UnboundedInputDetection(),
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
                "source": "built-in"
                if isinstance(
                    r,
                    (
                        DangerousNameDetection,
                        ZeroWidthDetection,
                        PromptInjectionDetection,
                        EncodedBlobDetection,
                        HiddenContentDetection,
                        PermissionScopeMismatch,
                        SecretExposureDetection,
                        CommandInjectionDetection,
                        SupplyChainRiskDetection,
                        SchemaPoisoningDetection,
                        VersionAnomalyDetection,
                        InsecureTransportDetection,
                        AuthorizationHardeningDetection,
                        PathTraversalDetection,
                        UnboundedInputDetection,
                    ),
                )
                else "plugin",
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

    def pre_scan_check(
        self,
        baseline: object | None,
        current: object,
    ) -> list[Finding]:
        """Run fingerprint-based rules before tool-level analysis.

        Args:
            baseline: Previous ServerFingerprint or None (first scan).
            current: Current ServerFingerprint.
        """
        from mcpradar.fingerprint.fingerprinter import Fingerprinter
        from mcpradar.fingerprint.models import ServerFingerprint

        findings: list[Finding] = []
        if not isinstance(current, ServerFingerprint):
            return findings
        fp_baseline = baseline if isinstance(baseline, ServerFingerprint) else None
        fingerprinter = Fingerprinter()
        diff = fingerprinter.compare(fp_baseline, current)

        if diff.is_first_scan:
            findings.append(
                Finding(
                    rule_id="R110",
                    title="First scan; no baseline",
                    description="No previous fingerprint record found for this server",
                    severity=Severity.MEDIUM,
                    target=current.endpoint if hasattr(current, "endpoint") else "",
                    location="fingerprint",
                )
            )
            return findings

        # Rollback detection (CRITICAL)
        if diff.version_change == "rollback":
            findings.append(
                Finding(
                    rule_id="R110",
                    title="Version rollback attack detected",
                    description=(
                        f"Server version downgraded from {diff.previous_version} "
                        f"to {diff.current_version}; possible rollback attack"
                    ),
                    severity=Severity.CRITICAL,
                    target=current.endpoint if hasattr(current, "endpoint") else "",
                    location="fingerprint",
                    detail={
                        "previous": diff.previous_version,
                        "current": diff.current_version,
                    },
                )
            )

        # Unexpected major version upgrade (HIGH)
        if diff.version_change == "major_upgrade":
            findings.append(
                Finding(
                    rule_id="R110",
                    title="Unexpected major version upgrade",
                    description=(
                        f"Server version jumped from {diff.previous_version} "
                        f"to {diff.current_version} (major upgrade)"
                    ),
                    severity=Severity.HIGH,
                    target=current.endpoint if hasattr(current, "endpoint") else "",
                    location="fingerprint",
                    detail={
                        "previous": diff.previous_version,
                        "current": diff.current_version,
                    },
                )
            )

        # Tool list changed (HIGH)
        if diff.tool_names_changed:
            findings.append(
                Finding(
                    rule_id="R110",
                    title="Tool list changed",
                    description=(
                        f"Server tool list has changed since previous scan. "
                        f"Added: {len(diff.tools_added)}, "
                        f"Removed: {len(diff.tools_removed)}"
                    ),
                    severity=Severity.HIGH,
                    target=current.endpoint if hasattr(current, "endpoint") else "",
                    location="fingerprint",
                    detail={
                        "tools_added": diff.tools_added,
                        "tools_removed": diff.tools_removed,
                    },
                )
            )

        # TLS downgrade (HIGH)
        if diff.tls_downgrade:
            findings.append(
                Finding(
                    rule_id="R110",
                    title="TLS downgrade detected",
                    description="Server TLS version has been downgraded since previous scan",
                    severity=Severity.HIGH,
                    target=current.endpoint if hasattr(current, "endpoint") else "",
                    location="fingerprint",
                )
            )

        # Endpoint changed (HIGH)
        if diff.endpoint_changed:
            findings.append(
                Finding(
                    rule_id="R110",
                    title="Server address changed",
                    description="Same server identity observed at a different address",
                    severity=Severity.HIGH,
                    target=current.endpoint if hasattr(current, "endpoint") else "",
                    location="fingerprint",
                )
            )

        # Protocol changed (MEDIUM)
        if diff.protocol_changed:
            findings.append(
                Finding(
                    rule_id="R110",
                    title="MCP protocol version changed",
                    description="Server MCP protocol version has changed",
                    severity=Severity.MEDIUM,
                    target=current.endpoint if hasattr(current, "endpoint") else "",
                    location="fingerprint",
                )
            )

        return findings
