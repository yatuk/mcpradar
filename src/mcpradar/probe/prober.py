"""Read-only MCP tool probing — safe runtime execution for response scanning."""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcp import ClientSession

    from mcpradar.scanner.report import ToolInfo

from mcpradar.scanner.rules import PROMPT_INJECTION_PATTERNS, SECRET_PATTERNS

# Import SandboxValidator lazily to avoid circular imports
from mcpradar.probe.sandbox import SandboxValidator

# ---------------------------------------------------------------------------
# ProbeResult
# ---------------------------------------------------------------------------


@dataclass
class ProbeResult:
    """Result of executing a single tool probe."""

    tool_name: str
    server_name: str
    success: bool
    response_time_ms: float
    response_preview: str  # Ilk 500 karakter
    contains_urls: bool
    contains_scripts: bool
    contains_secrets: bool
    contains_prompt_injection: bool
    error_message: str = ""
    finding_ids: list[str] = field(default_factory=list)  # R102 / R106 bulgu rule_id'leri

    def to_dict(self) -> dict[str, Any]:
        """Convert ProbeResult to a serializable dict."""
        return {
            "tool_name": self.tool_name,
            "server_name": self.server_name,
            "success": self.success,
            "response_time_ms": self.response_time_ms,
            "response_preview": self.response_preview,
            "contains_urls": self.contains_urls,
            "contains_scripts": self.contains_scripts,
            "contains_secrets": self.contains_secrets,
            "contains_prompt_injection": self.contains_prompt_injection,
            "error_message": self.error_message,
            "finding_ids": self.finding_ids,
        }


# ---------------------------------------------------------------------------
# ReadOnlyProber
# ---------------------------------------------------------------------------


class ReadOnlyProber:
    """Sadece okuma-amacli gorunen tool'lari guvenli parametrelerle calistirir
    ve donen yanitlari tarar.

    Amac: statik analizde yakalanamayan dinamik tehditleri (gizli URL'ler,
    script enjeksiyonu, token sizintisi) tespit etmek.

    When *sandbox_validator* is provided (via ``--sandbox`` CLI flag), also:
    - Excludes write-capable tools detected by the sandbox validator
    - Validates and sanitizes generated arguments before probe execution
    """

    SAFE_TOOL_PATTERNS: list[re.Pattern[str]] = [
        re.compile(r"^(get|list|read|fetch|search|query|browse|show|describe)", re.I),
    ]

    DANGEROUS_KEYWORDS: set[str] = {
        "write",
        "create",
        "delete",
        "remove",
        "modify",
        "update",
        "exec",
        "run",
        "spawn",
        "shell",
        "sudo",
        "kill",
        "stop",
    }

    MAX_PROBE_COUNT: int = 20
    PROBE_TIMEOUT: float = 5.0

    def __init__(self, sandbox_validator: SandboxValidator | None = None) -> None:
        self.sandbox_validator = sandbox_validator

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_safe_tool(self, tool: ToolInfo) -> bool:
        """Tool adi safe pattern'lerden birine uyuyor MU VE
        description DANGEROUS_KEYWORDS icermiyorsa True doner.

        If sandbox validator is configured, also rejects write-capable tools
        detected by the sandbox validator's is_write_tool() check.

        Her iki kosul da saglanmali.
        """
        name_safe = any(p.search(tool.name) for p in self.SAFE_TOOL_PATTERNS)
        if not name_safe:
            return False

        desc_lower = tool.description.lower()
        if any(kw in desc_lower for kw in self.DANGEROUS_KEYWORDS):
            return False

        # Sandbox: exclude write-capable tools
        if self.sandbox_validator is not None:
            if self.sandbox_validator.is_write_tool(tool):
                return False

        return True

    def generate_minimal_args(self, tool: ToolInfo) -> dict[str, Any]:
        """Tool'un input_schema'sindaki required alanlar icin minimal guvenli degerler uretir.

        Her tip icin:
        - "string": "test" (veya schema'daki default deger)
        - "number" veya "integer": 0
        - "boolean": False
        - "array": [] (items default'u varsa [default])
        - "object": {}
        - tip belirtilmemis: "test"
        """
        schema = tool.input_schema
        if not isinstance(schema, dict) or not schema:
            return {}

        # Hic properties yoksa bos don
        properties = schema.get("properties")
        if not isinstance(properties, dict) or not properties:
            return {}

        required: set[str] = set(schema.get("required", []))
        if not required:
            return {}

        return self._build_args_from_properties(properties, required)

    def _build_args_from_properties(
        self,
        properties: dict[str, Any],
        required: set[str],
    ) -> dict[str, Any]:
        """Build minimal args dict from schema properties only for required fields."""
        args: dict[str, Any] = {}
        for prop_name, prop_schema in properties.items():
            if prop_name not in required:
                continue
            if not isinstance(prop_schema, dict):
                args[prop_name] = "test"
                continue

            # default varsa onu kullan
            if "default" in prop_schema:
                args[prop_name] = prop_schema["default"]
                continue

            prop_type = prop_schema.get("type")

            if prop_type == "string":
                args[prop_name] = "test"
            elif prop_type in ("number", "integer"):
                args[prop_name] = 0
            elif prop_type == "boolean":
                args[prop_name] = False
            elif prop_type == "array":
                # items icinde default varsa kullan
                items = prop_schema.get("items")
                if isinstance(items, dict) and "default" in items:
                    args[prop_name] = [items["default"]]
                else:
                    args[prop_name] = []
            elif prop_type == "object":
                args[prop_name] = {}
            else:
                # tip belirtilmemis ya da taninmayan tip
                args[prop_name] = "test"
        return args

    async def probe_tool(
        self,
        session: ClientSession,
        tool: ToolInfo,
        server_name: str = "",
    ) -> ProbeResult:
        """Tek bir tool'u guvenli parametrelerle calistirir ve yaniti tarar.

        Adimlar:
        1. Minimal arguman uret
        2. Zaman olcumu baslat
        3. PROBE_TIMEOUT suresiyle call_tool
        4. Yanit text'ini cikar
        5. URL, script, secret, prompt injection tara
        6. ProbeResult dondur
        7. Timeout veya hata durumunda success=False
        """
        args = self.generate_minimal_args(tool)

        # Sandbox: validate and sanitize arguments before probe
        if self.sandbox_validator is not None and args:
            is_safe, reason = self.sandbox_validator.validate_args(args)
            if not is_safe:
                # Sanitize dangerous args and try again
                args = self.sandbox_validator.sanitize_args(args)

        try:
            start = time.perf_counter()
            result = await asyncio.wait_for(
                session.call_tool(tool.name, arguments=args),
                timeout=self.PROBE_TIMEOUT,
            )
            elapsed = time.perf_counter() - start
            response_time_ms = elapsed * 1000.0

            # Extract text from CallToolResult.content
            text = self._extract_response_text(result)
            response_preview = text[:500]

            # Scan response
            contains_urls, contains_scripts = self._scan_dynamic_patterns(text)
            contains_secrets, secret_ids = self._scan_secrets(text)
            contains_prompt_injection, pi_ids = self._scan_prompt_injection(text)

            finding_ids: list[str] = []
            finding_ids.extend(pi_ids)
            finding_ids.extend(secret_ids)

            return ProbeResult(
                tool_name=tool.name,
                server_name=server_name,
                success=True,
                response_time_ms=response_time_ms,
                response_preview=response_preview,
                contains_urls=contains_urls,
                contains_scripts=contains_scripts,
                contains_secrets=contains_secrets,
                contains_prompt_injection=contains_prompt_injection,
                finding_ids=finding_ids,
            )

        except TimeoutError:
            return ProbeResult(
                tool_name=tool.name,
                server_name=server_name,
                success=False,
                response_time_ms=0.0,
                response_preview="",
                contains_urls=False,
                contains_scripts=False,
                contains_secrets=False,
                contains_prompt_injection=False,
                error_message=f"Timeout ({self.PROBE_TIMEOUT}s) asildi",
            )

        except Exception as exc:
            return ProbeResult(
                tool_name=tool.name,
                server_name=server_name,
                success=False,
                response_time_ms=0.0,
                response_preview="",
                contains_urls=False,
                contains_scripts=False,
                contains_secrets=False,
                contains_prompt_injection=False,
                error_message=str(exc),
            )

    async def probe_all(
        self,
        session: ClientSession,
        tools: list[ToolInfo],
        server_name: str = "",
    ) -> list[ProbeResult]:
        """Guvenli tool'lari filtrele, sirali calistir (en fazla MAX_PROBE_COUNT), sonuclari don."""
        safe_tools = [t for t in tools if self.is_safe_tool(t)]
        results: list[ProbeResult] = []

        for idx, tool in enumerate(safe_tools):
            if idx >= self.MAX_PROBE_COUNT:
                break
            result = await self.probe_tool(session, tool, server_name)
            results.append(result)

        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_response_text(result: Any) -> str:
        """CallToolResult.content listesinden metin icerigini cikarir.

        Her content ogesinde .text attribute'u varsa toplar, yoksa gormezden gelir.
        """
        parts: list[str] = []
        try:
            content = result.content
        except AttributeError:
            return ""

        if not isinstance(content, list):
            return ""

        for item in content:
            item_text = getattr(item, "text", None)
            if isinstance(item_text, str) and item_text:
                parts.append(item_text)

        return "\n".join(parts)

    @staticmethod
    def _scan_dynamic_patterns(text: str) -> tuple[bool, bool]:
        """Yanit metninde URL ve script/exec pattern'lerini tara.

        Returns:
            (contains_urls, contains_scripts)
        """
        # URL detection
        url_pattern = re.compile(r'https?://[^\s"\'<>]+')
        contains_urls = bool(url_pattern.search(text))

        # Script / exec detection
        script_pattern = re.compile(
            r"<(script|iframe)|\beval\s*\(|\bexec\s*\(",
            re.IGNORECASE,
        )
        contains_scripts = bool(script_pattern.search(text))

        return contains_urls, contains_scripts

    @staticmethod
    def _scan_secrets(text: str) -> tuple[bool, list[str]]:
        """Yanit metnini SECRET_PATTERNS ile tara.

        Returns:
            (contains_secrets, [rule_id listesi])
        """
        contains = False
        finding_ids: list[str] = []
        for pattern, _label in SECRET_PATTERNS:
            if pattern.search(text):
                contains = True
                finding_ids.append("R106")
                break  # Her pattern icin ayri id eklemeye gerek yok, R106 yeterli
        return contains, finding_ids

    @staticmethod
    def _scan_prompt_injection(text: str) -> tuple[bool, list[str]]:
        """Yanit metnini PROMPT_INJECTION_PATTERNS ile tara.

        Returns:
            (contains_prompt_injection, [rule_id listesi])
        """
        contains = False
        finding_ids: list[str] = []
        for pattern, _label, _severity in PROMPT_INJECTION_PATTERNS:
            if pattern.search(text):
                contains = True
                finding_ids.append("R102")
                # Ilk eslesmede yeterli; tum pattern'leri tek tek raporlamaya gerek yok
                break
        return contains, finding_ids
