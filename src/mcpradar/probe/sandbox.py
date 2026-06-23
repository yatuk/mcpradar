"""Sandbox validator — arguman guvenligi ve yazma-kabiliyeti kontrolu."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mcpradar.scanner.report import ToolInfo

# ---------------------------------------------------------------------------
# SandboxPolicy
# ---------------------------------------------------------------------------


@dataclass
class SandboxPolicy:
    """Sandbox arguman dogrulamasi icin politika parametreleri."""

    max_args_depth: int = 3
    max_arg_string_length: int = 50
    forbidden_arg_values: set[str] = field(
        default_factory=lambda: {
            "rm -rf",
            "/",
            "/etc/passwd",
            "drop table",
            "shutdown",
            "true",
            "1",
            "admin",
            "root",
        }
    )


# ---------------------------------------------------------------------------
# SandboxValidator
# ---------------------------------------------------------------------------


class SandboxValidator:
    """Tool argumanlarini guvenlik politikalariyla dogrular ve temizler.

    Amac: probe sirasinda yanlislikla yazma/degistirme/silme islemi
    yapilmasini engellemek.
    """

    WRITE_KEYWORDS: set[str] = {
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

    def __init__(self, policy: SandboxPolicy | None = None) -> None:
        self.policy = policy or SandboxPolicy()

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate_args(self, args: dict[str, Any], depth: int = 0) -> tuple[bool, str]:
        """Argumanlari recursive olarak dogrular.

        Kontroller:
        - Derinlik > max_args_depth: reddedilir
        - String deger uzunlugu > max_arg_string_length: reddedilir
        - String deger (lowered) forbidden_arg_values icinde: reddedilir

        Returns:
            (is_safe, reason_string). is_safe=True ise reason bos olur.
        """
        if depth > self.policy.max_args_depth:
            return False, f"Arguman derinligi siniri ({self.policy.max_args_depth}) asildi"

        for key, value in args.items():
            result = self._validate_value(value, str(key), depth)
            if not result[0]:
                return result

        return True, ""

    def _validate_value(self, value: Any, path: str, depth: int) -> tuple[bool, str]:
        """Tek bir degeri recursive dogrula."""
        if isinstance(value, str):
            lowered = value.lower()
            if lowered in self.policy.forbidden_arg_values:
                return (
                    False,
                    f"Yasakli arguman degeri tespit edildi: '{value}' ({path})",
                )
            if len(value) > self.policy.max_arg_string_length:
                return (
                    False,
                    f"Arguman cok uzun ({len(value)} > "
                    f"{self.policy.max_arg_string_length}): {path}",
                )
        elif isinstance(value, dict):
            inner_result = self.validate_args(value, depth + 1)
            if not inner_result[0]:
                return inner_result
        elif isinstance(value, list):
            for idx, item in enumerate(value):
                result = self._validate_value(item, f"{path}[{idx}]", depth + 1)
                if not result[0]:
                    return result

        return True, ""

    # ------------------------------------------------------------------
    # Sanitization
    # ------------------------------------------------------------------

    def sanitize_args(self, args: dict[str, Any]) -> dict[str, Any]:
        """Guvenli olmayan degerleri guvenli alternatiflerle degistirir.

        - Uzun string'ler max_arg_string_length'e kisaltilir
        - Yasakli degerler "test" ile degistirilir
        - Derin ic ice gecmis degerler None yapilir (ust dict'te)

        Yeni bir dict olusturur, orijinal degismez.
        """
        result = self._sanitize_value(args, 0)
        if not isinstance(result, dict):
            return {}
        return result

    def _sanitize_value(self, value: Any, depth: int) -> Any:
        """Recursive sanitization."""
        if depth > self.policy.max_args_depth:
            return None

        if isinstance(value, str):
            lowered = value.lower()
            if lowered in self.policy.forbidden_arg_values:
                return "test"
            if len(value) > self.policy.max_arg_string_length:
                return value[: self.policy.max_arg_string_length]
            return value

        if isinstance(value, dict):
            sanitized: dict[str, Any] = {}
            for key, val in value.items():
                result = self._sanitize_value(val, depth + 1)
                # None sonuclari ekleme (derinlik asimi vs.)
                if result is not None or not isinstance(val, (dict, list)):
                    sanitized[key] = result if result is not None else val
            return sanitized

        if isinstance(value, list):
            return [self._sanitize_value(item, depth + 1) for item in value]

        return value

    # ------------------------------------------------------------------
    # Write capability detection
    # ------------------------------------------------------------------

    def is_write_tool(self, tool: ToolInfo) -> bool:
        """Tool adi veya description'i WRITE_KEYWORDS iceriyorsa True doner.

        Bu, write/exec/shell capable tool'lari belirlemek icin kullanilir.
        """
        name_lower = tool.name.lower()
        desc_lower = tool.description.lower()

        return any(kw in name_lower or kw in desc_lower for kw in self.WRITE_KEYWORDS)
