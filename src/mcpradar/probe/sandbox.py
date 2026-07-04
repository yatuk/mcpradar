"""Sandbox validator — argument safety and write-capability checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mcpradar.scanner.report import ToolInfo

# ---------------------------------------------------------------------------
# SandboxPolicy
# ---------------------------------------------------------------------------


@dataclass
class SandboxPolicy:
    """Policy parameters for sandbox argument validation."""

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
    """Validates and sanitizes tool arguments using security policies.

    Purpose: prevent accidental write/modify/delete operations
    during probing.
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
        """Validate arguments recursively.

        Checks:
        - Depth > max_args_depth: rejected
        - String value length > max_arg_string_length: rejected
        - String value (lowered) in forbidden_arg_values: rejected

        Returns:
            (is_safe, reason_string). reason is empty when is_safe=True.
        """
        if depth > self.policy.max_args_depth:
            return False, f"Argument depth limit ({self.policy.max_args_depth}) exceeded"

        for key, value in args.items():
            result = self._validate_value(value, str(key), depth)
            if not result[0]:
                return result

        return True, ""

    def _validate_value(self, value: Any, path: str, depth: int) -> tuple[bool, str]:
        """Recursively validate a single value."""
        if isinstance(value, str):
            lowered = value.lower()
            if lowered in self.policy.forbidden_arg_values:
                return (
                    False,
                    f"Forbidden argument value detected: '{value}' ({path})",
                )
            if len(value) > self.policy.max_arg_string_length:
                return (
                    False,
                    f"Argument too long ({len(value)} > "
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
        """Replace unsafe values with safe alternatives.

        - Long strings are truncated to max_arg_string_length
        - Forbidden values are replaced with "test"
        - Deeply nested values become None (in parent dict)

        Creates a new dict, original is unchanged.
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
                # Skip None results (depth exceeded etc.)
                if result is not None or not isinstance(val, (dict, list)):
                    sanitized[key] = result if result is not None else val
            return sanitized

        if isinstance(value, list):
            return [self._sanitize_value(item, depth + 1) for item in value]

        return value

    # ------------------------------------------------------------------
    # Write capability detection
    # ------------------------------------------------------------------

    def is_write_tool(self, tool: ToolInfo | None = None, *, name: str = "", description: str = "") -> bool:
        """Return True if tool name or description contains WRITE_KEYWORDS.

        Can be called with a ToolInfo object, OR with plain name+description
        for SDK usage without scanner model dependencies.
        """
        if tool is not None:
            name_lower = tool.name.lower()
            desc_lower = tool.description.lower()
        else:
            name_lower = name.lower()
            desc_lower = description.lower()

        return any(kw in name_lower or kw in desc_lower for kw in self.WRITE_KEYWORDS)
