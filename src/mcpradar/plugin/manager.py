"""Plugin manager — install, uninstall, list community plugins via pip."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any

from mcpradar._compat import get_entry_points


@dataclass
class PluginInfo:
    """Metadata about an installed community plugin."""

    name: str
    version: str = "?"
    author: str = "?"
    description: str = ""
    rule_ids: list[str] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)


class PluginManager:
    """Manages community plugin lifecycle via pip + importlib.metadata."""

    def install(self, package: str) -> tuple[bool, str]:
        """pip install + validate. Returns (success, message)."""
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", package],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            error_msg = result.stderr.strip().split("\n")[-1] if result.stderr else "Unknown error"
            return False, f"Kurulum basarisiz: {error_msg}"

        # Validate by discovering plugins
        from mcpradar.scanner.rules import _discover_plugins

        discovered = _discover_plugins()
        package_rules = [
            r for r in discovered if type(r).__module__.startswith(package.replace("-", "_"))
        ]
        if package_rules:
            rule_ids = ", ".join(r.rule_id for r in package_rules)
            msg = (
                f"Plugin '{package}' kuruldu ve dogrulandi ({len(package_rules)} kural: {rule_ids})"
            )
            return (True, msg)
        return True, f"Plugin '{package}' kuruldu (kural bulunamadi — entry_point kontrol edin)"

    def uninstall(self, package: str) -> tuple[bool, str]:
        """pip uninstall. Returns (success, message)."""
        result = subprocess.run(
            [sys.executable, "-m", "pip", "uninstall", "-y", package],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            error_msg = result.stderr.strip().split("\n")[-1] if result.stderr else "Unknown error"
            return False, f"Kaldirma basarisiz: {error_msg}"
        return True, f"Plugin '{package}' kaldirildi"

    def list_plugins(self) -> list[PluginInfo]:
        """List all installed community plugins with metadata."""
        from importlib.metadata import PackageNotFoundError, metadata

        eps = list(get_entry_points("mcpradar.rules"))

        # Group entry points by package
        by_package: dict[str, list[Any]] = {}
        for ep in eps:
            # Get package name: prefer ep.dist.name, fallback to module path
            pkg_name = self._get_package_name(ep)
            by_package.setdefault(pkg_name, []).append(ep)

        plugins: list[PluginInfo] = []
        for pkg_name, eps_list in by_package.items():
            try:
                # Skip built-in package (mcpradar itself)
                if pkg_name == "mcpradar":
                    continue

                meta = metadata(pkg_name)
                rule_ids = self._resolve_rule_ids(eps_list)

                plugins.append(
                    PluginInfo(
                        name=pkg_name,
                        version=self._meta_get(meta, "Version", "?"),
                        author=self._meta_get(
                            meta, "Author", self._meta_get(meta, "Author-email", "?")
                        ),
                        description=self._meta_get(meta, "Summary", ""),
                        rule_ids=rule_ids,
                        entry_points=[ep.name for ep in eps_list],
                    )
                )
            except PackageNotFoundError:
                continue

        return plugins

    @staticmethod
    def _get_package_name(ep: Any) -> str:
        """Extract package name from an EntryPoint object."""
        # Python 3.12+: ep.dist.name is available
        if hasattr(ep, "dist") and ep.dist is not None:
            return str(ep.dist.name)
        # Fallback: extract from ep.value (e.g. "mcpradar_rule_example.rule:ExampleRule")
        value = ep.value if hasattr(ep, "value") else str(ep)
        module_part = value.split(":")[0]
        return module_part.split(".")[0]

    @staticmethod
    def _meta_get(meta: Any, key: str, default: str) -> str:
        """Safely read a metadata field with a fallback."""
        try:
            return str(meta[key])
        except (KeyError, TypeError):
            return default

    @staticmethod
    def _resolve_rule_ids(eps_list: list[Any]) -> list[str]:
        """Try to instantiate each entry point and extract rule_id."""
        rule_ids: list[str] = []
        for ep in eps_list:
            try:
                cls = ep.load()
                instance = cls()
                rule_ids.append(instance.rule_id)
            except Exception:
                rule_ids.append("?")
        return rule_ids
