"""Pinned, isolated community plugin lifecycle management."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from platformdirs import user_data_dir

from mcpradar.plugin.runtime import (
    IsolatedPluginRule,
    PluginRuntimeError,
    discover_descriptors,
)

_PINNED_PACKAGE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s=]+)$")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass
class PluginInfo:
    """Metadata about an installed isolated plugin."""

    name: str
    version: str = "?"
    author: str = "?"
    description: str = ""
    rule_ids: list[str] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)


class PluginManager:
    """Install wheel-only plugins into a dedicated, non-imported directory."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = root or Path(user_data_dir("mcpradar")) / "plugins"
        self.manifest_path = self.root / "manifest.json"

    def install(self, package: str, sha256: str | None = None) -> tuple[bool, str]:
        """Install an exact-version wheel after caller-provided hash verification."""
        match = _PINNED_PACKAGE.fullmatch(package)
        if match is None:
            return False, "Plugin packages must be pinned exactly (name==version)"
        if sha256 is None or _SHA256.fullmatch(sha256) is None:
            return False, "Plugin installation requires a 64-character --sha256 wheel digest"
        name, version = match.groups()
        self.root.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory(prefix="mcpradar-plugin-") as temp:
            download = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "download",
                    "--no-deps",
                    "--only-binary=:all:",
                    "--dest",
                    temp,
                    package,
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if download.returncode != 0:
                detail = download.stderr.strip().splitlines()[-1] if download.stderr else "unknown"
                return False, f"Download failed: {detail}"
            wheels = list(Path(temp).glob("*.whl"))
            if len(wheels) != 1:
                return False, "Plugin download did not produce exactly one wheel"
            wheel = wheels[0]
            actual = hashlib.sha256(wheel.read_bytes()).hexdigest()
            if actual.lower() != sha256.lower():
                return False, "Plugin wheel digest does not match --sha256"

            target = self.root / "packages" / f"{name.lower().replace('-', '_')}-{version}"
            if target.exists():
                return False, f"Plugin '{package}' is already installed"
            target.mkdir(parents=True)
            install = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    "--no-deps",
                    "--target",
                    str(target),
                    str(wheel),
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if install.returncode != 0:
                shutil.rmtree(target, ignore_errors=True)
                detail = install.stderr.strip().splitlines()[-1] if install.stderr else "unknown"
                return False, f"Install failed: {detail}"

        try:
            descriptors = discover_descriptors(target, name)
        except PluginRuntimeError as exc:
            shutil.rmtree(target, ignore_errors=True)
            return False, f"Plugin validation failed: {exc}"
        if not descriptors:
            shutil.rmtree(target, ignore_errors=True)
            return False, "Plugin contains no mcpradar.rules entry points"

        manifest = self._load_manifest()
        manifest[name] = {
            "name": name,
            "version": version,
            "path": str(target),
            "sha256": sha256.lower(),
        }
        self._save_manifest(manifest)
        rule_ids = ", ".join(descriptor.rule_id for descriptor in descriptors)
        return True, f"Plugin '{package}' installed in isolation ({rule_ids})"

    def uninstall(self, package: str) -> tuple[bool, str]:
        """Remove a plugin directory recorded in the managed manifest."""
        name = package.split("==", 1)[0]
        manifest = self._load_manifest()
        item = manifest.get(name)
        if item is None:
            return False, f"Plugin '{name}' is not installed"
        target = Path(str(item.get("path", ""))).resolve()
        packages_root = (self.root / "packages").resolve()
        if not target.is_relative_to(packages_root):
            return False, "Refusing to remove a plugin outside the managed plugin directory"
        shutil.rmtree(target, ignore_errors=True)
        del manifest[name]
        self._save_manifest(manifest)
        return True, f"Plugin '{name}' uninstalled"

    def list_plugins(self) -> list[PluginInfo]:
        plugins: list[PluginInfo] = []
        for name, item in self._load_manifest().items():
            try:
                descriptors = discover_descriptors(Path(str(item["path"])), name)
            except (KeyError, PluginRuntimeError):
                descriptors = []
            plugins.append(
                PluginInfo(
                    name=name,
                    version=str(item.get("version", "?")),
                    rule_ids=[descriptor.rule_id for descriptor in descriptors],
                    entry_points=[descriptor.entry_point for descriptor in descriptors],
                )
            )
        return plugins

    def load_rules(self, allowlist: set[str]) -> list[IsolatedPluginRule]:
        rules: list[IsolatedPluginRule] = []
        for name, item in self._load_manifest().items():
            if name not in allowlist:
                continue
            try:
                descriptors = discover_descriptors(Path(str(item["path"])), name)
            except (KeyError, PluginRuntimeError):
                continue
            rules.extend(IsolatedPluginRule(descriptor) for descriptor in descriptors)
        return rules

    def _load_manifest(self) -> dict[str, dict[str, str]]:
        try:
            payload = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return payload if isinstance(payload, dict) else {}

    def _save_manifest(self, manifest: dict[str, dict[str, str]]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
        )
