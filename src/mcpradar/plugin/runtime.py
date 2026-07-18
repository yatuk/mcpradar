"""Out-of-process execution for explicitly enabled community rules."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcpradar.scanner.report import Finding, Severity, ToolInfo
from mcpradar.scanner.rules import Rule

_WORKER_TIMEOUT = 5.0
_MAX_WORKER_OUTPUT = 1_048_576


class PluginRuntimeError(RuntimeError):
    """An isolated plugin worker failed or violated its limits."""


@dataclass(frozen=True)
class PluginDescriptor:
    package: str
    entry_point: str
    rule_id: str
    title: str
    severity: str
    path: str


class IsolatedPluginRule(Rule):
    """Rule proxy that never imports plugin code into the scanner process."""

    def __init__(self, descriptor: PluginDescriptor) -> None:
        self.descriptor = descriptor
        self.rule_id = descriptor.rule_id
        self.title = descriptor.title
        self.severity = Severity.from_str(descriptor.severity)

    def check(self, tool: ToolInfo) -> list[Finding]:
        result = run_worker(
            Path(self.descriptor.path),
            "check",
            self.descriptor.entry_point,
            {
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.input_schema,
                "output_schema": tool.output_schema,
            },
        )
        findings = result.get("findings", [])
        if not isinstance(findings, list):
            raise PluginRuntimeError("plugin returned an invalid findings payload")
        parsed: list[Finding] = []
        for item in findings:
            if not isinstance(item, dict):
                continue
            parsed.append(
                Finding(
                    rule_id=str(item.get("rule_id", self.rule_id)),
                    title=str(item.get("title", self.title)),
                    description=str(item.get("description", "")),
                    severity=Severity.from_str(str(item.get("severity", self.severity.value))),
                    target=str(item.get("target", tool.name)),
                    location=str(item.get("location", "tool")),
                    evidence=str(item.get("evidence", "")),
                    detail=item.get("detail", {}) if isinstance(item.get("detail"), dict) else {},
                )
            )
        return parsed


def discover_descriptors(path: Path, package: str) -> list[PluginDescriptor]:
    result = run_worker(path, "describe", "", {})
    raw = result.get("rules", [])
    if not isinstance(raw, list):
        raise PluginRuntimeError("plugin descriptor payload is invalid")
    descriptors: list[PluginDescriptor] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        descriptors.append(
            PluginDescriptor(
                package=package,
                entry_point=str(item["entry_point"]),
                rule_id=str(item["rule_id"]),
                title=str(item["title"]),
                severity=str(item["severity"]),
                path=str(path),
            )
        )
    return descriptors


def run_worker(
    path: Path, action: str, entry_point: str, payload: dict[str, Any]
) -> dict[str, Any]:
    env = {
        key: value
        for key, value in os.environ.items()
        if key in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LANG"}
    }
    env["PYTHONNOUSERSITE"] = "1"
    command = [
        sys.executable,
        "-m",
        "mcpradar.plugin.worker",
        action,
        str(path),
        entry_point,
    ]
    try:
        result = subprocess.run(
            command,
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=_WORKER_TIMEOUT,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PluginRuntimeError(f"plugin worker failed: {exc}") from None
    if len(result.stdout) > _MAX_WORKER_OUTPUT or len(result.stderr) > _MAX_WORKER_OUTPUT:
        raise PluginRuntimeError("plugin worker exceeded its output limit")
    if result.returncode != 0:
        detail = result.stderr.strip()[-500:] or "unknown worker error"
        raise PluginRuntimeError(f"plugin worker rejected: {detail}")
    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise PluginRuntimeError("plugin worker returned invalid JSON") from None
    if not isinstance(output, dict):
        raise PluginRuntimeError("plugin worker returned a non-object payload")
    return output
