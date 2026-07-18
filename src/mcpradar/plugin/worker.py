"""Restricted subprocess entry point for community plugin rules."""

from __future__ import annotations

import json
import sys
from importlib.metadata import distributions
from pathlib import Path
from typing import Any


def _apply_resource_limits() -> None:
    try:
        import resource

        resource_api: Any = resource
        set_limit = getattr(resource, "setrlimit", None)
        if not callable(set_limit):
            return
        set_limit(resource_api.RLIMIT_CPU, (2, 2))
        set_limit(
            resource_api.RLIMIT_AS,
            (256 * 1024 * 1024, 256 * 1024 * 1024),
        )
        set_limit(resource_api.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
        set_limit(resource_api.RLIMIT_NOFILE, (64, 64))
    except (ImportError, OSError, ValueError):
        pass


def _install_audit_policy() -> None:
    def audit(event: str, args: tuple[object, ...]) -> None:
        if event.startswith(("socket.", "subprocess.")) or event in {
            "os.system",
            "os.posix_spawn",
            "ctypes.dlopen",
        }:
            raise PermissionError(f"plugin capability blocked: {event}")
        if event == "open" and len(args) > 1:
            mode = str(args[1])
            if any(flag in mode for flag in ("w", "a", "x", "+")):
                raise PermissionError("plugin filesystem writes are blocked")

    sys.addaudithook(audit)


def _entry_points(path: Path) -> dict[str, Any]:
    found: dict[str, Any] = {}
    for distribution in distributions(path=[str(path)]):
        for entry_point in distribution.entry_points:
            if entry_point.group == "mcpradar.rules":
                found[entry_point.name] = entry_point
    return found


def _describe(path: Path) -> dict[str, object]:
    from mcpradar.scanner.rules import Rule

    rules: list[dict[str, str]] = []
    for name, entry_point in _entry_points(path).items():
        instance = entry_point.load()()
        if not isinstance(instance, Rule):
            continue
        rules.append(
            {
                "entry_point": name,
                "rule_id": instance.rule_id,
                "title": instance.title,
                "severity": instance.severity.value,
            }
        )
    return {"rules": rules}


def _check(path: Path, selected: str, payload: dict[str, Any]) -> dict[str, object]:
    from mcpradar.scanner.report import ToolInfo
    from mcpradar.scanner.rules import Rule

    entry_point = _entry_points(path).get(selected)
    if entry_point is None:
        raise LookupError(f"entry point not found: {selected}")
    instance = entry_point.load()()
    if not isinstance(instance, Rule):
        raise TypeError("entry point does not produce a Rule")
    tool = ToolInfo(
        name=str(payload.get("name", "")),
        description=str(payload.get("description", "")),
        input_schema=payload.get("input_schema", {})
        if isinstance(payload.get("input_schema"), dict)
        else {},
        output_schema=payload.get("output_schema", {})
        if isinstance(payload.get("output_schema"), dict)
        else {},
    )
    findings = [
        {
            "rule_id": finding.rule_id,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity.value,
            "target": finding.target,
            "location": finding.location,
            "evidence": finding.evidence,
            "detail": finding.detail,
        }
        for finding in instance.check(tool)
    ]
    return {"findings": findings}


def main() -> int:
    if len(sys.argv) != 4:
        return 2
    action, raw_path, selected = sys.argv[1:]
    path = Path(raw_path).resolve()
    if not path.is_dir():
        return 2
    sys.path.insert(0, str(path))
    sys.dont_write_bytecode = True
    _apply_resource_limits()
    _install_audit_policy()
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        if not isinstance(payload, dict):
            return 2
        output = _describe(path) if action == "describe" else _check(path, selected, payload)
        sys.stdout.write(json.dumps(output))
        return 0
    except Exception as exc:
        sys.stderr.write(f"{type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
