"""Isolated plugin worker and explicit allowlist tests."""

from __future__ import annotations

from pathlib import Path

from mcpradar.plugin.manager import PluginManager
from mcpradar.plugin.runtime import IsolatedPluginRule, discover_descriptors
from mcpradar.scanner.report import ToolInfo


def _make_plugin(root: Path) -> None:
    (root / "demo_plugin.py").write_text(
        """
from mcpradar.scanner.report import Severity
from mcpradar.scanner.rules import Rule

class DemoRule(Rule):
    rule_id = "X901"
    title = "Isolated demo"
    severity = Severity.MEDIUM

    def check(self, tool):
        if tool.name == "bad":
            return [self._finding(tool.name, "isolated finding")]
        return []
""",
        encoding="utf-8",
    )
    dist = root / "demo_plugin-1.0.dist-info"
    dist.mkdir()
    (dist / "METADATA").write_text("Name: demo-plugin\nVersion: 1.0\n", encoding="utf-8")
    (dist / "entry_points.txt").write_text(
        "[mcpradar.rules]\ndemo = demo_plugin:DemoRule\n", encoding="utf-8"
    )


def test_plugin_runs_out_of_process(tmp_path: Path) -> None:
    _make_plugin(tmp_path)
    descriptors = discover_descriptors(tmp_path, "demo-plugin")
    assert [descriptor.rule_id for descriptor in descriptors] == ["X901"]
    rule = IsolatedPluginRule(descriptors[0])
    findings = rule.check(ToolInfo(name="bad"))
    assert [finding.rule_id for finding in findings] == ["X901"]


def test_plugin_manager_requires_exact_pin_and_hash(tmp_path: Path) -> None:
    manager = PluginManager(root=tmp_path)
    ok, message = manager.install("demo-plugin")
    assert not ok
    assert "pinned" in message


def test_plugins_are_not_loaded_without_allowlist(tmp_path: Path) -> None:
    manager = PluginManager(root=tmp_path)
    assert manager.load_rules(set()) == []
