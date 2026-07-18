"""Plugin loading tests."""

from __future__ import annotations

from unittest.mock import patch

from mcpradar.scanner.report import Finding, Severity, ToolInfo
from mcpradar.scanner.rules import Rule, RuleEngine


class _FakePlugin(Rule):
    rule_id = "X999"
    title = "Test plugin rule"
    severity = Severity.MEDIUM

    def check(self, tool: ToolInfo) -> list[Finding]:
        return []


class TestPluginDiscovery:
    def test_builtin_rules_always_loaded(self) -> None:
        engine = RuleEngine(min_severity=Severity("low"))
        rule_ids = {r["rule_id"] for r in engine.loaded_rules}
        assert "R001" in rule_ids
        assert "R101" in rule_ids
        assert "R102" in rule_ids

    @patch("mcpradar.scanner.rules._discover_plugins")
    def test_plugin_loaded_via_discovery(self, mock_discover) -> None:
        mock_discover.return_value = [_FakePlugin()]
        engine = RuleEngine(min_severity=Severity("low"), enabled_plugins=["demo"])
        rule_ids = {r["rule_id"] for r in engine.loaded_rules}
        assert "X999" in rule_ids

    @patch("mcpradar.scanner.rules._discover_plugins")
    def test_plugin_not_loaded_if_not_rule_instance(self, mock_discover) -> None:
        class NotARule:
            rule_id = "Y001"
            title = "Not a rule"

        mock_discover.return_value = [NotARule()]
        engine = RuleEngine(min_severity=Severity("low"), enabled_plugins=["demo"])
        rule_ids = {r["rule_id"] for r in engine.loaded_rules}
        assert "Y001" not in rule_ids

    def test_disable_rule(self) -> None:
        engine = RuleEngine(
            min_severity=Severity("low"),
            disabled_rules=["R001"],
        )
        rule_ids = {r["rule_id"] for r in engine.loaded_rules}
        assert "R001" not in rule_ids
        assert "R101" in rule_ids  # still loaded

    def test_disable_nonexistent(self) -> None:
        engine = RuleEngine(min_severity=Severity("low"))
        result = engine.disable("ZZZ99")
        assert result is False

    def test_disable_then_disable_again(self) -> None:
        engine = RuleEngine(min_severity=Severity("low"))
        engine.disable("R001")
        result = engine.disable("R001")
        assert result is False  # Already disabled

    def test_register_custom_rule(self) -> None:
        engine = RuleEngine(min_severity=Severity("low"))
        engine.register(_FakePlugin())
        rule_ids = {r["rule_id"] for r in engine.loaded_rules}
        assert "X999" in rule_ids

    def test_loaded_rules_metadata(self) -> None:
        engine = RuleEngine(min_severity=Severity("low"))
        for r in engine.loaded_rules:
            assert "rule_id" in r
            assert "title" in r
            assert "severity" in r
            assert "source" in r
            assert r["source"] in ("built-in", "plugin")

    def test_discover_plugins_empty_when_no_entry_points(self) -> None:
        from mcpradar.scanner.rules import _discover_plugins

        plugins = _discover_plugins()
        assert isinstance(plugins, list)
