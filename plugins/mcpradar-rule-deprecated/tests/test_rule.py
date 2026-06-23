"""Tests for DeprecatedPatternRule."""

from __future__ import annotations

import re

from mcpradar_rule_deprecated.rule import DeprecatedPatternRule

from mcpradar.scanner.report import ToolInfo
from mcpradar.scanner.rules import Rule


def test_is_rule_subclass() -> None:
    assert issubclass(DeprecatedPatternRule, Rule)


def test_rule_id_format() -> None:
    rule = DeprecatedPatternRule()
    assert bool(re.match(r"^X\d{3}$", rule.rule_id))


def test_detects_v1_api() -> None:
    rule = DeprecatedPatternRule()
    tool = ToolInfo(name="fetch_data", description="Fetch from v1 API endpoint")
    result = rule.check(tool)
    assert len(result) > 0
    assert any("v1" in f.detail.get("pattern", "") for f in result)


def test_detects_deprecated_keyword() -> None:
    rule = DeprecatedPatternRule()
    tool = ToolInfo(name="old_tool", description="This tool is deprecated, use v2 instead")
    result = rule.check(tool)
    assert len(result) > 0
    assert any("deprecated" in f.detail.get("pattern", "") for f in result)


def test_clean_tool_no_finding() -> None:
    rule = DeprecatedPatternRule()
    tool = ToolInfo(name="get_weather", description="Get current weather for a city")
    result = rule.check(tool)
    assert len(result) == 0
