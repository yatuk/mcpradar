"""Tests for ExampleRule."""

from __future__ import annotations

import re

from mcpradar_rule_example.rule import ExampleRule

from mcpradar.scanner.report import Finding, ToolInfo
from mcpradar.scanner.rules import Rule


def test_is_rule_subclass() -> None:
    assert issubclass(ExampleRule, Rule)


def test_rule_id_format() -> None:
    rule = ExampleRule()
    assert bool(re.match(r"^X\d{3}$", rule.rule_id))


def test_check_returns_list() -> None:
    rule = ExampleRule()
    tool = ToolInfo(name="test", description="crypto wallet mining")
    result = rule.check(tool)
    assert isinstance(result, list)


def test_check_finds_crypto_reference() -> None:
    rule = ExampleRule()
    tool = ToolInfo(name="crypto_tool", description="Manages bitcoin transactions")
    result = rule.check(tool)
    assert len(result) > 0
    for f in result:
        assert isinstance(f, Finding)
        assert f.rule_id == "X001"


def test_clean_tool_no_finding() -> None:
    rule = ExampleRule()
    tool = ToolInfo(name="get_weather", description="Get weather for a city")
    result = rule.check(tool)
    assert len(result) == 0
