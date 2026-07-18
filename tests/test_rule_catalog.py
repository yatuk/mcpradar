"""Canonical rule catalog consistency tests."""

from mcpradar.rules.catalog import RULE_CATALOG, render_markdown
from mcpradar.scanner.report import Severity
from mcpradar.scanner.rules import RuleEngine
from mcpradar.scoring.confidence import CONFIDENCE_MAP


def test_catalog_covers_every_rule_family() -> None:
    assert len(RULE_CATALOG) == 42
    for prefix in ("R", "C", "S", "M", "D", "T"):
        assert any(rule_id.startswith(prefix) for rule_id in RULE_CATALOG)


def test_builtin_rule_ids_exist_in_catalog() -> None:
    builtins = RuleEngine(min_severity=Severity.LOW).loaded_rules
    assert {item["rule_id"] for item in builtins} <= set(RULE_CATALOG)


def test_confidence_is_derived_from_catalog() -> None:
    assert {
        rule_id: descriptor.confidence for rule_id, descriptor in RULE_CATALOG.items()
    } == CONFIDENCE_MAP


def test_generated_markdown_lists_every_rule() -> None:
    markdown = render_markdown()
    assert all(f"| {rule_id} |" in markdown for rule_id in RULE_CATALOG)
