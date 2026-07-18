"""Per-finding detection confidence derived from the canonical rule catalog."""

from __future__ import annotations

from mcpradar.rules.catalog import RULE_CATALOG

CONFIDENCE_MAP: dict[str, float] = {
    rule_id: descriptor.confidence for rule_id, descriptor in RULE_CATALOG.items()
}
DEFAULT_CONFIDENCE = 0.5


def confidence_for(rule_id: str) -> float:
    """Return detection confidence in [0.0, 1.0] for a rule id."""
    return CONFIDENCE_MAP.get(rule_id, DEFAULT_CONFIDENCE)
