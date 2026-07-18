"""Cycle-safe, bounded traversal for JSON Schema Draft 2020-12."""

from __future__ import annotations

import time
from collections.abc import Iterator
from typing import Any

_MAP_KEYWORDS = (
    "items",
    "contains",
    "additionalProperties",
    "unevaluatedProperties",
    "propertyNames",
    "not",
    "if",
    "then",
    "else",
)
_LIST_KEYWORDS = ("allOf", "anyOf", "oneOf", "prefixItems")


class SchemaLimitError(ValueError):
    """Schema traversal exceeded its depth, node, or time budget."""


def iter_schema_properties(
    schema: dict[str, Any],
    *,
    max_depth: int = 32,
    max_nodes: int = 10_000,
    timeout_seconds: float = 0.1,
) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield properties through refs, composition, arrays and conditionals."""
    definitions = _definitions(schema)
    started = time.monotonic()
    nodes = 0

    def walk(
        node: object,
        path: str,
        depth: int,
        ref_stack: frozenset[str],
    ) -> Iterator[tuple[str, dict[str, Any]]]:
        nonlocal nodes
        nodes += 1
        if nodes > max_nodes or depth > max_depth:
            raise SchemaLimitError("schema traversal limit exceeded")
        if time.monotonic() - started > timeout_seconds:
            raise SchemaLimitError("schema traversal time limit exceeded")
        if not isinstance(node, dict):
            return

        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/") and ref not in ref_stack:
            resolved = definitions.get(ref)
            if resolved is not None:
                yield from walk(resolved, path, depth + 1, ref_stack | {ref})

        properties = node.get("properties")
        if isinstance(properties, dict):
            for name, value in properties.items():
                if not isinstance(value, dict):
                    continue
                property_path = f"{path}.{name}" if path else str(name)
                yield property_path, value
                yield from walk(value, property_path, depth + 1, ref_stack)

        pattern_properties = node.get("patternProperties")
        if isinstance(pattern_properties, dict):
            for pattern, value in pattern_properties.items():
                if isinstance(value, dict):
                    pattern_path = f"{path}.pattern[{pattern}]" if path else f"pattern[{pattern}]"
                    yield from walk(value, pattern_path, depth + 1, ref_stack)

        for keyword in _MAP_KEYWORDS:
            child = node.get(keyword)
            if isinstance(child, dict):
                child_path = f"{path}.items" if keyword == "items" and path else path
                yield from walk(child, child_path, depth + 1, ref_stack)
        for keyword in _LIST_KEYWORDS:
            children = node.get(keyword)
            if isinstance(children, list):
                for index, child in enumerate(children):
                    if isinstance(child, dict):
                        child_path = (
                            f"{path}[{index}]"
                            if keyword in {"anyOf", "oneOf", "prefixItems"}
                            else path
                        )
                        yield from walk(child, child_path, depth + 1, ref_stack)

    yield from walk(schema, "", 0, frozenset())


def iter_schema_nodes(
    schema: dict[str, Any],
    *,
    max_depth: int = 32,
    max_nodes: int = 10_000,
    timeout_seconds: float = 0.1,
) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield every inline schema node without resolving external references."""
    started = time.monotonic()
    seen = 0

    def walk(node: object, path: str, depth: int) -> Iterator[tuple[str, dict[str, Any]]]:
        nonlocal seen
        seen += 1
        if seen > max_nodes or depth > max_depth:
            raise SchemaLimitError("schema traversal limit exceeded")
        if time.monotonic() - started > timeout_seconds:
            raise SchemaLimitError("schema traversal time limit exceeded")
        if not isinstance(node, dict):
            return
        yield path, node
        properties = node.get("properties")
        if isinstance(properties, dict):
            for name, child in properties.items():
                yield from walk(child, f"{path}/properties/{name}", depth + 1)
        for keyword in ("$defs", "definitions", "patternProperties", "dependentSchemas"):
            children = node.get(keyword)
            if isinstance(children, dict):
                for name, child in children.items():
                    yield from walk(child, f"{path}/{keyword}/{name}", depth + 1)
        for keyword in _MAP_KEYWORDS:
            yield from walk(node.get(keyword), f"{path}/{keyword}", depth + 1)
        for keyword in _LIST_KEYWORDS:
            children = node.get(keyword)
            if isinstance(children, list):
                for index, child in enumerate(children):
                    yield from walk(child, f"{path}/{keyword}/{index}", depth + 1)

    yield from walk(schema, "#", 0)


def canonicalize_schema(value: object, *, max_depth: int = 64) -> object:
    """Return a deterministic key-ordered schema representation."""

    def canonicalize(node: object, depth: int) -> object:
        if depth > max_depth:
            raise SchemaLimitError("schema canonicalization depth exceeded")
        if isinstance(node, dict):
            return {str(key): canonicalize(node[key], depth + 1) for key in sorted(node)}
        if isinstance(node, list):
            return [canonicalize(item, depth + 1) for item in node]
        return node

    return canonicalize(value, 0)


def _definitions(schema: dict[str, Any]) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for keyword in ("$defs", "definitions"):
        values = schema.get(keyword)
        if not isinstance(values, dict):
            continue
        for name, value in values.items():
            if isinstance(value, dict):
                found[f"#/{keyword}/{name}"] = value
    return found
