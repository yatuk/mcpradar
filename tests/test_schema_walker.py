"""JSON Schema 2020-12 traversal and safety limits."""

from __future__ import annotations

import pytest

from mcpradar.schema.walker import (
    SchemaLimitError,
    canonicalize_schema,
    iter_schema_nodes,
    iter_schema_properties,
)


def test_walks_defs_refs_composition_conditionals_and_arrays() -> None:
    schema = {
        "$defs": {
            "Command": {
                "type": "object",
                "properties": {"command": {"type": "string"}},
            }
        },
        "properties": {
            "payload": {
                "allOf": [{"$ref": "#/$defs/Command"}],
                "if": {"properties": {"mode": {"const": "file"}}},
                "then": {
                    "properties": {
                        "paths": {
                            "type": "array",
                            "items": {"$ref": "#/$defs/Command"},
                        }
                    }
                },
            }
        },
    }
    paths = {path for path, _node in iter_schema_properties(schema)}
    assert {"payload", "payload.command", "payload.mode", "payload.paths"} <= paths
    assert "payload.paths.items.command" in paths


def test_external_refs_are_not_dereferenced() -> None:
    schema = {"properties": {"x": {"$ref": "https://attacker/schema.json"}}}
    assert [path for path, _node in iter_schema_properties(schema)] == ["x"]


def test_recursive_ref_is_bounded() -> None:
    schema = {
        "$defs": {
            "Node": {
                "properties": {
                    "child": {"$ref": "#/$defs/Node"},
                }
            }
        },
        "$ref": "#/$defs/Node",
    }
    assert [path for path, _node in iter_schema_properties(schema)] == ["child"]


def test_depth_limit_raises() -> None:
    schema: dict[str, object] = {}
    current = schema
    for index in range(10):
        child: dict[str, object] = {}
        current["properties"] = {f"p{index}": child}
        current = child
    with pytest.raises(SchemaLimitError):
        list(iter_schema_properties(schema, max_depth=3))


def test_canonicalization_orders_keys() -> None:
    assert canonicalize_schema({"b": 1, "a": {"d": 2, "c": 3}}) == {
        "a": {"c": 3, "d": 2},
        "b": 1,
    }


def test_iter_nodes_covers_all_2020_12_container_keywords() -> None:
    schema = {
        "$defs": {"A": {"type": "string"}},
        "definitions": {"B": {"type": "number"}},
        "patternProperties": {"^x": {"type": "boolean"}},
        "dependentSchemas": {"flag": {"required": ["other"]}},
        "items": {"type": "integer"},
        "allOf": [{"maxLength": 3}],
        "prefixItems": [{"const": "first"}],
    }
    paths = {path for path, _node in iter_schema_nodes(schema)}
    assert {
        "#/$defs/A",
        "#/definitions/B",
        "#/patternProperties/^x",
        "#/dependentSchemas/flag",
        "#/items",
        "#/allOf/0",
        "#/prefixItems/0",
    } <= paths


def test_iter_nodes_limits_and_canonicalization_depth() -> None:
    schema = {"properties": {"a": {"properties": {"b": {"type": "string"}}}}}
    with pytest.raises(SchemaLimitError):
        list(iter_schema_nodes(schema, max_nodes=1))
    with pytest.raises(SchemaLimitError):
        list(iter_schema_nodes(schema, max_depth=1))
    with pytest.raises(SchemaLimitError, match="canonicalization"):
        canonicalize_schema({"a": {"b": {"c": 1}}}, max_depth=1)


def test_pattern_and_union_property_paths() -> None:
    schema = {
        "patternProperties": {"^item": {"properties": {"value": {"type": "string"}}}},
        "anyOf": [{"properties": {"a": {"type": "string"}}}],
        "oneOf": [{"properties": {"b": {"type": "string"}}}],
        "prefixItems": [{"properties": {"c": {"type": "string"}}}],
    }
    paths = {path for path, _node in iter_schema_properties(schema)}
    assert {"pattern[^item].value", "[0].a", "[0].b", "[0].c"} <= paths
