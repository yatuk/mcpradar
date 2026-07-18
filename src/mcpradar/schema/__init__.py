"""Bounded JSON Schema 2020-12 traversal utilities."""

from mcpradar.schema.walker import (
    SchemaLimitError,
    canonicalize_schema,
    iter_schema_nodes,
    iter_schema_properties,
)

__all__ = [
    "SchemaLimitError",
    "canonicalize_schema",
    "iter_schema_nodes",
    "iter_schema_properties",
]
