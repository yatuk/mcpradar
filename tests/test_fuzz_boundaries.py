"""Property-based fuzzing for untrusted schemas and archive metadata."""

from __future__ import annotations

import contextlib
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from mcpradar.fetch.fetcher import FetchError, _validate_archive_members
from mcpradar.schema.walker import (
    SchemaLimitError,
    canonicalize_schema,
    iter_schema_nodes,
    iter_schema_properties,
)

_JSON_SCALARS = st.none() | st.booleans() | st.integers() | st.text(max_size=20)
_JSON = st.recursive(
    _JSON_SCALARS,
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=12), children, max_size=4)
    ),
    max_leaves=30,
)


@given(_JSON)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_schema_walkers_terminate_for_arbitrary_json(value: object) -> None:
    schema = value if isinstance(value, dict) else {"const": value}
    try:
        list(iter_schema_properties(schema, max_nodes=200, max_depth=12, timeout_seconds=0.5))
        list(iter_schema_nodes(schema, max_nodes=200, max_depth=12, timeout_seconds=0.5))
    except SchemaLimitError:
        pass


@given(_JSON)
def test_schema_canonicalization_is_idempotent(value: object) -> None:
    try:
        once = canonicalize_schema(value, max_depth=20)
        assert canonicalize_schema(once, max_depth=20) == once
    except SchemaLimitError:
        pass


@given(
    names=st.lists(
        st.text(
            alphabet=st.characters(
                whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="._-/\\"
            ),
            min_size=1,
            max_size=80,
        ),
        min_size=1,
        max_size=20,
    )
)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_archive_member_validation_never_escapes_destination(
    names: list[str], tmp_path: Path
) -> None:
    members = [(name, 1, False, True) for name in names]
    with contextlib.suppress(FetchError, OSError, RuntimeError, ValueError):
        _validate_archive_members(members, compressed_size=len(names), dest=tmp_path)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("path", ["../secret", "a/../../secret", "/root/secret", "..\\secret"])
def test_archive_traversal_is_always_rejected(path: str, tmp_path: Path) -> None:
    with pytest.raises(FetchError, match="unsafe path"):
        _validate_archive_members([(path, 1, False, True)], compressed_size=1, dest=tmp_path)
