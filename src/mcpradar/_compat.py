"""Python version compatibility shims."""

from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from importlib.metadata import EntryPoint


def get_entry_points(group: str) -> Iterator[EntryPoint]:
    """entry_points(group=...) polyfill for Python 3.11.

    In Python 3.12+, entry_points() accepts a ``group`` keyword argument.
    Python 3.11 only supports the dict-like ``.get(group, [])`` pattern.
    """
    from importlib.metadata import entry_points

    try:
        return iter(entry_points(group=group))
    except TypeError:
        return iter(entry_points().get(group, []))
