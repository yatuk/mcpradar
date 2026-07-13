"""Fetch an MCP server's source from a package reference.

Lets the source / dependency / config scanners run against a package that isn't
checked out locally — ``npm:<pkg>``, ``pip:<pkg>``, or a GitHub URL. Packages are
*downloaded and extracted*, never installed: no npm/pip lifecycle script runs,
so fetching an untrusted package is safe.
"""

from mcpradar.fetch.fetcher import (
    FetchError,
    fetch_source,
    is_ref,
    parse_ref,
    resolve_source,
)

__all__ = [
    "FetchError",
    "fetch_source",
    "is_ref",
    "parse_ref",
    "resolve_source",
]
