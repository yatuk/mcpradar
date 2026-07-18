"""Official Registry pagination and cache regressions."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcpradar.registry.client import RegistryClient


def _raw(name: str) -> dict:
    return {
        "server": {"name": name, "version": "1.0.0"},
        "_meta": {
            "io.modelcontextprotocol.registry/official": {
                "isLatest": True,
                "status": "active",
            }
        },
    }


def test_empty_next_cursor_ends_pagination(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = RegistryClient()
    monkeypatch.setattr(client, "_cache_path", lambda: tmp_path / "cache.json")
    calls = 0

    def fetch_page(limit: int, cursor: str | None) -> dict:
        nonlocal calls
        calls += 1
        return {"servers": [_raw("io.example/server")], "metadata": {"nextCursor": ""}}

    monkeypatch.setattr(client, "fetch_page", fetch_page)
    entries = client.list_servers(force_refresh=True)
    assert calls == 1
    assert [entry.name for entry in entries] == ["io.example/server"]


def test_fresh_cache_avoids_network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache = tmp_path / "cache.json"
    cache.write_text(
        json.dumps({"_cached_at": 9_999_999_999, "servers": [_raw("io.example/cached")]}),
        encoding="utf-8",
    )
    client = RegistryClient()
    monkeypatch.setattr(client, "_cache_path", lambda: cache)

    def unexpected_fetch(limit: int, cursor: str | None) -> dict:
        raise AssertionError("fresh cache should be used")

    monkeypatch.setattr(client, "fetch_page", unexpected_fetch)
    assert [entry.name for entry in client.list_servers()] == ["io.example/cached"]


def test_partial_walk_does_not_replace_full_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = tmp_path / "cache.json"
    client = RegistryClient()
    monkeypatch.setattr(client, "_cache_path", lambda: cache)
    monkeypatch.setattr(
        client,
        "fetch_page",
        lambda limit, cursor: {
            "servers": [_raw("io.example/partial")],
            "metadata": {"nextCursor": "more"},
        },
    )
    entries = client.list_servers(max_pages=1, force_refresh=True)
    assert [entry.name for entry in entries] == ["io.example/partial"]
    assert not cache.exists()


def test_repeated_cursor_stops_with_cache_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = RegistryClient()
    monkeypatch.setattr(client, "_cache_path", lambda: tmp_path / "missing.json")
    calls = 0

    def fetch_page(limit: int, cursor: str | None) -> dict:
        nonlocal calls
        calls += 1
        return {"servers": [_raw(f"io.example/{calls}")], "metadata": {"nextCursor": "same"}}

    monkeypatch.setattr(client, "fetch_page", fetch_page)
    assert client.list_servers(force_refresh=True) == []
    assert calls == 2
