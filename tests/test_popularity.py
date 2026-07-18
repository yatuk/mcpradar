"""Popularity ranking: signal fetch, log-scale combine, ranking."""

from __future__ import annotations

import math

import httpx
import pytest

from mcpradar.registry.client import PackageRef, RegistryEntry
from mcpradar.registry.popularity import (
    Signals,
    _is_server_package,
    discover_popular_registry_servers,
    discover_popular_servers,
    github_stars,
    npm_weekly_downloads,
    pypi_weekly_downloads,
    rank_servers,
)


def _mock_httpx(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    def fake_get(url, timeout=None, headers=None, follow_redirects=True):  # noqa: ANN001
        return handler(url)

    monkeypatch.setattr(httpx, "get", fake_get)


def _entry(name: str, *, npm: str = "", pypi: str = "", repo: str = "") -> RegistryEntry:
    packages = []
    if npm:
        packages.append(
            PackageRef(registry_type="npm", identifier=npm, version="1", transport="stdio")
        )
    if pypi:
        packages.append(
            PackageRef(registry_type="pypi", identifier=pypi, version="1", transport="stdio")
        )
    return RegistryEntry(
        name=name, title=name, description="", version="1", packages=packages, repository_url=repo
    )


class TestSignalsScore:
    def test_log_scale_sum(self) -> None:
        s = Signals(npm_downloads=1000, pypi_downloads=100, github_stars=10)
        expected = math.log10(1001) + math.log10(101) + math.log10(11)
        assert s.score == pytest.approx(round(expected, 4))

    def test_missing_signals_contribute_zero(self) -> None:
        assert Signals(npm_downloads=1000).score == pytest.approx(round(math.log10(1001), 4))

    def test_empty_is_zero(self) -> None:
        assert Signals().score == 0.0

    def test_multi_signal_outranks_single(self) -> None:
        multi = Signals(npm_downloads=500, github_stars=500).score
        single = Signals(npm_downloads=500).score
        assert multi > single


class TestFetchers:
    def test_npm_downloads(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _mock_httpx(monkeypatch, lambda url: httpx.Response(200, json={"downloads": 42}))
        assert npm_weekly_downloads("x") == 42

    def test_pypi_downloads(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _mock_httpx(monkeypatch, lambda url: httpx.Response(200, json={"data": {"last_week": 99}}))
        assert pypi_weekly_downloads("x") == 99

    def test_github_stars(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _mock_httpx(monkeypatch, lambda url: httpx.Response(200, json={"stargazers_count": 7}))
        assert github_stars("https://github.com/o/r") == 7

    def test_non_github_repo_returns_none(self) -> None:
        assert github_stars("https://gitlab.com/o/r") is None

    def test_network_error_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def boom(url):  # noqa: ANN001
            raise httpx.ConnectError("nope")

        _mock_httpx(monkeypatch, boom)
        assert npm_weekly_downloads("x") is None


class TestRanking:
    def test_ranks_by_score_desc_and_filters_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(url: str) -> httpx.Response:
            if "npmjs" in url and "popular" in url:
                return httpx.Response(200, json={"downloads": 1_000_000})
            if "npmjs" in url and "niche" in url:
                return httpx.Response(200, json={"downloads": 10})
            return httpx.Response(404)

        _mock_httpx(monkeypatch, handler)
        entries = [
            _entry("niche", npm="niche-pkg"),
            _entry("popular", npm="popular-pkg"),
            _entry("unknown", npm="missing-pkg"),  # 404 -> score 0, filtered
            _entry("remote-only"),  # no packages -> skipped
        ]
        ranked = rank_servers(entries, top_n=10)
        assert [r.entry.name for r in ranked] == ["popular", "niche"]
        assert all(r.score > 0 for r in ranked)

    def test_top_n_limit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _mock_httpx(monkeypatch, lambda url: httpx.Response(200, json={"downloads": 100}))
        entries = [_entry(f"s{i}", npm=f"pkg{i}") for i in range(5)]
        assert len(rank_servers(entries, top_n=3)) == 3


class TestServerFilter:
    def test_keeps_servers(self) -> None:
        assert _is_server_package("@x/mcp-server-mysql", ["mcp", "mcp-server"])
        assert _is_server_package("clickup-mcp-server", [])
        assert _is_server_package("@zereight/mcp-gitlab", ["mcp-server"])

    def test_drops_sdks_and_adapters(self) -> None:
        assert not _is_server_package("@modelcontextprotocol/sdk", ["mcp"])
        assert not _is_server_package("@mcp-b/webmcp-ts-sdk", ["mcp"])
        assert not _is_server_package("@langchain/mcp-adapters", ["mcp"])
        assert not _is_server_package("ai", ["mcp"])

    def test_drops_unrelated(self) -> None:
        assert not _is_server_package("left-pad", ["string", "pad"])


class TestDiscoverPopular:
    def test_discovers_scores_and_ranks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        search_objs = {
            "objects": [
                {"package": {"name": "big-mcp-server", "keywords": ["mcp-server"], "links": {}}},
                {"package": {"name": "small-mcp-server", "keywords": ["mcp-server"], "links": {}}},
                {"package": {"name": "@foo/sdk", "keywords": ["mcp"], "links": {}}},  # filtered
            ]
        }

        def handler(url: str) -> httpx.Response:
            if "/-/v1/search" in url:
                return httpx.Response(200, json=search_objs)
            if "big-mcp-server" in url:
                return httpx.Response(200, json={"downloads": 100000})
            if "small-mcp-server" in url:
                return httpx.Response(200, json={"downloads": 50})
            return httpx.Response(404)

        _mock_httpx(monkeypatch, handler)
        ranked = discover_popular_servers(top_n=10, search_size=20)
        names = [r.entry.name for r in ranked]
        assert names == ["big-mcp-server", "small-mcp-server"]
        assert "@foo/sdk" not in names
        # entry carries a scannable npm package ref
        assert ranked[0].entry.packages[0].identifier == "big-mcp-server"

    def test_registry_discovery_excludes_unpublished_packages(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        search_objs = {
            "objects": [
                {"package": {"name": "registry-mcp", "keywords": ["mcp-server"]}},
                {"package": {"name": "rogue-mcp", "keywords": ["mcp-server"]}},
            ]
        }

        def handler(url: str) -> httpx.Response:
            if "/-/v1/search" in url:
                return httpx.Response(200, json=search_objs)
            if "registry-mcp" in url:
                return httpx.Response(200, json={"downloads": 1234})
            if "rogue-mcp" in url:
                return httpx.Response(200, json={"downloads": 999999})
            return httpx.Response(404)

        class FakeClient:
            def search_servers(self, query, **kwargs):  # noqa: ANN001, ANN003, ANN201
                return (
                    [_entry("io.example/registry", npm="registry-mcp")]
                    if query == "registry-mcp"
                    else []
                )

        _mock_httpx(monkeypatch, handler)
        ranked = discover_popular_registry_servers(
            top_n=10,
            search_size=20,
            client=FakeClient(),  # type: ignore[arg-type]
        )
        assert [item.entry.name for item in ranked] == ["io.example/registry"]
        assert ranked[0].entry.packages[0].identifier == "registry-mcp"
