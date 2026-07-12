"""Tests for typosquatting detection (mcpradar.supply.typosquat)."""

from __future__ import annotations

import json
from pathlib import Path

from mcpradar.config_scan import scan_config_path
from mcpradar.scanner.report import Severity
from mcpradar.supply.typosquat import _levenshtein, check_typosquat


class TestLevenshtein:
    def test_basic(self) -> None:
        assert _levenshtein("kitten", "sitting") == 3
        assert _levenshtein("abc", "abc") == 0
        assert _levenshtein("twittter", "twitter") == 1

    def test_bounded(self) -> None:
        # far apart -> capped at max_dist + 1
        assert _levenshtein("aaaa", "bbbbbbbb", max_dist=2) == 3


class TestCheckTyposquat:
    def test_extra_letter_lookalike(self) -> None:
        hit = check_typosquat("twittter-mcp")
        assert hit is not None
        assert hit.suspected == "twitter-mcp"
        assert hit.distance == 1

    def test_doubled_char(self) -> None:
        hit = check_typosquat("mcp-server-fetchh")
        assert hit is not None
        assert hit.suspected == "mcp-server-fetch"

    def test_scope_lookalike(self) -> None:
        hit = check_typosquat("@modlecontextprotocol/server-filesystem")
        assert hit is not None
        assert "modelcontextprotocol" in hit.suspected

    def test_exact_known_is_clean(self) -> None:
        assert check_typosquat("@modelcontextprotocol/server-filesystem") is None
        assert check_typosquat("chrome-devtools-mcp") is None

    def test_unrelated_name_clean(self) -> None:
        assert check_typosquat("my-internal-company-server") is None
        assert check_typosquat("weather-forecast-mcp") is None

    def test_short_name_not_flagged(self) -> None:
        # too short to be a confident lookalike
        assert check_typosquat("git") is None

    def test_case_insensitive(self) -> None:
        assert check_typosquat("Twittter-MCP") is not None


class TestConfigIntegration:
    def _cfg(self, servers: dict, tmp_path: Path) -> list:
        f = tmp_path / ".mcp.json"
        f.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
        return scan_config_path(tmp_path).findings

    def test_typosquat_server_flagged(self, tmp_path: Path) -> None:
        f = self._cfg({"x": {"command": "npx", "args": ["-y", "twittter-mcp"]}}, tmp_path)
        t = [x for x in f if x.rule_id == "T001"]
        assert len(t) == 1
        assert t[0].severity == Severity.HIGH

    def test_uvx_package_flagged(self, tmp_path: Path) -> None:
        f = self._cfg({"x": {"command": "uvx", "args": ["mcp-server-fetchh"]}}, tmp_path)
        assert any(x.rule_id == "T001" for x in f)

    def test_legit_server_not_flagged(self, tmp_path: Path) -> None:
        f = self._cfg(
            {
                "x": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                }
            },
            tmp_path,
        )
        assert not [x for x in f if x.rule_id == "T001"]

    def test_non_runner_command_ignored(self, tmp_path: Path) -> None:
        # a local python script is not a package launch — no typosquat check
        f = self._cfg({"x": {"command": "python", "args": ["twittter-mcp.py"]}}, tmp_path)
        assert not [x for x in f if x.rule_id == "T001"]
