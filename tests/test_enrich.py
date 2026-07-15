"""Tests for leaderboard enrichment (mcpradar.enrich)."""

from __future__ import annotations

from pathlib import Path

from mcpradar import enrich
from mcpradar.enrich import enrich_result, package_ref_from_target
from mcpradar.scanner.report import Finding, Severity


class TestPackageRef:
    def test_npx_scoped(self) -> None:
        assert (
            package_ref_from_target("npx -y @modelcontextprotocol/server-filesystem .")
            == "npm:@modelcontextprotocol/server-filesystem"
        )

    def test_uvx(self) -> None:
        assert package_ref_from_target("uvx mcp-server-git --repository .") == "pip:mcp-server-git"

    def test_scoped_with_version(self) -> None:
        assert package_ref_from_target("npx -y @scope/pkg@1.2.3") == "npm:@scope/pkg"

    def test_local_script_none(self) -> None:
        assert package_ref_from_target("python -m ninova_mcp.server") is None
        assert package_ref_from_target("node index.js") is None
        assert package_ref_from_target("") is None


class TestEnrichResult:
    def test_merges_and_dedupes(self, monkeypatch, tmp_path: Path) -> None:
        src = tmp_path / "pkg"
        src.mkdir()
        monkeypatch.setattr(enrich, "resolve_source", lambda ref, workdir=None: src)

        dep = Finding("D001", "vuln dep", "axios CVE", Severity.HIGH, "axios@1.0")
        src_f = Finding("S007", "DCI", "read tool writes", Severity.HIGH, "server.py:5")
        monkeypatch.setattr(enrich, "_run_deps", lambda p: [enrich._finding_dict(dep)])
        monkeypatch.setattr(enrich, "_run_source", lambda p: [enrich._finding_dict(src_f)])

        result = {
            "target": "npx -y demo-mcp",
            "findings": [{"rule_id": "R109", "target": "t1"}],
        }
        ok, note = enrich_result(result)
        assert ok is True
        rules = {f["rule_id"] for f in result["findings"]}
        assert rules == {"R109", "D001", "S007"}
        assert result["enriched"] is True
        assert result["enriched_ref"] == "npm:demo-mcp"

    def test_no_ref_skipped(self) -> None:
        ok, note = enrich_result({"target": "python server.py", "findings": []})
        assert ok is False
        assert "no package ref" in note

    def test_fetch_failure_non_fatal(self, monkeypatch) -> None:
        from mcpradar.fetch import FetchError

        def boom(ref, workdir=None):
            raise FetchError("404")

        monkeypatch.setattr(enrich, "resolve_source", boom)
        ok, note = enrich_result({"target": "npx -y ghost-pkg", "findings": []})
        assert ok is False
        assert "fetch failed" in note
