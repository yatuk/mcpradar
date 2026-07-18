"""CLI integration tests using Typer CliRunner."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from typer.testing import CliRunner

from mcpradar.cli import app

runner = CliRunner()


class TestCLIVersion:
    def test_version(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "mcpradar" in result.stdout


class TestCLIInit:
    def test_init_creates_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "test_config.toml"
            result = runner.invoke(app, ["init", "-o", str(out)])
            assert result.exit_code == 0
            assert out.exists()
            content = out.read_text(encoding="utf-8")
            assert "servers" in content

    def test_init_default_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            import os

            old = os.getcwd()
            os.chdir(tmp)
            try:
                result = runner.invoke(app, ["init"])
                assert result.exit_code == 0
                assert Path("mcpradar.toml").exists()
            finally:
                os.chdir(old)


class TestCLIDiff:
    def test_diff_no_args_lists_targets(self) -> None:
        result = runner.invoke(app, ["diff"])
        # May say "No scans yet" or list targets
        assert result.exit_code == 0

    def test_diff_missing_server(self) -> None:
        result = runner.invoke(app, ["diff", "http://nonexistent"])
        assert result.exit_code == 0  # graceful exit

    def test_diff_json_output(self) -> None:
        result = runner.invoke(app, ["diff", "http://x", "--json"])
        assert result.exit_code == 0


class TestCLIScan:
    def test_scan_missing_target_shows_help(self) -> None:
        result = runner.invoke(app, ["scan"])
        assert result.exit_code in (0, 2)

    def test_scan_invalid_transport(self) -> None:
        result = runner.invoke(app, ["scan", "http://x", "-t", "invalid"])
        assert result.exit_code == 1

    def test_scan_invalid_protocol_profile(self) -> None:
        result = runner.invoke(app, ["scan", "http://x", "--protocol", "future"])
        assert result.exit_code == 1

    def test_stdio_requires_explicit_host_execution_consent(self) -> None:
        result = runner.invoke(app, ["scan", "python untrusted.py", "-t", "stdio"])
        assert result.exit_code == 2
        assert "explicit consent" in result.stdout.lower()

    def test_scan_help_shows_options(self) -> None:
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--transport" in result.stdout or "transport" in result.stdout.lower()
        assert "--format" in result.stdout or "format" in result.stdout.lower()
        assert "--severity" in result.stdout or "severity" in result.stdout.lower()


class TestCLIList:
    def test_list_no_target(self) -> None:
        result = runner.invoke(app, ["list"])
        assert result.exit_code == 0

    def test_list_specific_target(self) -> None:
        result = runner.invoke(app, ["list", "http://x"])
        assert result.exit_code == 0


class TestCLIShow:
    def test_show_nonexistent(self) -> None:
        result = runner.invoke(app, ["show", "nonexistent123"])
        assert result.exit_code == 0  # graceful error message


class TestCLIExport:
    def test_export_nonexistent(self) -> None:
        result = runner.invoke(app, ["export", "nonexistent", "-o", "/tmp/out.json"])
        assert result.exit_code == 0  # graceful exit


class TestCLIPurge:
    def test_purge_no_args(self) -> None:
        result = runner.invoke(app, ["purge"])
        assert result.exit_code == 0

    def test_purge_dry_run(self) -> None:
        result = runner.invoke(app, ["purge", "--older-than", "30d", "--dry-run"])
        assert result.exit_code == 0


class TestCLIWatch:
    def test_watch_help(self) -> None:
        result = runner.invoke(app, ["watch", "--help"])
        assert result.exit_code == 0


class TestCLILeaderboard:
    def test_leaderboard_generate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "data.json"
            result = runner.invoke(
                app,
                ["leaderboard", "generate", "-o", str(out), "--results-dir", str(Path(tmp))],
            )
            assert result.exit_code == 0
            assert out.exists()
            content = out.read_text(encoding="utf-8")
            data = json.loads(content)
            assert isinstance(data, list)  # empty when no results, but valid JSON

    def _generate(self, results_dir: Path, files: dict[str, dict]) -> list[dict]:
        for fname, payload in files.items():
            (results_dir / fname).write_text(json.dumps(payload), encoding="utf-8")
        out = results_dir / "data.json"
        result = runner.invoke(
            app,
            ["leaderboard", "generate", "-o", str(out), "--results-dir", str(results_dir)],
        )
        assert result.exit_code == 0, result.output
        return json.loads(out.read_text(encoding="utf-8"))

    def test_badges_generated_from_current_grade(self) -> None:
        """Each row gets a README badge SVG derived from the live grade, so an
        embedded badge never drifts out of sync with the data."""
        with tempfile.TemporaryDirectory() as tmp:
            self._generate(
                Path(tmp),
                {
                    "srv.json": {
                        "name": "@vendor/clean",
                        "id": "abc",
                        "target": "npx -y @vendor/clean",
                        "scanned_at": "2026-07-10T00:00:00+00:00",
                        "tools": [{"name": "t1"}],
                        "summary": {"total_tools": 1},
                        "findings": [],
                    },
                    "stub.json": {"name": "@vendor/pending", "status": "registry-pending"},
                },
            )
            badges = Path(tmp) / "badges"
            scanned_svg = (badges / "vendor-clean.svg").read_text(encoding="utf-8")
            assert "MCPRadar Security: A - 0.0/10" in scanned_svg
            pending_svg = (badges / "vendor-pending.svg").read_text(encoding="utf-8")
            assert "not scanned" in pending_svg

    def test_unscanned_stub_is_pending_not_grade_a(self) -> None:
        """A registry stub (no tools, no scan id) must render as pending with no
        grade — never as a clean grade-A pass."""
        with tempfile.TemporaryDirectory() as tmp:
            data = self._generate(
                Path(tmp),
                {
                    "stub.json": {
                        "name": "@vendor/never-scanned",
                        "status": "registry-pending",
                        "findings": [],
                        "tools": [],
                        "summary": {"total_tools": 0},
                    }
                },
            )
            row = next(r for r in data if r["server"] == "@vendor/never-scanned")
            assert row["status"] == "pending"
            assert row["grade"] == "-"
            assert row["risk_score"] is None
            assert row["scoring_model"] == "mrs-v1"

    def test_low_findings_excluded_from_grade(self) -> None:
        """A scan whose only findings are LOW stays grade A: LOW is
        informational lint and must not drive the grade."""
        with tempfile.TemporaryDirectory() as tmp:
            data = self._generate(
                Path(tmp),
                {
                    "srv.json": {
                        "id": "abc123",
                        "target": "npx -y @vendor/clean",
                        "scanned_at": "2026-07-10T00:00:00+00:00",
                        "tools": [{"name": "t1"}, {"name": "t2"}],
                        "summary": {"total_tools": 2},
                        "findings": [
                            {"rule_id": "R114", "severity": "low", "title": "lint"},
                            {"rule_id": "R114", "severity": "low", "title": "lint"},
                        ],
                    }
                },
            )
            row = next(r for r in data if r["server"] == "@vendor/clean")
            assert row["status"] == "scanned"
            assert row["grade"] == "A"
            assert row["risk_score"] == 0.0
            assert row["findings"] == 0  # medium+ headline count
            assert row["low_findings"] == 2

    def test_medium_findings_drive_grade(self) -> None:
        """MEDIUM+ findings produce a real non-A grade and are the headline
        finding count."""
        with tempfile.TemporaryDirectory() as tmp:
            data = self._generate(
                Path(tmp),
                {
                    "srv.json": {
                        "id": "def456",
                        "target": "npx -y @vendor/risky",
                        "scanned_at": "2026-07-10T00:00:00+00:00",
                        "tools": [{"name": "t1"}],
                        "summary": {"total_tools": 1},
                        "findings": [
                            {"rule_id": "R109", "severity": "medium", "title": "schema"},
                            {"rule_id": "R114", "severity": "low", "title": "lint"},
                        ],
                    }
                },
            )
            row = next(r for r in data if r["server"] == "@vendor/risky")
            assert row["status"] == "scanned"
            assert row["grade"] != "A"
            assert row["risk_score"] > 0
            assert row["findings"] == 1
            assert row["low_findings"] == 1

    def test_site_metadata_and_badge_paths_are_safe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            badges = root / "badges"
            badges.mkdir()
            unrelated = badges / "custom.svg"
            unrelated.write_text("<svg>unrelated</svg>", encoding="utf-8")
            rows = self._generate(
                root,
                {
                    "malicious-name.json": {
                        "name": "../filesystem/escape",
                        "id": "scan-id",
                        "tools": [{"name": "read_file"}],
                        "findings": [{"rule_id": "R113", "severity": "medium", "title": "path"}],
                    }
                },
            )
            row = rows[0]
            assert row["category"] == "File System"
            assert row["vuln_types"] == ["Path Traversal"]
            assert row["api_free"] is True
            assert row["history"] == []
            assert unrelated.exists()
            assert (badges / "filesystem-escape.svg").exists()
            assert not (root.parent / "escape.svg").exists()


class TestCLIDiffFormat:
    def test_diff_with_output_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "diff.json"
            result = runner.invoke(app, ["diff", "http://x", "--json", "-o", str(out)])
            assert result.exit_code == 0


class TestCLIWatchFull:
    def test_watch_with_all_flags(self) -> None:
        result = runner.invoke(
            app,
            [
                "watch",
                "http://x",
                "-t",
                "http",
                "-i",
                "10",
                "-c",
                "echo changed",
                "-w",
                "https://hooks.slack.com/x",
            ],
        )
        # Will fail connecting but shouldn't crash on arg parsing
        # Ctrl+C gets simulated by the connection failure
        assert result.exit_code in (0, 1)

    def test_watch_with_stdio(self) -> None:
        result = runner.invoke(
            app,
            ["watch", "python test", "-t", "stdio", "-i", "10"],
        )
        assert result.exit_code in (0, 1)


class TestCLIScanFormat:
    def test_scan_format_sarif(self) -> None:
        result = runner.invoke(
            app,
            ["scan", "http://x", "--format", "sarif", "--no-save"],
        )
        assert result.exit_code in (0, 1)

    def test_scan_format_json(self) -> None:
        result = runner.invoke(
            app,
            ["scan", "http://x", "--format", "json", "--no-save"],
        )
        assert result.exit_code in (0, 1)

    def test_scan_deprecated_json_flag(self) -> None:
        import warnings

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = runner.invoke(
                app,
                ["scan", "http://x", "--json", "--no-save"],
            )
            assert result.exit_code in (0, 1)
            # Should emit deprecation warning
            dep_warnings = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(dep_warnings) >= 1


class TestCLIExportFormats:
    def test_export_json(self) -> None:
        result = runner.invoke(
            app,
            ["export", "nonexistent", "-f", "json", "-o", "/tmp/out.json"],
        )
        assert result.exit_code == 0

    def test_export_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.csv"
            result = runner.invoke(
                app,
                ["export", "nonexistent", "-f", "csv", "-o", str(out)],
            )
            assert result.exit_code == 0

    def test_export_sarif(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.sarif"
            result = runner.invoke(
                app,
                ["export", "nonexistent", "-f", "sarif", "-o", str(out)],
            )
            assert result.exit_code == 0


class TestCLIPurgeOptions:
    def test_purge_with_target(self) -> None:
        result = runner.invoke(
            app,
            ["purge", "--older-than", "7d", "--target", "http://x", "--dry-run"],
        )
        assert result.exit_code == 0

    def test_purge_keep_last(self) -> None:
        result = runner.invoke(
            app,
            ["purge", "--keep-last", "5", "--dry-run"],
        )
        assert result.exit_code == 0


class TestCLIScanAll:
    def test_scan_all_no_config(self) -> None:
        import os

        with tempfile.TemporaryDirectory() as tmp:
            old = os.getcwd()
            os.chdir(tmp)
            try:
                result = runner.invoke(app, ["scan-all"])
                assert result.exit_code == 1  # no config found
            finally:
                os.chdir(old)
