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
