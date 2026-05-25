"""CLI integration tests using Typer CliRunner."""

from __future__ import annotations

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
        # May say "henuz hic scan yok" or list targets
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


class TestCLIRegistryScan:
    def test_registry_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "leaderboard.md"
            result = runner.invoke(app, ["registry-scan", "-o", str(out)])
            assert result.exit_code == 0
            assert out.exists()
            content = out.read_text(encoding="utf-8")
            assert "Leaderboard" in content or "leaderboard" in content


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
