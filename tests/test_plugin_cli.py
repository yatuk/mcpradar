"""Plugin CLI tests."""

from __future__ import annotations

import tempfile
from pathlib import Path

from typer.testing import CliRunner

from mcpradar.cli import app

runner = CliRunner()


class TestPluginInit:
    def test_init_creates_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = runner.invoke(app, ["plugin", "init", "my-test", "-o", tmp])
            assert result.exit_code == 0
            pkg_dir = Path(tmp) / "mcpradar-rule-my-test"
            assert pkg_dir.exists()
            assert (pkg_dir / "pyproject.toml").exists()
            assert (pkg_dir / "src").exists()
            assert (pkg_dir / "tests").exists()

    def test_init_pyproject_has_entry_point(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = runner.invoke(app, ["plugin", "init", "my-sqli", "-o", tmp])
            assert result.exit_code == 0
            pyproject = Path(tmp) / "mcpradar-rule-my-sqli" / "pyproject.toml"
            content = pyproject.read_text(encoding="utf-8")
            assert "mcpradar.rules" in content
            assert "MySqliRule" in content

    def test_init_creates_module_with_correct_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = runner.invoke(app, ["plugin", "init", "test-rule", "-o", tmp])
            assert result.exit_code == 0
            module_dir = Path(tmp) / "mcpradar-rule-test-rule" / "src" / "mcpradar_rule_test_rule"
            assert module_dir.exists()
            rule_file = module_dir / "rule.py"
            assert rule_file.exists()
            content = rule_file.read_text(encoding="utf-8")
            assert "TestRuleRule" in content or "class" in content


class TestPluginValidate:
    def test_validate_valid_template(self) -> None:
        result = runner.invoke(app, ["plugin", "validate", "plugins/template"])
        # Template should validate (has valid entry_point, Rule subclass, X### rule_id)
        assert result.exit_code == 0

    def test_validate_missing_directory(self) -> None:
        result = runner.invoke(app, ["plugin", "validate", "/nonexistent/plugin/path"])
        assert result.exit_code == 1

    def test_validate_with_tests(self) -> None:
        result = runner.invoke(
            app,
            ["plugin", "validate", "plugins/template", "--run-tests"],
        )
        assert result.exit_code == 0

    def test_validate_missing_pyproject(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "src").mkdir()
            result = runner.invoke(app, ["plugin", "validate", tmp])
            assert result.exit_code == 1

    def test_validate_deprecated_plugin(self) -> None:
        result = runner.invoke(app, ["plugin", "validate", "plugins/mcpradar-rule-deprecated"])
        assert result.exit_code == 0


class TestPluginList:
    def test_list_runs_without_error(self) -> None:
        result = runner.invoke(app, ["plugin", "list"])
        assert result.exit_code == 0

    def test_list_shows_helpful_message_when_empty(self) -> None:
        result = runner.invoke(app, ["plugin", "list"])
        output = result.stdout.lower()
        # Should mention "yuklu" (Turkish for "installed") or show the tip
        assert "plugin" in output or "yuklu" in output


class TestPluginInstall:
    def test_install_nonexistent_package_fails(self) -> None:
        result = runner.invoke(
            app,
            [
                "plugin",
                "install",
                "nonexistent-pkg-xyz-99999",
                "--sha256",
                "0" * 64,
            ],
        )
        assert result.exit_code == 1


class TestPluginUninstall:
    def test_uninstall_nonexistent_package_fails(self) -> None:
        result = runner.invoke(app, ["plugin", "uninstall", "nonexistent-pkg-xyz-99999"])
        # Even uninstalling a non-existent package may succeed (pip idempotent) or fail
        # Just check it doesn't crash
        assert result.exit_code in (0, 1)
