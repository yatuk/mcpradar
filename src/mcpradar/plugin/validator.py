"""Plugin validator — checks plugin structure, imports, and tests."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ValidationResult:
    """Result of a single validation check."""

    passed: bool
    message: str
    detail: str = ""


@dataclass
class ValidationReport:
    """Complete validation report for a plugin."""

    directory: Path
    results: list[ValidationResult] = field(default_factory=list)
    tests_passed: bool | None = None

    @property
    def is_valid(self) -> bool:
        return all(r.passed for r in self.results)


class PluginValidator:
    """Validates a MCPRadar plugin package."""

    def __init__(self, run_tests: bool = False) -> None:
        self._run_tests = run_tests

    def validate(self, directory: Path) -> ValidationReport:
        report = ValidationReport(directory=directory)

        # 1. pyproject.toml exists
        pyproject = directory / "pyproject.toml"
        if not pyproject.exists():
            report.results.append(
                ValidationResult(False, "pyproject.toml not found", str(pyproject))
            )
            return report  # Can't continue without pyproject.toml
        report.results.append(ValidationResult(True, "pyproject.toml found"))

        # 2. Entry point section exists
        entry_points = self._parse_entry_points(pyproject)
        if not entry_points:
            report.results.append(
                ValidationResult(
                    False,
                    "No entry_point defined",
                    '[project.entry-points."mcpradar.rules"] not found',
                )
            )
            return report
        report.results.append(
            ValidationResult(
                True,
                f"{len(entry_points)} entry_point(s) defined",
                ", ".join(entry_points),
            )
        )

        # 3. Each entry point is importable + 4. Rule subclass + 5. rule_id format
        src_path = directory / "src"
        if str(src_path) not in sys.path:
            sys.path.insert(0, str(src_path))

        try:
            import importlib

            from mcpradar.scanner.rules import Rule

            for ep_ref in entry_points:
                # ep_ref is like "mcpradar_rule_example.rule:ExampleRule"
                if ":" not in ep_ref:
                    report.results.append(
                        ValidationResult(
                            False,
                            f"Invalid entry_point format: '{ep_ref}'",
                            "Expected module:Class",
                        )
                    )
                    continue

                module_path, class_name = ep_ref.split(":", 1)

                # Check import
                try:
                    module = importlib.import_module(module_path)
                except ImportError as exc:
                    report.results.append(
                        ValidationResult(
                            False,
                            f"Module could not be imported: {module_path}",
                            str(exc),
                        )
                    )
                    continue

                # Check class exists
                if not hasattr(module, class_name):
                    report.results.append(
                        ValidationResult(
                            False,
                            f"Class not found: {class_name}",
                            f"'{class_name}' not in module {module_path}",
                        )
                    )
                    continue

                cls = getattr(module, class_name)

                # Check Rule subclass
                if not isinstance(cls, type) or not issubclass(cls, Rule):
                    report.results.append(
                        ValidationResult(
                            False,
                            f"Rule class does not inherit from Rule: {class_name}",
                        )
                    )
                    continue

                # Check rule_id format
                try:
                    instance = cls()
                except Exception as exc:
                    report.results.append(
                        ValidationResult(
                            False,
                            f"Could not instantiate rule: {class_name}",
                            str(exc),
                        )
                    )
                    continue

                if not re.match(r"^X\d{3}$", instance.rule_id):
                    report.results.append(
                        ValidationResult(
                            False,
                            f"Invalid rule_id format: '{instance.rule_id}'",
                            "Expected X### (e.g. X001)",
                        )
                    )
                else:
                    report.results.append(
                        ValidationResult(
                            True,
                            f"Rule valid: {class_name} ({instance.rule_id}) - {instance.title}",
                        )
                    )

        finally:
            if str(src_path) in sys.path:
                sys.path.remove(str(src_path))

        # 6. Run tests (optional)
        if self._run_tests:
            tests_dir = directory / "tests"
            if not tests_dir.exists() or not list(tests_dir.glob("test_*.py")):
                report.tests_passed = None
                report.results.append(
                    ValidationResult(True, "Test directory empty or missing — skipping")
                )
            else:
                # Resolve to absolute so relative cwd doesn't break paths
                abs_directory = directory.resolve()
                abs_tests_dir = abs_directory / "tests"
                src_dir = str(abs_directory / "src")
                env = os.environ.copy()
                existing_path = env.get("PYTHONPATH", "")
                env["PYTHONPATH"] = (
                    src_dir + os.pathsep + existing_path if existing_path else src_dir
                )
                try:
                    result = subprocess.run(
                        [sys.executable, "-m", "pytest", str(abs_tests_dir), "-v"],
                        cwd=str(abs_directory),
                        capture_output=True,
                        text=True,
                        timeout=30,
                        env=env,
                    )
                    report.tests_passed = result.returncode == 0
                    if report.tests_passed:
                        report.results.append(ValidationResult(True, "Tests passed"))
                    else:
                        report.results.append(
                            ValidationResult(
                                False,
                                "Tests failed",
                                result.stdout.split("\n")[-3]
                                if result.stdout
                                else str(result.stderr),
                            )
                        )
                except FileNotFoundError:
                    report.results.append(
                        ValidationResult(False, "pytest not found — tests could not run")
                    )
                except subprocess.TimeoutExpired:
                    report.results.append(ValidationResult(False, "Tests timed out"))

        return report

    @staticmethod
    def _parse_entry_points(pyproject: Path) -> list[str]:
        """Parse entry_points from pyproject.toml. Returns list of ref strings."""
        import tomllib

        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except Exception:
            return []

        eps = data.get("project", {}).get("entry-points", {})
        mcpradar_eps = eps.get("mcpradar.rules", {})
        if isinstance(mcpradar_eps, dict):
            return list(mcpradar_eps.values())
        return []
