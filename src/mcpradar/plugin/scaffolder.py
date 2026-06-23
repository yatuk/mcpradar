"""Plugin package scaffolder — generates new MCPRadar rule packages from template."""

from __future__ import annotations

import shutil
from pathlib import Path


class Scaffolder:
    """Generates a new MCPRadar plugin package from the built-in template."""

    def __init__(self, template_dir: Path | None = None) -> None:
        if template_dir is None:
            # Find project root: this file is at src/mcpradar/plugin/scaffolder.py
            project_root = Path(__file__).resolve().parent.parent.parent.parent
            template_dir = project_root / "plugins" / "template"
        self._template_dir = template_dir

    def scaffold(
        self,
        name: str,
        output_dir: Path,
        description: str = "Custom detection rule for MCPRadar",
    ) -> Path:
        """Generate a new plugin package. Returns path to created package directory."""
        if not self._template_dir.exists():
            raise FileNotFoundError(f"Template not found: {self._template_dir}")

        # Derive names
        package_name = f"mcpradar-rule-{name}"
        module_name = f"mcpradar_rule_{name.replace('-', '_')}"
        class_name = f"{self._pascal_case(name)}Rule"
        entry_point_name = name.replace("-", "_")

        # Variable substitution map
        vars_map = {
            "mcpradar-rule-example": package_name,
            "mcpradar_rule_example": module_name,
            "ExampleRule": class_name,
            '"example"': f'"{entry_point_name}"',
        }

        dest_dir = output_dir / package_name
        if dest_dir.exists():
            shutil.rmtree(dest_dir)

        # Copy template with substitution
        self._copy_with_substitution(self._template_dir, dest_dir, vars_map)

        return dest_dir

    @staticmethod
    def _pascal_case(name: str) -> str:
        """Convert 'my-sqli' -> 'MySqli'."""
        return "".join(part.capitalize() for part in name.replace("_", "-").split("-"))

    @staticmethod
    def _replace_vars(text: str, vars_map: dict[str, str]) -> str:
        """Apply all variable substitutions to text."""
        result = text
        for old, new in vars_map.items():
            result = result.replace(old, new)
        return result

    def _copy_with_substitution(self, src: Path, dst: Path, vars_map: dict[str, str]) -> None:
        """Copy directory tree with variable substitution in file contents and names."""
        dst.mkdir(parents=True, exist_ok=True)
        for item in src.iterdir():
            # Skip Python cache directories and bytecode files
            if item.name == "__pycache__" or item.suffix == ".pyc":
                continue
            target_name = self._replace_vars(item.name, vars_map)
            target = dst / target_name
            if item.is_dir():
                self._copy_with_substitution(item, target, vars_map)
            else:
                content = item.read_text(encoding="utf-8")
                new_content = self._replace_vars(content, vars_map)
                target.write_text(new_content, encoding="utf-8")
