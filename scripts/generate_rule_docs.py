"""Generate detection-rule documentation from the canonical catalog."""

from pathlib import Path

from mcpradar.rules.catalog import render_markdown


def main() -> None:
    output = Path("docs/detection-rules.md")
    output.write_text(render_markdown(), encoding="utf-8")
    print(f"Generated {output}")


if __name__ == "__main__":
    main()
