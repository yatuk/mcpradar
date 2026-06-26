"""mcpradar.toml configuration file generator."""

from __future__ import annotations

from pathlib import Path

import tomli_w


class Initializer:
    def generate(self, path: Path) -> None:
        config = {
            "servers": [
                {
                    "url": "http://localhost:8080",
                    "name": "local-mcp",
                    "transport": "http",
                    "interval": 300,
                }
            ],
            "rules": {
                "min_severity": "medium",
                "disabled_rules": [],
            },
            "watch": {
                "interval": 300,
                "alert_command": "",
                "alert_webhook": "",
            },
            "output": {
                "format": "rich",
                "history_dir": "snapshots",
            },
        }
        path.write_text(tomli_w.dumps(config), encoding="utf-8")
