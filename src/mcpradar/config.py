"""mcpradar.toml configuration reader."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ServerConfig:
    url: str
    name: str = ""
    transport: str = "http"
    interval: int = 300


@dataclass
class RulesConfig:
    min_severity: str = "medium"
    disabled_rules: list[str] = field(default_factory=list)


@dataclass
class WatchConfig:
    interval: int = 300
    alert_command: str = ""
    alert_webhook: str = ""


@dataclass
class OutputConfig:
    format: str = "rich"
    history_dir: str = "snapshots"


@dataclass
class MCPRadarConfig:
    servers: list[ServerConfig] = field(default_factory=list)
    rules: RulesConfig = field(default_factory=RulesConfig)
    watch: WatchConfig = field(default_factory=WatchConfig)
    output: OutputConfig = field(default_factory=OutputConfig)

    @classmethod
    def from_file(cls, path: Path | str | None = None) -> MCPRadarConfig | None:
        paths = [Path(p) for p in ([path] if path else []) if Path(p).exists()]
        if not paths:
            default = Path("mcpradar.toml")
            if default.exists():
                paths = [default]

        if not paths:
            return None

        with open(paths[0], "rb") as f:
            raw = tomllib.load(f)

        servers = []
        for s in raw.get("servers", raw.get("server", [])):
            servers.append(
                ServerConfig(
                    url=s.get("url", ""),
                    name=s.get("name", ""),
                    transport=s.get("transport", "http"),
                    interval=s.get("interval", 300),
                )
            )

        rules_raw = raw.get("rules", {})
        rules = RulesConfig(
            min_severity=rules_raw.get("min_severity", "medium"),
            disabled_rules=rules_raw.get("disabled_rules", []),
        )

        watch_raw = raw.get("watch", {})
        watch = WatchConfig(
            interval=watch_raw.get("interval", 300),
            alert_command=watch_raw.get("alert_command", ""),
            alert_webhook=watch_raw.get("alert_webhook", ""),
        )

        output_raw = raw.get("output", {})
        output = OutputConfig(
            format=output_raw.get("format", "rich"),
            history_dir=output_raw.get("history_dir", "snapshots"),
        )

        return cls(servers=servers, rules=rules, watch=watch, output=output)
