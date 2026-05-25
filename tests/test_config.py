"""Config reader tests."""

import tempfile
from pathlib import Path

from mcpradar.config import MCPRadarConfig


class TestConfig:
    def test_from_file_basic(self) -> None:
        toml = """
[[servers]]
url = "http://test"
name = "test-server"
transport = "http"
interval = 300
"""
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "mcpradar.toml"
            p.write_text(toml)

            cfg = MCPRadarConfig.from_file(p)
            assert cfg is not None
            assert len(cfg.servers) == 1
            assert cfg.servers[0].url == "http://test"
            assert cfg.servers[0].name == "test-server"
            assert cfg.servers[0].transport == "http"

    def test_from_file_with_rules_and_watch(self) -> None:
        toml = """
[[servers]]
url = "http://x"
name = "x"

[rules]
min_severity = "high"
disabled_rules = ["R001"]

[watch]
interval = 600
alert_command = "echo changed"
alert_webhook = "https://hooks.slack.com/x"

[output]
format = "sarif"
history_dir = "my_snapshots"
"""
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "mcpradar.toml"
            p.write_text(toml)

            cfg = MCPRadarConfig.from_file(p)
            assert cfg is not None
            assert cfg.rules.min_severity == "high"
            assert cfg.rules.disabled_rules == ["R001"]
            assert cfg.watch.interval == 600
            assert cfg.watch.alert_command == "echo changed"
            assert cfg.watch.alert_webhook == "https://hooks.slack.com/x"
            assert cfg.output.format == "sarif"

    def test_missing_file_returns_none(self) -> None:
        import os
        with tempfile.TemporaryDirectory() as tmp:
            old = os.getcwd()
            os.chdir(tmp)
            try:
                cfg = MCPRadarConfig.from_file()
                assert cfg is None
            finally:
                os.chdir(old)

    def test_multiple_servers(self) -> None:
        toml = """
[[servers]]
url = "http://a"
name = "server-a"
transport = "stdio"

[[servers]]
url = "http://b"
name = "server-b"
transport = "sse"
interval = 120
"""
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "mcpradar.toml"
            p.write_text(toml)

            cfg = MCPRadarConfig.from_file(p)
            assert cfg is not None
            assert len(cfg.servers) == 2
            assert cfg.servers[0].transport == "stdio"
            assert cfg.servers[1].transport == "sse"
            assert cfg.servers[1].interval == 120
