"""Tests for the agentic capability layer (mcpradar.scoring.capability)."""

from __future__ import annotations

from mcpradar.scoring.capability import (
    CAPABILITY_WEIGHTS,
    compute_aars,
    dominant_capability,
    tag_tool,
)


def _tool(name: str, desc: str = "", props: list[str] | None = None) -> dict:
    schema = {"properties": {p: {} for p in (props or [])}}
    return {"name": name, "description": desc, "input_schema": schema}


class TestTagTool:
    def test_code_exec(self) -> None:
        assert "code_exec" in tag_tool(_tool("run_command", "Run a shell command", ["command"]))
        assert "code_exec" in tag_tool(_tool("system_config", "Execute system config commands"))
        assert "code_exec" in tag_tool(_tool("eval_expr", "eval the code", ["code"]))

    def test_pure_compute(self) -> None:
        assert tag_tool(_tool("calculate", "Evaluates a math expression", ["expression"])) == {
            "pure_compute"
        }
        assert tag_tool(_tool("get_weather", "Get current weather", ["city"])) == {"pure_compute"}

    def test_fs_write_over_read(self) -> None:
        # a tool that both reads and writes is tagged fs_write, not fs_read
        caps = tag_tool(_tool("edit_file", "Edit and save a file", ["path", "content"]))
        assert "fs_write" in caps
        assert "fs_read" not in caps

    def test_browser_requires_action_not_noun(self) -> None:
        # bare "browser" noun (browser-free) must not tag browser_control
        assert "browser_control" not in tag_tool(
            _tool("fetch_content", "Read a page without a browser", ["url"])
        )
        assert "browser_control" in tag_tool(_tool("browser_navigate", "Navigate to a URL"))
        assert "browser_control" in tag_tool(_tool("take_screenshot", "Screenshot the page"))

    def test_search_query_not_db_write(self) -> None:
        # a *search* query is not a database write
        assert "db_write" not in tag_tool(_tool("search", "Search the web", ["query"]))
        assert "db_write" in tag_tool(_tool("run_sql", "Execute an SQL insert", ["sql"]))

    def test_file_system_phrase_not_code_exec(self) -> None:
        # "file system" in a description must not tag code_exec
        assert "code_exec" not in tag_tool(
            _tool("read_file", "Read from the file system", ["path"])
        )


class TestComputeAars:
    def test_pure_compute_zero(self) -> None:
        assert compute_aars([_tool("calculate", "Evaluates math", ["expression"])]) == 0.0

    def test_exec_dominates(self) -> None:
        aars = compute_aars([_tool("run_command", "Run a shell command", ["command"])])
        assert aars == CAPABILITY_WEIGHTS["code_exec"]

    def test_breadth_bonus(self) -> None:
        # exec + net egress → top weight plus a breadth bonus
        tools = [
            _tool("run_command", "Run a command", ["command"]),
            _tool("fetch", "Fetch a URL", ["url"]),
        ]
        assert compute_aars(tools) == CAPABILITY_WEIGHTS["code_exec"] + 0.5

    def test_read_only_bonus_excluded(self) -> None:
        # fs_read (weight 1 < 2) adds no breadth bonus on top of fs_write
        tools = [
            _tool("write_file", "Write a file", ["path", "content"]),
            _tool("read_file", "Read a file", ["path"]),
        ]
        assert compute_aars(tools) == CAPABILITY_WEIGHTS["fs_write"]

    def test_dominant_capability(self) -> None:
        tools = [_tool("read_file", "Read", ["path"]), _tool("run_command", "Run", ["command"])]
        assert dominant_capability(tools) == "code_exec"
