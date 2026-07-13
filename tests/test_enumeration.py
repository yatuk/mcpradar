"""Enumeration robustness: pagination + per-tool error isolation + incomplete."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from mcpradar.scanner.engine import Scanner
from mcpradar.scanner.report import ScanReport


class _FakeSession:
    """Minimal async session returning paginated tool lists."""

    def __init__(self, pages: list[tuple[list[str], str | None]]) -> None:
        self._pages = pages
        self.calls: list[str | None] = []

    async def list_tools(self, cursor: str | None = None):
        self.calls.append(cursor)
        names, next_cursor = self._pages[len(self.calls) - 1]
        tools = [
            SimpleNamespace(name=n, description="", inputSchema={}, outputSchema=None)
            for n in names
        ]
        return SimpleNamespace(tools=tools, nextCursor=next_cursor)

    async def list_prompts(self):
        raise RuntimeError("no prompts")

    async def list_resources(self):
        raise RuntimeError("no resources")


def _collect(scanner: Scanner, session: _FakeSession) -> ScanReport:
    report = ScanReport(target="x", transport="stdio")
    asyncio.run(scanner._collect_all(session, report))
    return report


class TestPagination:
    def test_follows_next_cursor(self) -> None:
        session = _FakeSession([(["a", "b"], "cur1"), (["c"], None)])
        report = _collect(Scanner("x", transport="stdio"), session)
        assert [t.name for t in report.tools] == ["a", "b", "c"]
        assert report.summary["total_tools"] == 3
        assert session.calls == [None, "cur1"]
        assert report.incomplete is False


class TestErrorIsolation:
    def test_rule_error_does_not_drop_tools(self, monkeypatch) -> None:
        scanner = Scanner("x", transport="stdio")

        original = scanner.rule_engine.analyze

        def boom(tool):
            if tool.name == "b":
                raise ValueError("rule crashed")
            return original(tool)

        monkeypatch.setattr(scanner.rule_engine, "analyze", boom)
        session = _FakeSession([(["a", "b", "c"], None)])
        report = _collect(scanner, session)
        # all three tools survive even though the rule raised on 'b'
        assert [t.name for t in report.tools] == ["a", "b", "c"]
        assert report.incomplete is True
        assert "b" in report.incomplete_reason

    def test_enumeration_failure_marks_incomplete(self) -> None:
        class _Broken(_FakeSession):
            async def list_tools(self, cursor: str | None = None):
                raise ConnectionError("dropped")

        report = _collect(Scanner("x", transport="stdio"), _Broken([]))
        assert report.incomplete is True
        assert report.summary["total_tools"] == 0
