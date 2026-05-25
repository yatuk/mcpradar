"""MCP server tarama motoru — stdio + SSE + HTTP transport destegi."""

from __future__ import annotations

import contextlib
import shlex
from typing import Any

from mcp import ClientSession
from mcp.client.sse import sse_client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamablehttp_client
from mcp.types import Tool

from mcpradar.scanner.report import (
    PromptInfo,
    ResourceInfo,
    ScanReport,
    Severity,
    ToolInfo,
)
from mcpradar.scanner.rules import RuleEngine


class Scanner:
    def __init__(
        self,
        target: str,
        transport: str = "http",
        min_severity: Severity = Severity.MEDIUM,
    ) -> None:
        self.target = target
        self.transport = transport
        self.rule_engine = RuleEngine(min_severity=min_severity)

    async def run(self) -> ScanReport:
        report = ScanReport(target=self.target, transport=self.transport)

        if self.transport == "stdio":
            await self._run_stdio(report)
        elif self.transport == "sse":
            await self._run_sse(report)
        else:
            await self._run_http(report)

        return report

    # ------------------------------------------------------------------
    # Transport runners
    # ------------------------------------------------------------------

    async def _run_stdio(self, report: ScanReport) -> None:
        parts = shlex.split(self.target)
        params = StdioServerParameters(command=parts[0], args=parts[1:])
        async with (
            stdio_client(params) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            await self._collect_all(session, report)

    async def _run_sse(self, report: ScanReport) -> None:
        url = self.target
        if url.startswith("sse://"):
            url = url.replace("sse://", "http://", 1)
        async with (
            sse_client(url) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            await self._collect_all(session, report)

    async def _run_http(self, report: ScanReport) -> None:
        url = self.target
        # streamablehttp_client returns 3-tuple — can't combine in single `with`
        async with streamablehttp_client(url) as (read, write, _):  # noqa: SIM117
            async with ClientSession(read, write) as session:
                await session.initialize()
                await self._collect_all(session, report)

    # ------------------------------------------------------------------
    # Data collection + analysis
    # ------------------------------------------------------------------

    async def _collect_all(self, session: ClientSession, report: ScanReport) -> None:
        # -- tools --
        with contextlib.suppress(Exception):
            tools_result = await session.list_tools()
            for tool in tools_result.tools:
                ti = self._make_tool_info(tool)
                report.tools.append(ti)
                findings = self.rule_engine.analyze(ti)
                for f in findings:
                    report.add_finding(f)
                if not findings:
                    report.summary["clean"] += 1
            report.summary["total_tools"] = len(tools_result.tools)

        # -- prompts --
        with contextlib.suppress(Exception):
            prompts_result = await session.list_prompts()
            for prompt in prompts_result.prompts:
                report.prompts.append(
                    PromptInfo(
                        name=prompt.name,
                        description=getattr(prompt, "description", "") or "",
                        arguments=[
                            {
                                "name": a.name,
                                "description": getattr(a, "description", ""),
                                "required": getattr(a, "required", False),
                            }
                            for a in (getattr(prompt, "arguments", None) or [])
                        ],
                    )
                )
            report.summary["total_prompts"] = len(prompts_result.prompts)

        # -- resources --
        with contextlib.suppress(Exception):
            resources_result = await session.list_resources()
            for resource in resources_result.resources:
                report.resources.append(
                    ResourceInfo(
                        uri=str(getattr(resource, "uri", "")),
                        name=getattr(resource, "name", "") or "",
                        description=getattr(resource, "description", "") or "",
                        mime_type=getattr(resource, "mimeType", "") or "",
                    )
                )
            report.summary["total_resources"] = len(resources_result.resources)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_tool_info(tool: Tool) -> ToolInfo:
        return ToolInfo(
            name=tool.name,
            description=getattr(tool, "description", "") or "",
            input_schema=_extract_schema(getattr(tool, "inputSchema", None)),
            output_schema=_extract_schema(getattr(tool, "outputSchema", None)),
        )


def _extract_schema(raw: Any) -> dict[str, Any]:
    if raw is None:
        return {}
    if hasattr(raw, "model_dump"):
        result: Any = raw.model_dump()
        return result if isinstance(result, dict) else {}
    if isinstance(raw, dict):
        return raw
    return {}
