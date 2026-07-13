"""MCP server scan engine — stdio + SSE + HTTP transport support."""

from __future__ import annotations

import asyncio
import contextlib
import shlex
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcpradar.audit.auditor import AuditLogger

from mcp import ClientSession
from mcp.client.sse import sse_client
from mcp.client.stdio import StdioServerParameters, stdio_client

# streamablehttp_client renamed to streamable_http_client in MCP SDK 1.28+
from mcp.client.streamable_http import streamable_http_client as streamablehttp_client
from mcp.types import Tool

from mcpradar.probe.prober import ReadOnlyProber
from mcpradar.scanner.report import (
    PromptInfo,
    ResourceInfo,
    ScanReport,
    Severity,
    ToolInfo,
)
from mcpradar.scanner.rules import RuleEngine, check_server_auth


class Scanner:
    def __init__(
        self,
        target: str,
        transport: str = "http",
        min_severity: Severity = Severity.MEDIUM,
        prober: ReadOnlyProber | None = None,
        probe_safe_only: bool = True,
        audit: AuditLogger | None = None,
        launch_command: str | None = None,
    ) -> None:
        self.target = target
        self.transport = transport
        self.min_severity = min_severity
        self.prober = prober
        self.probe_safe_only = probe_safe_only
        self.rule_engine = RuleEngine(min_severity=min_severity)
        self.audit = audit
        # stdio only: actual command to launch (e.g. container-wrapped by
        # --sandbox) while `target` stays the server's identity for
        # reports, snapshots and diffs.
        self.launch_command = launch_command

    async def run(self) -> ScanReport:
        report = ScanReport(target=self.target, transport=self.transport)

        if self.audit:
            self.audit.log_scan_start(self.target, self.transport)

        if self.transport == "stdio":
            await self._run_stdio(report)
        elif self.transport == "sse":
            await self._run_sse(report)
        else:
            await self._run_http(report)

        # Transport security check
        from mcpradar.fingerprint.transport_check import TransportChecker

        checker = TransportChecker()
        tls_info = checker.check(self.target, self.transport)
        if tls_info or self.transport != "stdio":
            r111_findings = checker.generate_findings(self.target, self.transport, tls_info)
            for f in r111_findings:
                if f.severity >= self.min_severity:
                    report.add_finding(f)

        if self.audit:
            self.audit.log_scan_complete(report.id, len(report.findings))

        return report

    # ------------------------------------------------------------------
    # Auth hardening check (R112)
    # ------------------------------------------------------------------

    def _check_auth(
        self,
        report: ScanReport,
        session_id: str | None = None,
    ) -> None:
        """Run authorization hardening checks (R112) after server initialization.

        Args:
            report: Scan report to add findings to.
            session_id: The session ID if one was negotiated (Mcp-Session-Id header),
                None if the server uses stateless transports.
        """
        findings = check_server_auth(
            target=report.target,
            transport=report.transport,
            has_iss=None,  # OAuth discovery requires separate endpoint probing
            has_app_type=None,  # DCR metadata requires separate endpoint probing
            uses_session_id=bool(session_id),
        )
        for f in findings:
            if f.severity >= self.min_severity:
                report.add_finding(f)

    # ------------------------------------------------------------------
    # Transport runners
    # ------------------------------------------------------------------

    async def _run_stdio(self, report: ScanReport) -> None:
        parts = shlex.split(self.launch_command or self.target)
        params = StdioServerParameters(command=parts[0], args=parts[1:])
        async with (
            stdio_client(params) as (read, write),
            ClientSession(read, write) as session,
        ):
            init_result = await session.initialize()
            report.server_version = getattr(init_result, "serverVersion", "") or ""
            report.protocol_version = getattr(init_result, "protocolVersion", "") or ""
            caps = getattr(init_result, "capabilities", None)
            if caps is not None:
                if hasattr(caps, "model_dump"):
                    report.capabilities = caps.model_dump()
                elif isinstance(caps, dict):
                    report.capabilities = caps
            await self._collect_all(session, report)
            self._check_auth(report, session_id=None)

            # Runtime probing
            if self.prober is not None:
                if self.probe_safe_only:
                    tools_to_probe = [t for t in report.tools if self.prober.is_safe_tool(t)]
                else:
                    tools_to_probe = list(report.tools)
                for tool in tools_to_probe[: self.prober.MAX_PROBE_COUNT]:
                    result = await self.prober.probe_tool(session, tool, report.target)
                    report.probe_results.append(result)

    async def _run_sse(self, report: ScanReport) -> None:
        url = self.target
        if url.startswith("sse://"):
            url = url.replace("sse://", "http://", 1)

        sse_session_id: str | None = None

        def _on_session_created(sid: str) -> None:
            nonlocal sse_session_id
            sse_session_id = sid

        async with (
            sse_client(url, on_session_created=_on_session_created) as (read, write),
            ClientSession(read, write) as session,
        ):
            init_result = await session.initialize()
            report.server_version = getattr(init_result, "serverVersion", "") or ""
            report.protocol_version = getattr(init_result, "protocolVersion", "") or ""
            caps = getattr(init_result, "capabilities", None)
            if caps is not None:
                if hasattr(caps, "model_dump"):
                    report.capabilities = caps.model_dump()
                elif isinstance(caps, dict):
                    report.capabilities = caps
            await self._collect_all(session, report)
            self._check_auth(report, session_id=sse_session_id)

            # Runtime probing
            if self.prober is not None:
                if self.probe_safe_only:
                    tools_to_probe = [t for t in report.tools if self.prober.is_safe_tool(t)]
                else:
                    tools_to_probe = list(report.tools)
                for tool in tools_to_probe[: self.prober.MAX_PROBE_COUNT]:
                    result = await self.prober.probe_tool(session, tool, report.target)
                    report.probe_results.append(result)

    async def _run_http(self, report: ScanReport) -> None:
        url = self.target
        # streamablehttp_client returns 3-tuple — get_session_id callback
        async with (
            streamablehttp_client(url) as (read, write, get_session_id),
            ClientSession(read, write) as session,
        ):
            init_result = await session.initialize()
            report.server_version = getattr(init_result, "serverVersion", "") or ""
            report.protocol_version = getattr(init_result, "protocolVersion", "") or ""
            caps = getattr(init_result, "capabilities", None)
            if caps is not None:
                if hasattr(caps, "model_dump"):
                    report.capabilities = caps.model_dump()
                elif isinstance(caps, dict):
                    report.capabilities = caps
            await self._collect_all(session, report)

            # Detect session ID for R112
            http_session_id = get_session_id() if callable(get_session_id) else None
            self._check_auth(report, session_id=http_session_id)

            # Runtime probing
            if self.prober is not None:
                if self.probe_safe_only:
                    tools_to_probe = [t for t in report.tools if self.prober.is_safe_tool(t)]
                else:
                    tools_to_probe = list(report.tools)
                for tool in tools_to_probe[: self.prober.MAX_PROBE_COUNT]:
                    result = await self.prober.probe_tool(session, tool, report.target)
                    report.probe_results.append(result)

    # ------------------------------------------------------------------
    # Data collection + analysis
    # ------------------------------------------------------------------

    async def _collect_all(self, session: ClientSession, report: ScanReport) -> None:
        # -- tools -- (cursor-paginated; a partial failure marks the scan
        # incomplete rather than silently under-counting to a clean grade A)
        cursor: str | None = None
        try:
            for _page in range(50):  # hard cap: never loop forever on a bad cursor
                tools_result = (
                    await session.list_tools(cursor) if cursor else await session.list_tools()
                )
                for tool in tools_result.tools:
                    ti = self._make_tool_info(tool)
                    report.tools.append(ti)
                    try:
                        findings = self.rule_engine.analyze(ti)
                    except Exception as exc:  # a rule bug must not drop the tool
                        findings = []
                        report.incomplete = True
                        report.incomplete_reason = f"rule error on tool '{ti.name}': {exc}"[:200]
                    for f in findings:
                        report.add_finding(f)
                    if not findings:
                        report.summary["clean"] += 1
                # Only a genuine non-empty string cursor continues pagination;
                # anything else (None, a mock, "") ends it.
                nxt = getattr(tools_result, "nextCursor", None)
                if not isinstance(nxt, str) or not nxt or nxt == cursor:
                    break
                cursor = nxt
        except Exception as exc:
            report.incomplete = True
            if not report.incomplete_reason:
                report.incomplete_reason = f"tool enumeration failed: {exc}"[:200]
        report.summary["total_tools"] = len(report.tools)

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


class ParallelScanner:
    """Scan multiple MCP servers concurrently with a semaphore cap."""

    def __init__(self, max_concurrency: int = 5) -> None:
        self._semaphore = asyncio.Semaphore(max_concurrency)

    async def scan_one(
        self,
        target: str,
        transport: str = "http",
        min_severity: Severity = Severity.MEDIUM,
        prober: ReadOnlyProber | None = None,
        audit: AuditLogger | None = None,
    ) -> ScanReport:
        """Scan a single server, guarded by the concurrency semaphore."""
        async with self._semaphore:
            scanner = Scanner(
                target=target,
                transport=transport,
                min_severity=min_severity,
                prober=prober,
                audit=audit,
            )
            return await scanner.run()

    async def scan_all(
        self,
        servers: list[tuple[str, str]],
        min_severity: Severity = Severity.MEDIUM,
        prober: ReadOnlyProber | None = None,
        audit: AuditLogger | None = None,
    ) -> list[ScanReport | Exception]:
        """Scan all servers concurrently.

        Args:
            servers: List of (target, transport) tuples.

        Returns:
            List of ScanReport or Exception for each server.
            Exceptions are returned, not raised — one failing server
            does not block others.
        """
        tasks = [
            self.scan_one(target, transport, min_severity, prober, audit)
            for target, transport in servers
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results  # type: ignore[return-value]
