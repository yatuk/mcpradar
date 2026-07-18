"""MCP server scan engine — stdio + SSE + HTTP transport support."""

from __future__ import annotations

import asyncio
import shlex
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcpradar.audit.auditor import AuditLogger

from mcp import ClientSession
from mcp.client import streamable_http as _streamable_http
from mcp.client.sse import sse_client
from mcp.client.stdio import StdioServerParameters, stdio_client

from mcpradar.probe.prober import ReadOnlyProber
from mcpradar.scanner.report import (
    PromptInfo,
    ResourceInfo,
    ResourceTemplateInfo,
    ScanReport,
    Severity,
    SurfaceState,
    SurfaceStatus,
    ToolInfo,
)
from mcpradar.scanner.rules import RuleEngine, check_server_auth

# streamablehttp_client was renamed in MCP SDK 1.28. Support the complete
# declared >=1.27,<2 compatibility window while erasing incompatible call
# signatures exposed by the two SDK versions.
streamablehttp_client: Any = getattr(_streamable_http, "streamable_http_client", None)
if streamablehttp_client is None:  # pragma: no cover - MCP SDK 1.27 compatibility
    streamablehttp_client = _streamable_http.streamablehttp_client


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
        enabled_plugins: list[str] | None = None,
        protocol_profile: str = "v1",
    ) -> None:
        self.target = target
        self.transport = transport
        self.min_severity = min_severity
        self.prober = prober
        self.probe_safe_only = probe_safe_only
        self.rule_engine = RuleEngine(
            min_severity=min_severity,
            enabled_plugins=enabled_plugins,
        )
        self.audit = audit
        # stdio only: actual command to launch (e.g. container-wrapped by
        # --sandbox) while `target` stays the server's identity for
        # reports, snapshots and diffs.
        self.launch_command = launch_command
        self.protocol_profile = protocol_profile

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
        has_iss: bool | None = None
        has_pkce: bool | None = None
        # OAuth discovery only applies to network transports; stdio has no
        # authorization server. Best-effort — never fails the scan.
        if report.transport in ("http", "sse"):
            try:
                from mcpradar.probe.oauth import probe_oauth_metadata

                meta = probe_oauth_metadata(report.target)
                if meta is not None and meta.uses_oauth:
                    has_iss = meta.has_iss
                    has_pkce = meta.has_pkce_s256
            except Exception:
                pass

        findings = check_server_auth(
            target=report.target,
            transport=report.transport,
            has_iss=has_iss,
            has_app_type=None,  # application_type is client-side, not observable
            uses_session_id=bool(session_id),
            has_pkce_s256=has_pkce,
            protocol_version=report.protocol_version,
        )
        for f in findings:
            if f.severity >= self.min_severity:
                report.add_finding(f)

        from mcpradar.scanner.protocol import assess_migration_readiness

        report.migration_readiness.extend(
            assess_migration_readiness(
                report.protocol_version,
                uses_session_id=bool(session_id),
            )
        )

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
            self._apply_initialize_result(report, init_result)
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
            self._apply_initialize_result(report, init_result)
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
        if self.protocol_profile in {"auto", "2026-07-28"}:
            from mcpradar.scanner.protocol_adapter import (
                ProtocolNotSupportedError,
                StatelessHttpSession,
            )

            try:
                async with StatelessHttpSession(url) as stateless_session:
                    discovery = await stateless_session.discover()
                    supported = getattr(discovery, "supportedVersions", [])
                    if not isinstance(supported, list) or "2026-07-28" not in supported:
                        raise ProtocolNotSupportedError("server did not advertise MCP 2026-07-28")
                    self._apply_discovery_result(report, discovery)
                    await self._collect_all(stateless_session, report)
                    self._check_auth(report, session_id=None)
                    return
            except ProtocolNotSupportedError:
                if self.protocol_profile == "2026-07-28":
                    raise
        # streamablehttp_client returns 3-tuple — get_session_id callback
        async with (
            streamablehttp_client(url) as (read, write, get_session_id),
            ClientSession(read, write) as session,
        ):
            init_result = await session.initialize()
            self._apply_initialize_result(report, init_result)
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

    async def _collect_all(self, session: object, report: ScanReport) -> None:
        """Enumerate every MCP list surface with bounded cursor pagination."""
        surface_specs = (
            ("tools", "list_tools", "tools"),
            ("prompts", "list_prompts", "prompts"),
            ("resources", "list_resources", "resources"),
            (
                "resource_templates",
                "list_resource_templates",
                "resourceTemplates",
            ),
        )
        collected: dict[str, list[object]] = {}
        for surface, method, result_attribute in surface_specs:
            items, status = await self._collect_pages(
                session,
                report,
                surface=surface,
                method_name=method,
                result_attribute=result_attribute,
            )
            collected[surface] = items
            report.surface_status[surface] = status

        for raw_tool in collected["tools"]:
            try:
                tool = self._make_tool_info(raw_tool)
            except Exception as exc:
                self._mark_incomplete(report, f"invalid tool metadata: {exc}")
                continue
            report.tools.append(tool)
            try:
                findings = self.rule_engine.analyze(tool)
            except Exception as exc:
                findings = []
                self._mark_incomplete(report, f"rule error on tool '{tool.name}': {exc}")
            for finding in findings:
                report.add_finding(finding)
            if not findings:
                report.summary["clean"] += 1

        for raw_prompt in collected["prompts"]:
            prompt = PromptInfo(
                name=str(getattr(raw_prompt, "name", "")),
                description=str(getattr(raw_prompt, "description", "") or ""),
                arguments=[
                    {
                        "name": str(getattr(argument, "name", "")),
                        "description": str(getattr(argument, "description", "") or ""),
                        "required": bool(getattr(argument, "required", False)),
                    }
                    for argument in (getattr(raw_prompt, "arguments", None) or [])
                ],
            )
            report.prompts.append(prompt)
            self._analyze_text_surface(report, "prompt", prompt.name, prompt.description)

        for raw_resource in collected["resources"]:
            resource = ResourceInfo(
                uri=str(getattr(raw_resource, "uri", "")),
                name=str(getattr(raw_resource, "name", "") or ""),
                description=str(getattr(raw_resource, "description", "") or ""),
                mime_type=str(getattr(raw_resource, "mimeType", "") or ""),
            )
            report.resources.append(resource)
            self._analyze_text_surface(
                report,
                "resource",
                resource.name or resource.uri,
                resource.description,
            )

        for raw_template in collected["resource_templates"]:
            template = ResourceTemplateInfo(
                uri_template=str(getattr(raw_template, "uriTemplate", "")),
                name=str(getattr(raw_template, "name", "") or ""),
                description=str(getattr(raw_template, "description", "") or ""),
                mime_type=str(getattr(raw_template, "mimeType", "") or ""),
            )
            report.resource_templates.append(template)
            self._analyze_text_surface(
                report,
                "resource_template",
                template.name or template.uri_template,
                template.description,
            )

        if report.server_instructions:
            self._analyze_text_surface(
                report,
                "server_instructions",
                report.target,
                report.server_instructions,
            )
            report.surface_status["server_instructions"] = SurfaceStatus(
                state=SurfaceState.COMPLETE,
                count=1,
                pages=1,
            )
        else:
            report.surface_status["server_instructions"] = SurfaceStatus()

        report.summary["total_tools"] = len(report.tools)
        report.summary["total_prompts"] = len(report.prompts)
        report.summary["total_resources"] = len(report.resources)
        report.summary["total_resource_templates"] = len(report.resource_templates)

    async def _collect_pages(
        self,
        session: object,
        report: ScanReport,
        *,
        surface: str,
        method_name: str,
        result_attribute: str,
    ) -> tuple[list[object], SurfaceStatus]:
        method = getattr(session, method_name, None)
        if not callable(method) or not self._surface_supported(report, surface):
            return [], SurfaceStatus()

        items: list[object] = []
        cursor: str | None = None
        pages = 0
        ttl_ms: int | None = None
        cache_scope = ""
        try:
            for _page in range(50):
                result = await method(cursor) if cursor else await method()
                page_items = getattr(result, result_attribute, None)
                if not isinstance(page_items, (list, tuple)):
                    return [], SurfaceStatus(
                        state=SurfaceState.UNSUPPORTED,
                        error=f"{method_name} returned no {result_attribute} list",
                    )
                items.extend(page_items)
                pages += 1
                raw_ttl = getattr(result, "ttlMs", None)
                if isinstance(raw_ttl, int):
                    ttl_ms = raw_ttl
                raw_scope = getattr(result, "cacheScope", None)
                if isinstance(raw_scope, str):
                    cache_scope = raw_scope
                next_cursor = getattr(result, "nextCursor", None)
                if not isinstance(next_cursor, str) or not next_cursor or next_cursor == cursor:
                    return items, SurfaceStatus(
                        state=SurfaceState.COMPLETE,
                        count=len(items),
                        pages=pages,
                        ttl_ms=ttl_ms,
                        cache_scope=cache_scope,
                    )
                cursor = next_cursor
            self._mark_incomplete(report, f"{surface} pagination exceeded 50 pages")
            return items, SurfaceStatus(
                state=SurfaceState.PARTIAL,
                count=len(items),
                pages=pages,
                error="pagination page limit exceeded",
                ttl_ms=ttl_ms,
                cache_scope=cache_scope,
            )
        except Exception as exc:
            if surface == "tools" or self._surface_advertised(report, surface):
                self._mark_incomplete(report, f"{surface} enumeration failed: {exc}")
            return items, SurfaceStatus(
                state=SurfaceState.PARTIAL if items else SurfaceState.FAILED,
                count=len(items),
                pages=pages,
                error=str(exc)[:200],
                ttl_ms=ttl_ms,
                cache_scope=cache_scope,
            )

    def _analyze_text_surface(
        self,
        report: ScanReport,
        surface: str,
        name: str,
        description: str,
    ) -> None:
        synthetic = ToolInfo(name=name, description=description)
        try:
            findings = self.rule_engine.analyze(synthetic)
        except Exception as exc:
            self._mark_incomplete(report, f"rule error on {surface} '{name}': {exc}")
            return
        for finding in findings:
            finding.location = surface
            finding.detail = {**finding.detail, "surface": surface}
            report.add_finding(finding)

    @staticmethod
    def _surface_advertised(report: ScanReport, surface: str) -> bool:
        capability = "resources" if surface == "resource_templates" else surface
        return capability in report.capabilities

    @classmethod
    def _surface_supported(cls, report: ScanReport, surface: str) -> bool:
        return not report.capabilities or cls._surface_advertised(report, surface)

    @staticmethod
    def _mark_incomplete(report: ScanReport, reason: str) -> None:
        report.incomplete = True
        if not report.incomplete_reason:
            report.incomplete_reason = reason[:200]

    @staticmethod
    def _apply_initialize_result(report: ScanReport, result: object) -> None:
        protocol = getattr(result, "protocolVersion", "")
        report.protocol_version = protocol if isinstance(protocol, str) else ""
        server = getattr(result, "serverInfo", None) or getattr(result, "serverVersion", None)
        version = getattr(server, "version", server)
        report.server_version = version if isinstance(version, str) else ""
        instructions = getattr(result, "instructions", "")
        report.server_instructions = instructions if isinstance(instructions, str) else ""
        capabilities = getattr(result, "capabilities", None)
        if isinstance(capabilities, dict):
            report.capabilities = capabilities
        elif capabilities is not None and callable(getattr(capabilities, "model_dump", None)):
            dumped = capabilities.model_dump()
            if isinstance(dumped, dict):
                report.capabilities = dumped

    @staticmethod
    def _apply_discovery_result(report: ScanReport, result: object) -> None:
        report.protocol_version = "2026-07-28"
        server = getattr(result, "serverInfo", None)
        version = getattr(server, "version", "")
        report.server_version = version if isinstance(version, str) else ""
        instructions = getattr(result, "instructions", "")
        report.server_instructions = instructions if isinstance(instructions, str) else ""
        capabilities = getattr(result, "capabilities", None)
        model_dump = getattr(capabilities, "model_dump", None)
        if callable(model_dump):
            dumped = model_dump()
            if isinstance(dumped, dict):
                report.capabilities = dumped

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_tool_info(tool: object) -> ToolInfo:
        name = getattr(tool, "name", "")
        if not isinstance(name, str) or not name:
            raise ValueError("tool name is missing")
        return ToolInfo(
            name=name,
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
