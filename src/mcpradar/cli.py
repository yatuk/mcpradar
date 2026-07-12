"""MCPRadar CLI - Typer application and command definitions."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC
from pathlib import Path
from typing import Any

import typer

from mcpradar import __version__
from mcpradar.storage.store import Store

app = typer.Typer(
    name="mcpradar",
    help="MCP server security scanner - tool poisoning and vulnerability detection",
    no_args_is_help=True,
)


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"mcpradar v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(  # noqa: B008
        False,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version information",
    ),
) -> None:
    pass


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


@app.command()
def scan(
    target: str = typer.Argument(
        help="MCP server URL (http://host:port), SSE URL (sse://host:port), "
        "or stdio command ('uvx my-mcp-server --port 0')"
    ),
    transport: str = typer.Option(  # noqa: B008
        "http",
        "--transport",
        "-t",
        help="Transport type: http, sse, stdio",
    ),
    output: Path | None = typer.Option(  # noqa: B008
        None, "--output", "-o", help="Write results to JSON file"
    ),
    severity: str = typer.Option(  # noqa: B008
        "medium",
        "--severity",
        "-s",
        help="Minimum severity threshold (low/medium/high/critical)",
    ),
    json_only: bool = typer.Option(  # noqa: B008
        False,
        "--json",
        hidden=True,
        help="Deprecated: use --format json instead",
    ),
    output_format: str = typer.Option(  # noqa: B008
        "rich",
        "--format",
        "-f",
        help="Output format: rich, json, sarif, cef",
    ),
    no_save: bool = typer.Option(  # noqa: B008
        False, "--no-save", help="Do not save snapshot to database"
    ),
    sandbox: bool = typer.Option(  # noqa: B008
        False,
        "--sandbox",
        help="Isolate the scan: run stdio servers in a disposable "
        "Docker/Podman container (egress locked, ephemeral FS) and "
        "validate probe arguments",
    ),
    sandbox_image: str | None = typer.Option(  # noqa: B008
        None,
        "--sandbox-image",
        help="Container image for --sandbox (default: auto-picked from the "
        "launch command: python:3.12-slim or node:22-slim)",
    ),
    sandbox_network: str = typer.Option(  # noqa: B008
        "none",
        "--sandbox-network",
        help="Container network for --sandbox: 'none' (egress lock, default) "
        "or 'bridge' (needed for npx/uvx package download)",
    ),
) -> None:
    """Scan an MCP server for security issues and save to SQLite."""
    import warnings

    from mcpradar.output.console import console
    from mcpradar.scanner.engine import Scanner
    from mcpradar.scanner.report import Severity

    if json_only:
        warnings.warn(
            "--json is deprecated, use --format json instead",
            DeprecationWarning,
            stacklevel=2,
        )
        output_format = "json"

    valid_transports = {"http", "sse", "stdio"}
    if transport not in valid_transports:
        console.print(f"[red]Invalid transport: {transport}. Valid: {valid_transports}[/]")
        raise typer.Exit(code=1)

    sev = Severity.from_str(severity)

    # When --sandbox is enabled, wire SandboxValidator into the prober
    prober = None
    if sandbox:
        from mcpradar.probe.prober import ReadOnlyProber
        from mcpradar.probe.sandbox import SandboxValidator

        prober = ReadOnlyProber(sandbox_validator=SandboxValidator())

    # --sandbox + stdio: launch the server inside a disposable container
    launch_command = None
    if sandbox and transport == "stdio":
        from mcpradar.sandbox import (
            ContainerPolicy,
            SandboxUnavailableError,
            network_warning,
            wrap_stdio_command,
        )

        if sandbox_network not in {"none", "bridge"}:
            console.print(
                f"[red]Invalid --sandbox-network: {sandbox_network}. Valid: none, bridge[/]"
            )
            raise typer.Exit(code=1)
        policy = ContainerPolicy(image=sandbox_image, network=sandbox_network)
        try:
            launch_command = wrap_stdio_command(target, policy)
        except SandboxUnavailableError as e:
            console.print(f"[red]{e}[/]")
            raise typer.Exit(code=2) from None
        warning = network_warning(target, policy)
        if warning:
            console.print(f"[yellow]{warning}[/]")
        console.print("[dim]Sandbox: server runs in a disposable container[/]")

    scanner = Scanner(
        target=target,
        transport=transport,
        min_severity=sev,
        prober=prober,
        probe_safe_only=True,
        launch_command=launch_command,
    )

    with console.status(f"[bold blue]{target}[/] scanning..."):
        report = asyncio.run(scanner.run())

    if json_only or output_format == "json":
        console.print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    elif output_format == "sarif":
        from mcpradar.output.sarif import to_sarif

        sarif_data = to_sarif(report)
        console.print(json.dumps(sarif_data, indent=2, ensure_ascii=False))
    elif output_format == "cef":
        from mcpradar.output.cef import to_cef

        cef_output = to_cef(report)
        if cef_output:
            console.print(cef_output)
    else:
        console.print_report(report)

    # Auto-save to DB
    if not no_save:
        store = Store()
        store.save(report)
        count = store.scan_count(target)
        store.close()
        console.print(f"\n[dim]Saved to DB: {report.id} (#{count} scan for server)[/]")

    if output:
        _save_output(report, output, output_format)


# ---------------------------------------------------------------------------
# scan-source
# ---------------------------------------------------------------------------


@app.command(name="scan-source")
def scan_source(
    path: str = typer.Argument(  # noqa: B008
        help="Path to an MCP server .py file or a directory of source to analyze"
    ),
    severity: str = typer.Option(  # noqa: B008
        "low", "--severity", "-s", help="Minimum severity: low/medium/high/critical"
    ),
    output_format: str = typer.Option(  # noqa: B008
        "rich", "--format", "-f", help="Output format: rich, json, sarif"
    ),
    output: Path | None = typer.Option(  # noqa: B008
        None, "--output", "-o", help="Write results to a file"
    ),
) -> None:
    """Statically analyze MCP server SOURCE CODE without running it.

    Detects SSRF, unsafe deserialization, command/SQL injection, and
    Description-Code Inconsistency (a read-only tool whose handler writes to
    disk or executes commands) — issues invisible to schema-level scanning.
    """
    from mcpradar.output.console import console
    from mcpradar.scanner.report import ScanReport, Severity
    from mcpradar.source import analyze_path

    src = Path(path)
    if not src.exists():
        console.print(f"[red]Path not found: {path}[/]")
        raise typer.Exit(code=1)

    sev = Severity.from_str(severity)
    with console.status(f"[bold blue]{path}[/] analyzing source..."):
        result = analyze_path(src)

    report = ScanReport(target=str(src), transport="source")
    for f in result.findings:
        if f.severity >= sev:
            report.add_finding(f)
    report.summary["total_tools"] = 0

    if output_format == "json":
        console.print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    elif output_format == "sarif":
        from mcpradar.output.sarif import to_sarif

        console.print(json.dumps(to_sarif(report), indent=2, ensure_ascii=False))
    else:
        console.print(
            f"[bold]{result.files_scanned}[/] source file(s) analyzed, "
            f"[bold]{len(report.findings)}[/] finding(s)\n"
        )
        console.print_report(report)

    if output:
        _save_output(report, output, output_format)


# ---------------------------------------------------------------------------
# scan-config
# ---------------------------------------------------------------------------


@app.command(name="scan-config")
def scan_config(
    path: str = typer.Argument(  # noqa: B008
        help="Path to an MCP/agent config file or a project directory to scan"
    ),
    severity: str = typer.Option(  # noqa: B008
        "low", "--severity", "-s", help="Minimum severity: low/medium/high/critical"
    ),
    output_format: str = typer.Option(  # noqa: B008
        "rich", "--format", "-f", help="Output format: rich, json, sarif"
    ),
    output: Path | None = typer.Option(  # noqa: B008
        None, "--output", "-o", help="Write results to a file"
    ),
) -> None:
    """Scan MCP / agent config files for poisoning.

    Inspects the launch commands, hook commands, and permission grants in
    config files (claude_desktop_config.json, .mcp.json, .cursor/mcp.json,
    .claude/settings.json, …) for download-to-shell RCE, credential
    exfiltration, reverse shells, and over-broad permissions (M001-M007).
    """
    from mcpradar.config_scan import scan_config_path
    from mcpradar.output.console import console
    from mcpradar.scanner.report import ScanReport, Severity

    src = Path(path)
    if not src.exists():
        console.print(f"[red]Path not found: {path}[/]")
        raise typer.Exit(code=1)

    sev = Severity.from_str(severity)
    with console.status(f"[bold blue]{path}[/] scanning config..."):
        result = scan_config_path(src)

    report = ScanReport(target=str(src), transport="config")
    for f in result.findings:
        if f.severity >= sev:
            report.add_finding(f)

    if output_format == "json":
        console.print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    elif output_format == "sarif":
        from mcpradar.output.sarif import to_sarif

        console.print(json.dumps(to_sarif(report), indent=2, ensure_ascii=False))
    else:
        console.print(
            f"[bold]{result.files_scanned}[/] config file(s) scanned, "
            f"[bold]{len(report.findings)}[/] finding(s)\n"
        )
        console.print_report(report)

    if output:
        _save_output(report, output, output_format)


# ---------------------------------------------------------------------------
# probe
# ---------------------------------------------------------------------------


@app.command()
def probe(
    target: str = typer.Argument(help="MCP server address (URL or stdio command)"),
    transport: str = typer.Option(  # noqa: B008
        "http", "--transport", "-t", help="Transport protocol: http, sse, stdio"
    ),
    safe_only: bool = typer.Option(  # noqa: B008
        True, "--safe-only/--all", help="Only probe read-only tools (safe)"
    ),
    max_probes: int = typer.Option(  # noqa: B008
        20, "--max", "-m", help="Maximum number of tools to probe"
    ),
    timeout: float = typer.Option(  # noqa: B008
        5.0, "--timeout", help="Timeout per tool (seconds)"
    ),
    json_only: bool = typer.Option(  # noqa: B008
        False, "--json", help="JSON output only"
    ),
    min_severity: str = typer.Option(  # noqa: B008
        "low", "--severity", "-s", help="Minimum severity level"
    ),
    sandbox: bool = typer.Option(  # noqa: B008
        False, "--sandbox", help="Probe with sandbox argument validation"
    ),
) -> None:
    """Probe MCP server tools by executing them safely.

    Sends minimal safe input to read-only tools,
    scans responses for URLs, scripts, secrets, and prompt injection.

    --sandbox: Validates arguments via SandboxValidator and excludes
    write-capable tools from probing.
    """
    import asyncio

    from mcpradar.output.console import console
    from mcpradar.probe.prober import ReadOnlyProber
    from mcpradar.probe.sandbox import SandboxValidator
    from mcpradar.scanner.engine import Scanner
    from mcpradar.scanner.report import Severity

    sandbox_validator = SandboxValidator() if sandbox else None
    prober_obj = ReadOnlyProber(sandbox_validator=sandbox_validator)
    prober_obj.MAX_PROBE_COUNT = max_probes
    prober_obj.PROBE_TIMEOUT = timeout

    scanner = Scanner(
        target=target,
        transport=transport,
        min_severity=Severity(min_severity),
        prober=prober_obj,
        probe_safe_only=safe_only,
    )

    with console.status(f"[bold blue]{target}[/] probing..."):
        report = asyncio.run(scanner.run())

    if json_only:
        console.print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        _print_probe_results(console, report)


def _print_probe_results(console: Any, report: Any) -> None:
    """Rich formatted probe results output."""
    from rich.table import Table

    probed = report.probe_results

    console.print(f"\n[bold]Probe Results: {report.target}[/]")
    console.print(f"  Transport: {report.transport}")
    console.print(f"  Tool count: {len(report.tools)}, Probed: {len(probed)}")

    if not probed:
        console.print("  [yellow]No tools probed (no safe tools found or all are write-only)[/]")
        return

    success_count = sum(1 for p in probed if p.success)
    fail_count = len(probed) - success_count
    console.print(f"  Successful: [green]{success_count}[/], Failed: [red]{fail_count}[/]")

    table = Table("Tool", "Time (ms)", "Success", "URL", "Script", "Secret", "Injection", "Preview")
    for p in probed:
        table.add_row(
            p.tool_name,
            f"{p.response_time_ms:.0f}",
            "✅" if p.success else f"❌ {p.error_message[:30]}",
            "🔗" if p.contains_urls else "",
            "⚠️" if p.contains_scripts else "",
            "🔑" if p.contains_secrets else "",
            "💉" if p.contains_prompt_injection else "",
            p.response_preview[:60] + ("..." if len(p.response_preview) > 60 else ""),
        )
    console.print(table)

    # Summary of detected issues
    issues = []
    if any(p.contains_urls for p in probed):
        issues.append(
            f"[yellow]{sum(1 for p in probed if p.contains_urls)} response(s) containing URLs[/]"
        )
    if any(p.contains_scripts for p in probed):
        issues.append(
            f"[red]{sum(1 for p in probed if p.contains_scripts)} response(s) containing scripts[/]"
        )
    if any(p.contains_secrets for p in probed):
        issues.append(
            f"[red]{sum(1 for p in probed if p.contains_secrets)} response(s) containing secrets[/]"
        )
    if any(p.contains_prompt_injection for p in probed):
        pi_count = sum(1 for p in probed if p.contains_prompt_injection)
        issues.append(f"[red]{pi_count} prompt injection response(s)[/]")
    if issues:
        console.print("\n[bold]Detected Risks:[/] " + ", ".join(issues))


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------


@app.command()
def diff(
    server: str | None = typer.Argument(
        default=None,
        help="Server URL to compare (leave empty to list all servers)",
    ),
    snapshot_a: str | None = typer.Option(  # noqa: B008
        None, "--snapshot-a", "-a", help="First snapshot ID (manual comparison)"
    ),
    snapshot_b: str | None = typer.Option(  # noqa: B008
        None, "--snapshot-b", "-b", help="Second snapshot ID (manual comparison)"
    ),
    since: str | None = typer.Option(  # noqa: B008
        None, "--since", help="Show changes since this timestamp or scan ID"
    ),
    output: Path | None = typer.Option(  # noqa: B008
        None, "--output", "-o", help="Write diff result to JSON file"
    ),
    json_only: bool = typer.Option(  # noqa: B008
        False, "--json", help="JSON output only"
    ),
) -> None:
    """Compare schema changes between two scan snapshots.

    Examples:
        mcpradar diff                    # list all servers
        mcpradar diff http://x           # compare latest 2 scans
        mcpradar diff http://x --since 2026-01-01
        mcpradar diff -a abc -b def      # specific two snapshots
    """
    from mcpradar.diff.differ import Differ
    from mcpradar.output.console import console

    store = Store()

    # Manual snapshot pair
    if snapshot_a and snapshot_b:
        report_a = store.load(snapshot_a)
        report_b = store.load(snapshot_b)
        differ = Differ()
        delta = differ.compare(report_a, report_b)
        _output_diff(delta, json_only, output)
        store.close()
        return

    # List targets
    if server is None:
        targets = store.list_targets()
        if not targets:
            console.print("[dim]No scans yet. Run 'mcpradar scan <url>' first.[/]")
        else:
            console.print("[bold]Scanned servers:[/]")
            for t in targets:
                count = store.scan_count(t)
                last = store.latest_scans(t, 1)
                last_id = last[0][:12] if last else "-"
                console.print(f"  [cyan]{t}[/] - {count} scans, last: {last_id}")
        store.close()
        return

    # Server-level diff: latest 2
    try:
        ids = store.latest_scans(server, 2)
    except Exception:
        ids = []

    if since:
        ids = store.scan_since(server, since)
        if not ids:
            console.print(f"[dim]No scans after '{since}' for {server}.[/]")
            store.close()
            return
        if len(ids) >= 2:
            ids = [ids[0], ids[-1]]  # newest vs oldest in range
            console.print(
                f"[dim]{len(store.scan_since(server, since))} scans, comparing newest vs oldest[/]"
            )

    if len(ids) < 2:
        console.print(
            f"[dim]At least 2 scans needed for {server} (currently {len(ids)}). "
            "Run 'mcpradar scan' multiple times first.[/]"
        )
        store.close()
        return

    report_a = store.load(ids[0])
    report_b = store.load(ids[1])
    differ = Differ()
    delta = differ.compare(report_a, report_b)
    _output_diff(delta, json_only, output)
    store.close()


def _save_output(report: Any, output: Path, fmt: str) -> None:
    from mcpradar.output.console import console

    if fmt == "sarif":
        from mcpradar.output.sarif import to_sarif

        data = to_sarif(report)
        out_path = output if output.suffix == ".sarif" else output.with_suffix(".sarif")
        out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    elif fmt == "cef":
        from mcpradar.output.cef import to_cef

        cef_text = to_cef(report)
        out_path = output if output.suffix == ".cef" else output.with_suffix(".cef")
        out_path.write_text(cef_text, encoding="utf-8")
    else:
        out_path = output if output.suffix == ".json" else output.with_suffix(".json")
        if hasattr(report, "to_dict"):
            out_path.write_text(
                json.dumps(report.to_dict(), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        else:
            out_path.write_text(
                json.dumps(report, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
    console.print(f"[dim]Output: {out_path}[/]")


def _output_diff(delta: Any, json_only: bool, output: Path | None) -> None:
    from mcpradar.output.console import console

    if json_only:
        console.print(json.dumps(delta.to_dict(), indent=2, ensure_ascii=False))
    else:
        console.print_diff(delta)

    if output:
        out = output if output.suffix == ".json" else output.with_suffix(".json")
        out.write_text(json.dumps(delta.to_dict(), indent=2, ensure_ascii=False))
        console.print(f"\n[dim]Diff JSON: {out}[/]")


# ---------------------------------------------------------------------------
# list / show / export / purge - snapshot browser
# ---------------------------------------------------------------------------


@app.command(name="list")
def list_snapshots(
    target: str | None = typer.Argument(
        default=None,
        help="Server URL (leave empty to list all servers)",
    ),
    limit: int = typer.Option(  # noqa: B008
        20, "--limit", "-n", help="Maximum number of snapshots to show"
    ),
) -> None:
    """List all snapshots for a server."""
    from rich.table import Table

    from mcpradar.output.console import console

    store = Store()

    if target is None:
        targets = store.list_targets()
        if not targets:
            console.print("[dim]No scans yet.[/]")
        else:
            table = Table(title="Scanned Servers", show_header=True)
            table.add_column("Server")
            table.add_column("Scan Count", justify="right")
            table.add_column("Last Scan")
            for t in targets:
                count = store.scan_count(t)
                last = store.latest_scans(t, 1)
                last_id = last[0][:12] if last else "-"
                table.add_row(t, str(count), last_id)
            console.print(table)
        store.close()
        return

    ids = store.latest_scans(target, limit)
    if not ids:
        console.print(f"[dim]No snapshots found for {target}.[/]")
        store.close()
        return

    table = Table(title=f"Snapshots: {target}", show_header=True)
    table.add_column("ID", width=14)
    table.add_column("Date", width=22)
    table.add_column("Transport", width=8)
    table.add_column("Tools", justify="right")
    table.add_column("L", justify="right")
    table.add_column("M", justify="right")
    table.add_column("H", justify="right")
    table.add_column("C", justify="right")

    for sid in ids:
        try:
            r = store.load(sid)
            s = r.summary
            table.add_row(
                r.id[:12],
                r.scanned_at[:19],
                r.transport,
                str(s.get("total_tools", 0)),
                str(s.get("low", 0)),
                str(s.get("medium", 0)),
                str(s.get("high", 0)),
                str(s.get("critical", 0)),
            )
        except Exception:
            table.add_row(sid[:12], "?", "", "", "", "", "", "")

    store.close()
    console.print(table)


@app.command()
def show(
    scan_id: str = typer.Argument(help="Snapshot ID to show"),
) -> None:
    """Show detailed report for a single snapshot."""
    from mcpradar.output.console import console

    store = Store()
    try:
        report = store.load(scan_id)
        console.print_report(report)
    except LookupError:
        console.print(f"[red]Snapshot not found: {scan_id}[/]")
    finally:
        store.close()


@app.command()
def export(
    scan_id: str = typer.Argument(help="Snapshot ID to export"),
    output_format: str = typer.Option(  # noqa: B008
        "json", "--format", "-f", help="Format: json, sarif, csv, cef"
    ),
    output: Path = typer.Option(  # noqa: B008
        ..., "--output", "-o", help="Output file"
    ),
) -> None:
    """Export a snapshot in JSON, SARIF, or CSV format."""
    from mcpradar.output.console import console

    store = Store()
    try:
        report = store.load(scan_id)
        if output_format == "sarif":
            from mcpradar.output.sarif import to_sarif

            data = to_sarif(report)
            p = output if output.suffix == ".sarif" else output.with_suffix(".sarif")
            p.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        elif output_format == "csv":
            p = output if output.suffix == ".csv" else output.with_suffix(".csv")
            _export_csv(report, p)
        elif output_format == "cef":
            from mcpradar.output.cef import to_cef

            cef_text = to_cef(report)
            p = output if output.suffix == ".cef" else output.with_suffix(".cef")
            p.write_text(cef_text, encoding="utf-8")
        else:
            p = output if output.suffix == ".json" else output.with_suffix(".json")
            store.export_json(report, p)
        console.print(f"[green]Export: {p}[/]")
    except LookupError:
        console.print(f"[red]Snapshot not found: {scan_id}[/]")
    finally:
        store.close()


def _export_csv(report: Any, path: Path) -> None:
    import csv

    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["rule_id", "severity", "target", "title", "description", "evidence"])
        for f_ in report.findings:
            w.writerow(
                [
                    f_.rule_id,
                    f_.severity.value,
                    f_.target,
                    f_.title,
                    f_.description,
                    f_.evidence,
                ]
            )


@app.command()
def purge(
    older_than: str | None = typer.Option(  # noqa: B008
        None, "--older-than", help="Delete snapshots older than this (e.g. 30d, 7d, 2026-01-01)"
    ),
    keep_last: int | None = typer.Option(  # noqa: B008
        None, "--keep-last", help="Keep only the last N snapshots, delete older ones"
    ),
    target: str | None = typer.Option(  # noqa: B008
        None, "--target", help="Clean up only for this server"
    ),
    dry_run: bool = typer.Option(  # noqa: B008
        False, "--dry-run", help="Preview deletions without executing"
    ),
) -> None:
    """Purge old snapshots."""
    from mcpradar.output.console import console

    store = Store()

    if older_than:
        cutoff = _parse_duration(older_than)
        ids = store.scans_older_than(cutoff, target)
    elif keep_last:
        ids = store.scans_beyond_keep(target, keep_last)
    else:
        console.print("[dim]You must specify --older-than or --keep-last.[/]")
        store.close()
        return

    if not ids:
        console.print("[dim]No snapshots to delete.[/]")
        store.close()
        return

    console.print(f"[yellow]{len(ids)} snapshot(s) to delete:[/]")
    for sid in ids[:10]:
        console.print(f"  [dim]- {sid}[/]")
    if len(ids) > 10:
        console.print(f"  [dim]... and {len(ids) - 10} more[/]")

    if not dry_run:
        store.delete_scans(ids)
        console.print(f"[green]{len(ids)} snapshot(s) deleted.[/]")
    else:
        console.print("[dim](--dry-run: no action taken)[/]")

    store.close()


def _parse_duration(s: str) -> str:
    """Parse '30d', '7d', '24h' into ISO timestamp cutoff."""
    import re
    from datetime import UTC, datetime, timedelta

    m = re.match(r"(\d+)\s*(d|h|w)", s.lower())
    if m:
        n = int(m.group(1))
        unit = m.group(2)
        if unit == "d":
            delta = timedelta(days=n)
        elif unit == "h":
            delta = timedelta(hours=n)
        else:
            delta = timedelta(weeks=n)
        return (datetime.now(UTC) - delta).isoformat()
    return s  # assume it's already ISO format


# ---------------------------------------------------------------------------
# sbom
# ---------------------------------------------------------------------------


@app.command()
def sbom(
    output_path: Path | None = typer.Option(  # noqa: B008
        None, "--output", "-o", help="Output file path (prints to stdout if omitted)"
    ),
) -> None:
    """Generate CycloneDX 1.5 SBOM in JSON format."""
    from mcpradar.output.console import console
    from mcpradar.output.sbom import export_sbom

    path_str = str(output_path) if output_path else None
    result = export_sbom(path_str)
    if not output_path:
        console.print(result)
    else:
        console.print(f"[green]SBOM exported to {output_path}[/]")


# ---------------------------------------------------------------------------
# deps - dependency vulnerability scan (SBOM -> OSV)
# ---------------------------------------------------------------------------


@app.command()
def deps(
    path: str = typer.Argument(  # noqa: B008
        help="Path to an MCP server's source (dir or manifest) to check dependencies for"
    ),
    severity: str = typer.Option(  # noqa: B008
        "low", "--severity", "-s", help="Minimum severity: low/medium/high/critical"
    ),
    output_format: str = typer.Option(  # noqa: B008
        "rich", "--format", "-f", help="Output format: rich, json, sarif"
    ),
    output: Path | None = typer.Option(  # noqa: B008
        None, "--output", "-o", help="Write results to a file"
    ),
    list_only: bool = typer.Option(  # noqa: B008
        False, "--list", help="Only list resolved dependencies; skip the OSV query"
    ),
) -> None:
    """Resolve a server's dependencies and check them against OSV.dev.

    Parses package.json / package-lock.json / requirements.txt / pyproject.toml
    / uv.lock, then batch-queries the OSV vulnerability database (GitHub
    Advisory, PyPA, npm) and reports each known-vulnerable dependency (D001).
    """
    from mcpradar.output.console import console
    from mcpradar.scanner.report import ScanReport, Severity
    from mcpradar.supply import extract_dependencies, scan_dependencies

    src = Path(path)
    if not src.exists():
        console.print(f"[red]Path not found: {path}[/]")
        raise typer.Exit(code=1)

    if list_only:
        found = extract_dependencies(src)
        console.print(f"[bold]{len(found)}[/] dependencies resolved:")
        for d in found:
            console.print(f"  [dim]{d.ecosystem}[/] {d.name}@{d.version}")
        return

    sev = Severity.from_str(severity)
    with console.status(f"[bold blue]{path}[/] checking dependencies against OSV..."):
        resolved, all_findings = scan_dependencies(src)

    report = ScanReport(target=str(src), transport="deps")
    for f in all_findings:
        if f.severity >= sev:
            report.add_finding(f)

    vuln_pkgs = {f.detail.get("package") for f in report.findings}
    if output_format == "json":
        console.print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    elif output_format == "sarif":
        from mcpradar.output.sarif import to_sarif

        console.print(json.dumps(to_sarif(report), indent=2, ensure_ascii=False))
    else:
        console.print(
            f"[bold]{len(resolved)}[/] dependencies scanned, "
            f"[bold]{len(report.findings)}[/] advisories across "
            f"[bold]{len(vuln_pkgs)}[/] vulnerable package(s)\n"
        )
        console.print_report(report)

    if output:
        _save_output(report, output, output_format)


# ---------------------------------------------------------------------------
# scan-all - scan all servers from config file
# ---------------------------------------------------------------------------


@app.command()
def scan_all(
    config_path: Path | None = typer.Option(  # noqa: B008
        None, "--config", help="Configuration file path (default: mcpradar.toml)"
    ),
    severity: str = typer.Option(  # noqa: B008
        "medium",
        "--severity",
        "-s",
        help="Minimum severity threshold (low/medium/high/critical)",
    ),
    json_only: bool = typer.Option(  # noqa: B008
        False, "--json", help="JSON output only"
    ),
    parallel: bool = typer.Option(  # noqa: B008
        False, "--parallel", help="Scan servers in parallel"
    ),
    max_concurrency: int = typer.Option(  # noqa: B008
        5, "--max-concurrency", "-c", help="Maximum concurrent scan count"
    ),
) -> None:
    """Scan all servers from mcpradar.toml sequentially."""
    from mcpradar.config import MCPRadarConfig
    from mcpradar.output.console import console

    cfg = MCPRadarConfig.from_file(config_path)
    if cfg is None or not cfg.servers:
        console.print(
            "[red]Configuration not found. Run 'mcpradar init' first or create mcpradar.toml.[/]"
        )
        raise typer.Exit(code=1)

    console.print(f"[bold]mcpradar scan-all[/] - {len(cfg.servers)} server(s) to scan\n")
    if not parallel:
        for srv in cfg.servers:
            console.print(f"\n[bold cyan]>>> {srv.name or srv.url}[/]")
            try:
                scan(
                    target=srv.url,
                    transport=srv.transport,
                    severity=severity,
                    json_only=json_only,
                    no_save=False,
                )
            except Exception as exc:
                console.print(f"[red]Error: {srv.url} - {exc}[/]")
    else:
        from mcpradar.scanner.engine import ParallelScanner
        from mcpradar.scanner.report import ScanReport, Severity

        sev = Severity.from_str(severity)
        servers = [(srv.url, srv.transport or "http") for srv in cfg.servers]
        ps = ParallelScanner(max_concurrency=max_concurrency)
        console.print(
            f"[bold]Scanning: {len(servers)} server(s) "
            f"(parallel, max {max_concurrency} concurrent)...[/]"
        )

        async def _run_parallel() -> None:
            results = await ps.scan_all(servers, min_severity=sev)
            for i, result in enumerate(results):
                srv = cfg.servers[i]
                if isinstance(result, Exception):
                    console.print(f"[red]ERROR {srv.url}: {result}[/]")
                elif isinstance(result, ScanReport):
                    console.print(
                        f"[green]OK {srv.url}: "
                        f"{len(result.tools)} tools, "
                        f"{len(result.findings)} findings[/]"
                    )
                    store = Store()
                    store.save(result)
                    store.close()
                    if json_only:
                        console.print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))

        asyncio.run(_run_parallel())


# ---------------------------------------------------------------------------
# analyze-context
# ---------------------------------------------------------------------------


@app.command()
def analyze_context(
    config_path: Path | None = typer.Option(  # noqa: B008
        None, "--config", help="Configuration file path"
    ),
    json_only: bool = typer.Option(  # noqa: B008
        False, "--json", help="JSON output only"
    ),
    deep: bool = typer.Option(  # noqa: B008
        False, "--deep", help="Deep graph analysis (C006, C007 rules)"
    ),
    graph_output: Path | None = typer.Option(  # noqa: B008
        None, "--graph", "-g", help="GraphViz DOT output file"
    ),
) -> None:
    """Analyze the security of multiple MCP servers together.

    Detects cross-server contamination risks:
    tool name collisions, shadowing, data exfiltration chains.
    """
    import asyncio

    from mcpradar.analyzer.context import ContextAnalyzer
    from mcpradar.config import MCPRadarConfig
    from mcpradar.output.console import console
    from mcpradar.scanner.engine import Scanner
    from mcpradar.scanner.report import Severity

    cfg = MCPRadarConfig.from_file(config_path)
    if cfg is None or not cfg.servers:
        console.print("[red]Configuration not found or servers list is empty.[/]")
        raise typer.Exit(code=1)

    servers = cfg.servers[:10]  # Max 10
    console.print(f"[bold]mcpradar analyze-context[/] - analyzing {len(servers)} server(s)\n")

    scans: list[Any] = []
    for srv in servers:
        with console.status(f"[dim]{srv.name or srv.url}[/] scanning..."):
            try:
                scanner = Scanner(
                    target=srv.url,
                    transport=srv.transport,
                    min_severity=Severity("low"),
                )
                report = asyncio.run(scanner.run())
                scans.append(report)
                console.print(f"  [green]{srv.name or srv.url}[/] - {len(report.tools)} tools")
            except Exception as exc:
                console.print(f"  [red]{srv.name or srv.url}[/] - error: {exc}")

    if len(scans) < 2:
        console.print("[red]At least 2 servers must be scannable.[/]")
        raise typer.Exit(code=1)

    analyzer = ContextAnalyzer(scans, deep=deep)
    ctx_report = analyzer.analyze()

    if graph_output and ctx_report.attack_graph_dot:
        graph_output.write_text(ctx_report.attack_graph_dot, encoding="utf-8")
        console.print(f"[green]GraphViz DOT saved: {graph_output}[/]")
    elif graph_output and not ctx_report.attack_graph_dot:
        console.print("[yellow]--deep flag is required for graph output.[/]")

    if json_only:
        console.print(json.dumps(ctx_report.to_dict(), indent=2, ensure_ascii=False))
    else:
        _print_context_report(ctx_report, console)


def _print_context_report(ctx_report: Any, console: Any) -> None:
    """Rich output for context analysis."""
    from rich.table import Table

    console.print()
    console.rule("[bold]Cross-Server Context Analysis[/]")
    console.print(
        f"[dim]{ctx_report.server_count} servers, "
        f"{ctx_report.tool_count} tools, "
        f"{len(ctx_report.findings)} cross-server findings[/]\n"
    )

    if not ctx_report.findings:
        console.print("[green]No cross-server risks detected.[/]")
        return

    table = Table(title="Cross-Server Findings", show_header=True, show_lines=True)
    table.add_column("Rule", width=6)
    table.add_column("Severity", width=8)
    table.add_column("Servers", width=24)
    table.add_column("Description")

    for f in ctx_report.findings:
        color = {
            "critical": "bold red",
            "high": "orange1",
            "medium": "yellow",
            "low": "dim cyan",
        }.get(f.severity.value, "")
        table.add_row(
            f"[{color}]{f.rule_id}[/]",
            f"[{color}]{f.severity.value.upper()}[/]",
            ", ".join(f.servers[:3]),
            f.description,
        )

    console.print(table)

    # Risk graph
    if ctx_report.risk_graph:
        console.print("\n[bold]Risk Graph:[/]")
        for srv, deps in ctx_report.risk_graph.items():
            console.print(f"  [cyan]{srv}[/] ←→ {', '.join(deps)}")

    # Risk score
    if ctx_report.risk_score > 0:
        if ctx_report.risk_score < 30:
            color = "green"
        elif ctx_report.risk_score < 60:
            color = "yellow"
        else:
            color = "red"
        console.print(f"\n[bold]Risk Score:[/] [{color}]{ctx_report.risk_score}/100[/]")

    console.print()


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------


@app.command()
def stats(
    target: str | None = typer.Argument(
        None, help="Target for server-specific stats (omit for global)"
    ),
    days: int = typer.Option(  # noqa: B008
        30, "--days", "-d", help="Days for trend analysis"
    ),
    json_only: bool = typer.Option(  # noqa: B008
        False, "--json", help="Output as JSON"
    ),
) -> None:
    """Display security statistics and trend analysis."""
    from mcpradar.audit.stats import StatsEngine
    from mcpradar.output.console import console

    engine = StatsEngine()

    if target:
        # Server-specific stats + trend
        server_stats = engine.server_stats(target)

        if json_only:
            output = server_stats.to_dict()
            trend = engine.trend_analysis(target, days=days)
            output["trend"] = trend.to_dict()
            console.print(json.dumps(output, indent=2, ensure_ascii=False))
            return

        if server_stats.total_scans == 0:
            console.print(f"[dim]No data for target: {target}[/]")
            return

        # Summary panel
        from rich.panel import Panel

        summary_lines = [
            f"Target: [bold]{server_stats.target}[/]",
            f"Total scans: [cyan]{server_stats.total_scans}[/]",
            f"First scan: {server_stats.first_scan[:19] if server_stats.first_scan else 'N/A'}",
            f"Last scan: {server_stats.last_scan[:19] if server_stats.last_scan else 'N/A'}",
            f"Total findings: [yellow]{server_stats.total_findings}[/]",
            "",
            "Findings by severity:",
        ]
        for sev in ("critical", "high", "medium", "low"):
            count = server_stats.findings_by_severity.get(sev, 0)
            sev_color = {
                "critical": "bold red",
                "high": "orange1",
                "medium": "yellow",
                "low": "dim cyan",
            }.get(sev, "")
            bar = "█" * min(count, 50)
            summary_lines.append(f"  [{sev_color}]{sev.upper():8}[/] {count:4} {bar}")

        console.print(Panel("\n".join(summary_lines), title="Server Statistics"))

        # Top rules table
        if server_stats.top_rules:
            from rich.table import Table as RTable

            rules_table = RTable(title="Top Triggered Rules", show_header=True, header_style="bold")
            rules_table.add_column("Rule ID")
            rules_table.add_column("Count")
            for rule_id, count in server_stats.top_rules:
                rules_table.add_row(rule_id, str(count))
            console.print(rules_table)

        # Trend
        trend = engine.trend_analysis(target, days=days)
        direction_icon = {
            "improving": "[green]↓ improving[/]",
            "worsening": "[red]↑ worsening[/]",
            "stable": "[yellow]→ stable[/]",
        }.get(trend.trend_direction, "?")
        console.print(f"\nTrend ({days}d): {direction_icon}")
        if trend.daily_scans:
            scans_str = " ".join(str(d["count"]) for d in trend.daily_scans)
            console.print(f"  Scans/day: [dim]{scans_str}[/]")
        if trend.daily_findings:
            findings_str = " ".join(str(d["count"]) for d in trend.daily_findings)
            console.print(f"  Findings/day: [dim]{findings_str}[/]")

    else:
        # Global stats
        global_stats = engine.global_stats()

        if json_only:
            console.print(json.dumps(global_stats.to_dict(), indent=2, ensure_ascii=False))
            return

        if global_stats.total_targets == 0:
            console.print("[dim]No scan data available.[/]")
            return

        from rich.panel import Panel

        summary_lines = [
            f"Targets: [cyan]{global_stats.total_targets}[/]",
            f"Total scans: [cyan]{global_stats.total_scans}[/]",
            f"Total findings: [yellow]{global_stats.total_findings}[/]",
            f"Audit events: [cyan]{global_stats.audit_event_count}[/]",
            "",
            "Findings by severity:",
        ]
        for sev in ("critical", "high", "medium", "low"):
            count = global_stats.findings_by_severity.get(sev, 0)
            sev_color = {
                "critical": "bold red",
                "high": "orange1",
                "medium": "yellow",
                "low": "dim cyan",
            }.get(sev, "")
            bar = "█" * min(count, 50)
            summary_lines.append(f"  [{sev_color}]{sev.upper():8}[/] {count:4} {bar}")

        console.print(Panel("\n".join(summary_lines), title="Global Statistics"))

        # Top tables
        from rich.table import Table as RTable

        if global_stats.top_scanned_targets:
            t_table = RTable(title="Top Scanned Targets", show_header=True, header_style="bold")
            t_table.add_column("Target")
            t_table.add_column("Scans")
            for t, c in global_stats.top_scanned_targets:
                t_table.add_row(t[:50], str(c))
            console.print(t_table)

        if global_stats.top_triggered_rules:
            r_table = RTable(title="Top Triggered Rules", show_header=True, header_style="bold")
            r_table.add_column("Rule ID")
            r_table.add_column("Count")
            for rule_id, count in global_stats.top_triggered_rules:
                r_table.add_row(rule_id, str(count))
            console.print(r_table)


# rules
# ---------------------------------------------------------------------------

rules_app = typer.Typer(help="Manage detection rules", no_args_is_help=True)
app.add_typer(rules_app, name="rules")


@rules_app.command(name="list")
def rules_list() -> None:
    """List all loaded rules (built-in + plugins)."""
    from rich.table import Table

    from mcpradar.output.console import console
    from mcpradar.scanner.report import Severity
    from mcpradar.scanner.rules import RuleEngine

    engine = RuleEngine(min_severity=Severity("low"))
    table = Table(title="Loaded Rules", show_header=True)
    table.add_column("Rule ID", width=8)
    table.add_column("Title", width=36)
    table.add_column("Severity", width=10)
    table.add_column("Source", width=12)

    for r in engine.loaded_rules:
        sev = r["severity"]
        color = {
            "critical": "bold red",
            "high": "orange1",
            "medium": "yellow",
            "low": "dim cyan",
        }.get(sev, "")
        table.add_row(
            f"[{color}]{r['rule_id']}[/]",
            r["title"],
            sev.upper(),
            r["source"],
        )

    console.print(table)


@rules_app.command(name="info")
def rules_info(
    rule_id: str = typer.Argument(help="Rule ID (example: R102)"),
) -> None:
    """Show detailed info for a specific rule."""
    from mcpradar.output.console import console
    from mcpradar.scanner.report import Severity
    from mcpradar.scanner.rules import RuleEngine

    engine = RuleEngine(min_severity=Severity("low"))
    for r in engine._rules:
        if r.rule_id == rule_id.upper():
            console.print(f"[bold]{r.rule_id}[/] - {r.title}")
            console.print(f"  Severity: {r.severity.value}")
            console.print(f"  Class: {type(r).__module__}.{type(r).__name__}")
            return
    console.print(f"[red]Rule '{rule_id}' not found.[/]")


@rules_app.command(name="disable")
def rules_disable(
    rule_id: str = typer.Argument(help="Rule ID to disable"),
) -> None:
    """Disable a rule (updates mcpradar.toml)."""
    import tomllib
    from pathlib import Path

    import tomli_w

    from mcpradar.output.console import console
    from mcpradar.scanner.report import Severity
    from mcpradar.scanner.rules import RuleEngine

    engine = RuleEngine(min_severity=Severity("low"))
    rid = rule_id.upper()
    if engine.disable(rid):
        console.print(f"[yellow]Rule {rid} disabled.[/]")
        config_path = Path("mcpradar.toml")
        if config_path.exists():
            raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
            raw.setdefault("rules", {})
            raw.setdefault("disabled_rules", [])
            if rid not in raw["rules"]["disabled_rules"]:
                raw["rules"]["disabled_rules"].append(rid)
            config_path.write_text(tomli_w.dumps(raw), encoding="utf-8")
            console.print("[dim]Updated mcpradar.toml[/]")
    else:
        console.print(f"[dim]Rule {rid} not found or already disabled.[/]")


# ---------------------------------------------------------------------------
# plugin
# ---------------------------------------------------------------------------

plugin_app = typer.Typer(help="Manage community plugins", no_args_is_help=True)
app.add_typer(plugin_app, name="plugin")


@plugin_app.command(name="init")
def plugin_init(
    name: str = typer.Argument(help="Plugin name (example: my-custom-sqli)"),
    output: Path = typer.Option(  # noqa: B008
        Path("plugins"),
        "--output",
        "-o",
        help="Output directory (default: ./plugins)",
    ),
) -> None:
    """Create a new MCPRadar plugin package."""
    from mcpradar.output.console import console
    from mcpradar.plugin.scaffolder import Scaffolder

    scaffolder = Scaffolder()
    try:
        created = scaffolder.scaffold(name, output)
    except FileNotFoundError as exc:
        console.print(f"[red]Error:[/] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(f"[green]OK[/] Plugin created: [bold]{created}[/]")
    console.print(f"  cd {created}")
    console.print("  pip install -e .")
    console.print(f"  mcpradar plugin validate {created}")


@plugin_app.command(name="validate")
def plugin_validate(
    directory: Path = typer.Argument(  # noqa: B008
        help="Plugin directory (example: ./plugins/mcpradar-rule-my-custom)",
    ),
    run_tests: bool = typer.Option(  # noqa: B008
        False,
        "--run-tests",
        "-t",
        help="Also run tests with pytest",
    ),
) -> None:
    """Validate plugin structure."""
    from mcpradar.output.console import console
    from mcpradar.plugin.validator import PluginValidator

    if not directory.exists():
        console.print(f"[red]Directory not found: {directory}[/]")
        raise typer.Exit(code=1)

    validator = PluginValidator(run_tests=run_tests)
    report = validator.validate(directory)

    for result in report.results:
        if result.passed:
            console.print(f"  [green][✓][/] {result.message}")
        else:
            console.print(f"  [red][✗][/] {result.message}")
            if result.detail:
                console.print(f"    [dim]{result.detail}[/]")

    if report.tests_passed is True:
        console.print("  [green][✓][/] Tests passed")
    elif report.tests_passed is False:
        console.print("  [red][✗][/] Tests failed")

    if report.is_valid:
        console.print("\n[green]All checks passed.[/]")
    else:
        console.print("\n[red]Some checks failed.[/]")
        raise typer.Exit(code=1)


@plugin_app.command(name="list")
def plugin_list() -> None:
    """List installed community plugins."""
    from rich.table import Table

    from mcpradar.output.console import console
    from mcpradar.plugin.manager import PluginManager

    manager = PluginManager()
    plugins = manager.list_plugins()

    if not plugins:
        console.print("[dim]No community plugins installed yet.[/]")
        console.print("[dim]To install a plugin: mcpradar plugin install <package>[/]")
        return

    table = Table(title="Installed Community Plugins", show_header=True)
    table.add_column("Package", width=28)
    table.add_column("Version", width=8)
    table.add_column("Author", width=20)
    table.add_column("Rules", width=30)

    for p in plugins:
        table.add_row(
            p.name,
            p.version,
            p.author[:20] if p.author else "?",
            ", ".join(p.rule_ids),
        )

    console.print(table)


@plugin_app.command(name="install")
def plugin_install(
    package: str = typer.Argument(help="Package name (example: mcpradar-rule-sqli)"),
) -> None:
    """Install and validate a community plugin via pip."""
    from mcpradar.output.console import console
    from mcpradar.plugin.manager import PluginManager

    manager = PluginManager()
    console.print(f"[dim]Installing {package}...[/]")
    success, message = manager.install(package)

    if success:
        console.print(f"[green]OK[/] {message}")
    else:
        console.print(f"[red]Error:[/] {message}")
        raise typer.Exit(code=1)


@plugin_app.command(name="uninstall")
def plugin_uninstall(
    package: str = typer.Argument(help="Package name"),
) -> None:
    """Uninstall a community plugin."""
    from mcpradar.output.console import console
    from mcpradar.plugin.manager import PluginManager

    manager = PluginManager()
    console.print(f"[dim]Uninstalling {package}...[/]")
    success, message = manager.uninstall(package)

    if success:
        console.print(f"[green]OK[/] {message}")
    else:
        console.print(f"[red]Error:[/] {message}")
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# fingerprint
# ---------------------------------------------------------------------------

fingerprint_app = typer.Typer(help="Server fingerprint and identity tracking", no_args_is_help=True)
app.add_typer(fingerprint_app, name="fingerprint")


@fingerprint_app.command(name="create")
def fingerprint_create(
    target: str = typer.Argument(help="MCP server address"),
    transport: str = typer.Option(  # noqa: B008
        "http",
        "--transport",
        "-t",
        help="Transport protocol (http, sse, stdio)",
    ),
) -> None:
    """Create and save a server fingerprint."""
    import asyncio

    from mcpradar.fingerprint.fingerprinter import Fingerprinter
    from mcpradar.fingerprint.transport_check import TransportChecker
    from mcpradar.output.console import console
    from mcpradar.scanner.engine import Scanner
    from mcpradar.scanner.report import Severity
    from mcpradar.storage.store import Store

    # Scan the server
    sev = Severity.from_str("low")
    scanner = Scanner(target=target, transport=transport, min_severity=sev)
    with console.status(f"[bold blue]{target}[/] scanning..."):
        report = asyncio.run(scanner.run())

    # Transport check
    checker = TransportChecker()
    tls_info = checker.check(target, transport)

    # Create fingerprint
    fingerprinter = Fingerprinter()
    fp = fingerprinter.create(report, tls_info)

    # Save to database
    store = Store()
    store.save_fingerprint(fp)

    # Display
    console.print("\n[bold]Fingerprint[/]")
    console.print(f"  Server ID:      [bold cyan]{fp.server_id}[/]")
    console.print(f"  Endpoint:       {fp.endpoint}")
    console.print(f"  Transport:      {fp.transport}")
    console.print(f"  Server Version: {fp.server_version or '(unknown)'}")
    console.print(f"  Protocol:       {fp.protocol_version or '(unknown)'}")
    console.print(f"  Tool Count:     {fp.tool_count}")
    console.print(f"  Tools Hash:     [dim]{fp.tool_names_hash[:16]}...[/]")
    if tls_info and tls_info.version != "N/A":
        console.print(f"  TLS Version:    {tls_info.version}")
        if tls_info.cert_issuer:
            console.print(f"  Cert Issuer:    {tls_info.cert_issuer}")
        cert_ok = "[green]Yes[/]" if tls_info.cert_valid else "[red]No[/]"
        console.print(f"  Cert Valid:     {cert_ok}")
        ss_ok = "[yellow]Yes[/]" if tls_info.self_signed else "[green]No[/]"
        console.print(f"  Self-Signed:    {ss_ok}")
    elif tls_info and tls_info.version == "plain":
        console.print("  TLS:            [red]Plain HTTP (unencrypted)[/]")

    console.print("\n[green]Fingerprint saved.[/]")
    console.print(f"To compare: mcpradar fingerprint compare {target} -t {transport}")


@fingerprint_app.command(name="compare")
def fingerprint_compare(
    target: str = typer.Argument(help="MCP server address"),
    transport: str = typer.Option(  # noqa: B008
        "http",
        "--transport",
        "-t",
        help="Transport protocol (http, sse, stdio)",
    ),
) -> None:
    """Compare against a previous fingerprint."""
    import asyncio

    from mcpradar.fingerprint.fingerprinter import Fingerprinter
    from mcpradar.fingerprint.transport_check import TransportChecker
    from mcpradar.output.console import console
    from mcpradar.scanner.engine import Scanner
    from mcpradar.scanner.report import Severity
    from mcpradar.storage.store import Store

    # Load baseline
    store = Store()
    baseline = store.load_fingerprint(target, transport)

    if baseline is None:
        console.print("[yellow]No previous fingerprint record for this server.[/]")
        console.print(
            f"To create a fingerprint: mcpradar fingerprint create {target} -t {transport}"
        )
        return

    # Current scan
    sev = Severity.from_str("low")
    scanner = Scanner(target=target, transport=transport, min_severity=sev)
    with console.status(f"[bold blue]{target}[/] scanning..."):
        report = asyncio.run(scanner.run())

    # Transport check
    checker = TransportChecker()
    tls_info = checker.check(target, transport)

    # Create current fingerprint
    fingerprinter = Fingerprinter()
    current = fingerprinter.create(report, tls_info)

    # Compare
    diff = fingerprinter.compare(baseline, current)

    # Display
    console.print("\n[bold]Fingerprint Comparison[/]")
    console.print(f"  [dim]Previous:[/] {baseline.first_seen}")
    console.print(f"  [dim]Now:     [/] {current.first_seen}")

    if diff.is_first_scan:
        console.print("\n[yellow]First scan - comparison not available.[/]")
        return

    if not any(
        [
            diff.tool_names_changed,
            diff.version_change,
            diff.protocol_changed,
            diff.capabilities_changed,
            diff.tls_changed,
            diff.endpoint_changed,
        ]
    ):
        console.print("\n[green]No changes detected.[/]")
        return

    console.print("\n[bold]Detected Changes:[/]")

    if diff.version_change:
        color = "red" if diff.version_change == "rollback" else "yellow"
        label = {
            "rollback": "VERSION ROLLBACK",
            "major_upgrade": "Major version upgrade",
            "minor_upgrade": "Minor version change",
        }.get(diff.version_change, diff.version_change)
        console.print(
            f"  [{color}][!][/] {label}: {diff.previous_version} → {diff.current_version}"
        )

    if diff.tool_names_changed:
        console.print("  [yellow][!][/] Tool list changed")

    if diff.tls_downgrade:
        console.print("  [red][!][/] TLS downgrade detected")
    elif diff.tls_changed:
        console.print("  [yellow][!][/] TLS info changed")

    if diff.endpoint_changed:
        console.print("  [red][!][/] Server address changed")

    if diff.protocol_changed:
        console.print("  [dim][i][/] MCP protocol version changed")

    if diff.capabilities_changed:
        console.print("  [dim][i][/] Capabilities changed")


@fingerprint_app.command(name="list")
def fingerprint_list() -> None:
    """List stored fingerprints."""
    from rich.table import Table

    from mcpradar.output.console import console
    from mcpradar.storage.store import Store

    store = Store()
    fingerprints = store.list_fingerprints()

    if not fingerprints:
        console.print("[dim]No fingerprint records yet.[/]")
        console.print("[dim]To create a fingerprint: mcpradar fingerprint create <target>[/]")
        return

    table = Table(title="Stored Fingerprints", show_header=True)
    table.add_column("Server ID", width=18)
    table.add_column("Endpoint", width=30)
    table.add_column("Version", width=10)
    table.add_column("Tools", width=6)
    table.add_column("TLS", width=10)
    table.add_column("Last Seen", width=20)

    for fp in fingerprints:
        tls_ver = fp.tls_info.version if fp.tls_info else "N/A"
        table.add_row(
            fp.server_id,
            fp.endpoint[:30],
            fp.server_version or "?",
            str(fp.tool_count),
            tls_ver,
            fp.last_seen[:19],
        )

    console.print(table)


# ---------------------------------------------------------------------------
# cve
# ---------------------------------------------------------------------------

cve_app = typer.Typer(help="CVE feed management", no_args_is_help=True)
app.add_typer(cve_app, name="cve")


@cve_app.command(name="sync")
def cve_sync() -> None:
    """Synchronize CVE feed from NVD."""
    from mcpradar.cvefeed.syncer import NVDAPISyncer, save_feed, sync_feed
    from mcpradar.output.console import console

    console.print("[bold]Syncing CVE feed from NVD...[/]")
    try:
        syncer = NVDAPISyncer()
        count = syncer.sync_all()
        console.print(f"[green]✓ {count} CVEs in feed[/]")
    except Exception as exc:
        console.print(f"[yellow]NVD sync failed: {exc}[/]")
        console.print("[dim]Falling back to seed data...[/]")
        entries = sync_feed()
        save_feed(entries)
        console.print(f"[green]✓ {len(entries)} CVEs synced (seed only)[/]")


@cve_app.command(name="match")
def cve_match(
    scan_id: str = typer.Argument(help="Scan ID to match findings against CVEs"),
    min_score: float = typer.Option(  # noqa: B008
        0.3, "--min-score", help="Minimum match score (0.0-1.0)"
    ),
    backend: str = typer.Option(  # noqa: B008
        "nvd",
        "--backend",
        help="CVE lookup backend: nvd (local feed) or osv (OSV.dev API)",
    ),
    ecosystem: str | None = typer.Option(  # noqa: B008
        None, "--ecosystem", help="Package ecosystem for OSV backend (npm, PyPI, etc.)"
    ),
    package: str | None = typer.Option(  # noqa: B008
        None, "--package", help="Package name for OSV backend"
    ),
    version: str | None = typer.Option(  # noqa: B008
        None, "--version", help="Package version for OSV backend"
    ),
) -> None:
    """Match scan findings to known CVEs.

    Supports two backends:
    - nvd (default): matches findings against a local NVD-derived CVE feed.
    - osv: queries OSV.dev for vulnerabilities affecting a specific package version.
      Requires --ecosystem, --package, and --version.
    """
    from mcpradar.output.console import console
    from mcpradar.storage.store import Store

    store = Store()
    try:
        report = store.load(scan_id)
    except Exception as err:
        console.print(f"[red]Scan not found: {scan_id}[/]")
        raise typer.Exit(1) from err

    if backend == "osv":
        # --- OSV backend ---
        if not ecosystem or not package or not version:
            console.print("[red]OSV backend requires --ecosystem, --package, and --version[/]")
            raise typer.Exit(1)

        from mcpradar.cvefeed.osv import enrich_scan_with_osv

        osv_matches = enrich_scan_with_osv(
            findings=report.findings,
            package_ecosystem=ecosystem,
            package_name=package,
            package_version=version,
        )

        if not osv_matches:
            console.print(
                f"[dim]No OSV vulnerabilities found for {package}@{version} ({ecosystem})[/]"
            )
            return

        from rich.table import Table

        table = Table(
            title=f"OSV CVE Matches - {package}@{version} ({ecosystem})",
            show_header=True,
            header_style="bold",
        )
        table.add_column("OSV ID")
        table.add_column("Aliases")
        table.add_column("Severity")
        table.add_column("Fixed Version")
        table.add_column("Summary", width=50)

        for m in osv_matches:
            sev = m.get("severity_score")
            sev_display = f"{sev:.1f}" if sev else "-"
            table.add_row(
                m.get("id", "?"),
                ", ".join(m.get("aliases", [])),
                sev_display,
                m.get("fixed_version", "-") or "-",
                m.get("summary", "")[:50],
            )

        console.print(table)
        return

    # --- NVD backend (default) ---
    from mcpradar.cvefeed.syncer import load_feed, match_findings_to_cves

    feed = load_feed()
    if not feed:
        console.print("[dim]CVE feed is empty. Run 'mcpradar cve sync' first.[/]")
        raise typer.Exit(1)

    matches = match_findings_to_cves(report.findings, feed, min_score=min_score)

    if not matches:
        console.print("[dim]No CVE matches found for this scan.[/]")
        return

    from rich.table import Table

    table = Table(title=f"CVE Matches for {scan_id}", show_header=True, header_style="bold")
    table.add_column("Finding Rule")
    table.add_column("Finding Title", width=30)
    table.add_column("CVE ID")
    table.add_column("CVE Severity")
    table.add_column("Score")
    table.add_column("Keywords")

    for match in matches:
        score_color = "green" if match.score >= 0.7 else "yellow" if match.score >= 0.5 else "dim"
        table.add_row(
            match.finding_rule,
            match.finding_title[:30],
            match.cve_id,
            match.cve_severity.upper(),
            f"[{score_color}]{match.score:.2f}[/]",
            ", ".join(match.matched_keywords[:5]),
        )

    console.print(table)


@cve_app.command(name="list")
def cve_list(
    severity: str | None = typer.Option(  # noqa: B008
        None, "--severity", "-s", help="Filter by severity: low, medium, high, critical"
    ),
    search: str | None = typer.Option(  # noqa: B008
        None, "--search", help="Search in CVE description"
    ),
    limit: int = typer.Option(  # noqa: B008
        50, "--limit", "-n", help="Maximum CVEs to show"
    ),
) -> None:
    """List cached MCP-related CVEs."""
    from mcpradar.cvefeed.syncer import load_feed
    from mcpradar.output.console import console

    feed = load_feed()
    if not feed:
        console.print("[dim]CVE feed is empty. Run 'mcpradar cve sync' first.[/]")
        return

    # Filter
    if severity:
        feed = [c for c in feed if c.severity.lower() == severity.lower()]
    if search:
        search_lower = search.lower()
        feed = [c for c in feed if search_lower in c.description.lower()]

    feed = feed[:limit]

    if not feed:
        console.print("[dim]No CVEs match the filter.[/]")
        return

    from rich.table import Table

    table = Table(title=f"CVEs ({len(feed)})", show_header=True, header_style="bold")
    table.add_column("CVE ID", width=16)
    table.add_column("Severity", width=10)
    table.add_column("Published", width=12)
    table.add_column("Description", width=60)

    for cve in feed:
        sev_color = {
            "critical": "bold red",
            "high": "orange1",
            "medium": "yellow",
            "low": "dim cyan",
        }.get(cve.severity.lower(), "dim")
        desc = cve.description[:80].replace("\n", " ")
        published = cve.published[:10] if cve.published else "-"
        table.add_row(
            cve.cve_id,
            f"[{sev_color}]{cve.severity.upper()}[/]",
            published,
            desc,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# watch
# ---------------------------------------------------------------------------


@app.command()
def watch(
    target: str = typer.Argument(help="MCP server URL or stdio command"),
    transport: str = typer.Option(  # noqa: B008
        "http", "--transport", "-t", help="Transport type: http, sse, stdio"
    ),
    interval: int = typer.Option(  # noqa: B008
        300, "--interval", "-i", help="Scan interval (seconds, default 300)"
    ),
    alert_cmd: str | None = typer.Option(  # noqa: B008
        None,
        "--alert-cmd",
        "-c",
        help="Command to run on change (shlex, shell=False)",
    ),
    alert_webhook: str | None = typer.Option(  # noqa: B008
        None, "--alert-webhook", "-w", help="Webhook URL to POST on change"
    ),
) -> None:
    """Periodically scan an MCP server and notify on changes."""
    from mcpradar.output.console import console
    from mcpradar.watch.watcher import Watcher

    watcher = Watcher(
        target,
        transport=transport,
        interval=interval,
        alert_cmd=alert_cmd,
        alert_webhook=alert_webhook,
    )

    console.print(f"[bold]mcpradar watch started: {target}[/]")
    console.print(f"[dim]Interval: {interval}s | Ctrl+C to exit[/]\n")

    try:
        asyncio.run(watcher.run())
    except KeyboardInterrupt:
        console.print("\n[dim]Watch stopped.[/]")


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


@app.command()
def audit(
    target: str | None = typer.Option(  # noqa: B008
        None, "--target", help="Filter by target URL"
    ),
    event_type: str | None = typer.Option(  # noqa: B008
        None,
        "--type",
        help="Filter by event type: scan_started, scan_completed, diff_detected, alert_sent, error",
    ),
    since: str | None = typer.Option(  # noqa: B008
        None, "--since", help="Show events since timestamp (ISO 8601 or relative: 7d, 24h, 1w)"
    ),
    limit: int = typer.Option(  # noqa: B008
        50, "--limit", "-n", help="Maximum events to show"
    ),
    json_only: bool = typer.Option(  # noqa: B008
        False, "--json", help="Output as JSON"
    ),
    export_path: Path | None = typer.Option(  # noqa: B008
        None, "--export", "-o", help="Export audit log to file"
    ),
) -> None:
    """View and export the security audit trail."""
    from datetime import datetime, timedelta

    from mcpradar.audit.auditor import AuditLogger
    from mcpradar.output.console import console

    # Parse --since for relative durations
    since_ts = None
    if since:
        if since.endswith("d"):
            try:
                days = int(since[:-1])
                since_ts = (datetime.now(UTC) - timedelta(days=days)).isoformat()
            except ValueError as err:
                console.print(f"[red]Invalid --since format: {since}[/]")
                raise typer.Exit(1) from err
        elif since.endswith("h"):
            try:
                hours = int(since[:-1])
                since_ts = (datetime.now(UTC) - timedelta(hours=hours)).isoformat()
            except ValueError as err:
                console.print(f"[red]Invalid --since format: {since}[/]")
                raise typer.Exit(1) from err
        elif since.endswith("w"):
            try:
                weeks = int(since[:-1])
                since_ts = (datetime.now(UTC) - timedelta(weeks=weeks)).isoformat()
            except ValueError as err:
                console.print(f"[red]Invalid --since format: {since}[/]")
                raise typer.Exit(1) from err
        else:
            since_ts = since  # Assume ISO 8601

    logger = AuditLogger()
    events = logger.query(since=since_ts, event_type=event_type, target=target, limit=limit)

    if export_path:
        logger.export_audit_log(export_path, fmt="json")
        console.print(f"[green]Audit log exported to {export_path}[/]")

    if json_only:
        console.print(json.dumps([e.to_dict() for e in events], indent=2, ensure_ascii=False))
        return

    if not events:
        console.print("[dim]No audit events found.[/]")
        return

    from rich.table import Table

    table = Table(title="Audit Trail", show_header=True, header_style="bold")
    table.add_column("Timestamp", width=20)
    table.add_column("Type", width=16)
    table.add_column("Severity", width=10)
    table.add_column("Target", width=30)
    table.add_column("Detail", width=50)

    for e in events:
        # Severity color
        sev_color = {"info": "dim", "warning": "yellow", "error": "bold red"}.get(e.severity, "dim")

        # Event type badge
        type_badges = {
            "scan_started": "[dim cyan]SCAN_START[/]",
            "scan_completed": "[cyan]SCAN_DONE[/]",
            "diff_detected": "[yellow]DIFF[/]",
            "alert_sent": "[orange1]ALERT[/]",
            "error": "[bold red]ERROR[/]",
        }
        type_display = type_badges.get(e.event_type, e.event_type)

        # Detail preview (truncated)
        detail_str = str(e.detail) if e.detail else ""
        if len(detail_str) > 80:
            detail_str = detail_str[:77] + "..."

        table.add_row(
            e.timestamp[:19].replace("T", " "),
            type_display,
            f"[{sev_color}]{e.severity.upper()}[/]",
            e.target[:30] if e.target else "-",
            detail_str,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# registry - MCP Registry integration
# ---------------------------------------------------------------------------

registry_app = typer.Typer(help="MCP Registry integration", no_args_is_help=True)
app.add_typer(registry_app, name="registry")


@registry_app.command(name="fetch")
def registry_fetch(
    limit: int = typer.Option(  # noqa: B008
        100, "--limit", "-n", help="Maximum servers to fetch per page"
    ),
    all_versions: bool = typer.Option(  # noqa: B008
        False, "--all-versions", help="Include all versions (not just latest)"
    ),
    json_only: bool = typer.Option(  # noqa: B008
        False, "--json", help="Output as JSON"
    ),
) -> None:
    """Fetch MCP server list from the official registry and cache locally."""
    from mcpradar.output.console import console
    from mcpradar.registry.client import RegistryClient

    console.print("[bold]Fetching MCP Registry...[/]")
    client = RegistryClient()
    entries = client.list_servers(limit=limit, latest_only=not all_versions)

    scannable = sum(1 for e in entries if e.packages)
    remote_only = len(entries) - scannable

    if json_only:
        console.print(
            json.dumps(
                {
                    "count": len(entries),
                    "scannable": scannable,
                    "remote_only": remote_only,
                    "servers": [
                        {
                            "name": e.name,
                            "title": e.title,
                            "version": e.version,
                            "packages": [
                                {
                                    "type": p.registry_type,
                                    "identifier": p.identifier,
                                    "transport": p.transport,
                                }
                                for p in e.packages
                            ],
                            "categories": e.categories,
                            "status": e.status,
                        }
                        for e in entries
                    ],
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return

    console.print(f"[green]Fetched {len(entries)} servers[/]")
    console.print(f"  With packages (scannable): [cyan]{scannable}[/]")
    console.print(f"  Remote-only: [dim]{remote_only}[/]")
    console.print(f"[dim]Cache: {client._cache_path()}[/]")


@registry_app.command(name="list")
def registry_list(
    limit: int = typer.Option(  # noqa: B008
        20, "--limit", "-n", help="Maximum entries to display"
    ),
    category: str | None = typer.Option(  # noqa: B008
        None, "--category", "-c", help="Filter by category (e.g. Developer Tools)"
    ),
    transport: str | None = typer.Option(  # noqa: B008
        None, "--transport", "-t", help="Filter by transport (stdio, streamable-http, sse)"
    ),
    scannable_only: bool = typer.Option(  # noqa: B008
        False, "--scannable", help="Show only servers with installable packages"
    ),
    json_only: bool = typer.Option(  # noqa: B008
        False, "--json", help="Output as JSON"
    ),
) -> None:
    """List MCP servers from the cached registry."""
    from rich.table import Table

    from mcpradar.output.console import console
    from mcpradar.registry.client import RegistryClient

    client = RegistryClient()
    entries = client.list_servers(limit=100, latest_only=True)

    # Filters
    if category:
        entries = [e for e in entries if any(category.lower() in c.lower() for c in e.categories)]
    if transport:
        entries = [e for e in entries if any(p.transport == transport for p in e.packages)]
    if scannable_only:
        entries = [e for e in entries if e.packages]

    entries = entries[:limit]

    if not entries:
        console.print("[dim]No entries match the filter. Run 'mcpradar registry fetch' first.[/]")
        return

    if json_only:
        output = [
            {
                "name": e.name,
                "version": e.version,
                "packages": [
                    {"type": p.registry_type, "identifier": p.identifier} for p in e.packages
                ],
                "categories": e.categories,
                "status": e.status,
            }
            for e in entries
        ]
        console.print(json.dumps(output, indent=2, ensure_ascii=False))
        return

    table = Table(title="MCP Registry Servers", show_header=True, header_style="bold")
    table.add_column("Name", width=36)
    table.add_column("Version", width=10)
    table.add_column("Packages", width=20)
    table.add_column("Categories", width=24)
    table.add_column("Status", width=10)

    for e in entries:
        pkg_str = ", ".join(f"{p.registry_type}:{p.identifier}" for p in e.packages[:2])
        if len(e.packages) > 2:
            pkg_str += f" +{len(e.packages) - 2}"
        cat_str = ", ".join(e.categories[:2])
        status_color = "green" if e.status == "active" else "yellow"
        table.add_row(
            e.name[:36],
            e.version[:10],
            pkg_str[:20] if pkg_str else "[dim]remote only[/]",
            cat_str[:24],
            f"[{status_color}]{e.status}[/]",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# leaderboard
# ---------------------------------------------------------------------------

leaderboard_app = typer.Typer(help="Security leaderboard generation", no_args_is_help=True)
app.add_typer(leaderboard_app, name="leaderboard")


@leaderboard_app.command(name="generate")
def leaderboard_generate(
    output_path: Path | None = typer.Option(  # noqa: B008
        None, "--output", "-o", help="Output path (default: docs/leaderboard/data.json)"
    ),
    results_dir: Path | None = typer.Option(  # noqa: B008
        None, "--results-dir", help="Validation results directory (default: validation/results)"
    ),
) -> None:
    """Generate leaderboard data.json with AIVSS scores from scan results."""
    import hashlib
    import json

    from mcpradar import __version__
    from mcpradar.output.console import console

    results = results_dir or Path("validation/results")
    output = output_path or Path("docs/leaderboard/data.json")

    rows: list[dict[str, Any]] = []

    if results.exists():
        for fpath in sorted(results.glob("*.json")):
            try:
                data = json.loads(fpath.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue

            name = data.get("name") or ""
            if not name:
                target = data.get("target", "")
                for token in target.split():
                    if token.startswith("@"):
                        name = token
                        break
                if not name:
                    name = fpath.stem

            # Handle both raw to_dict() format and processed validation format
            summary = data.get("summary", {})
            tools = summary.get("total_tools", len(data.get("tools", [])))
            findings_list = data.get("findings", [])
            scan_id = data.get("scan_id", "") or data.get("id", "")

            # A result file only counts as a real scan if it carries scan
            # evidence: enumerated tools, a scan id, or a scan timestamp.
            # Stub entries (registry placeholders with none of these) must NOT
            # be presented as a clean grade-A pass — they are simply pending.
            was_scanned = bool(tools or scan_id or data.get("scanned_at"))
            if not was_scanned:
                rows.append(
                    {
                        "server": name,
                        "display_name": name.replace("@", "").replace("/", " / "),
                        "version": data.get("version", ""),
                        "aivss_score": None,
                        "grade": "-",
                        "confidence": None,
                        "tools": tools,
                        "findings": 0,
                        "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                        "findings_detail": [],
                        "tool_hash": "",
                        "last_scanned": "-",
                        "scanner_version": __version__,
                        "status": "pending",
                    }
                )
                continue

            # Compute severity counts from findings array
            sev: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for f in findings_list:
                s = f.get("severity", "")
                if s in sev:
                    sev[s] += 1

            # The grade reflects MEDIUM+ findings only. LOW findings are
            # informational lint (e.g. R114 "string has no length constraint")
            # that fire on almost every server; counting them would push clean
            # reference servers to a failing grade — the same MEDIUM+ scope the
            # accuracy benchmark uses. The LOW count is still surfaced
            # separately for transparency.
            meaningful = sev["critical"] + sev["high"] + sev["medium"]
            low_findings = sev["low"]

            # Compute AIVSS score from MEDIUM+ severity counts. Score is the
            # severity-weighted finding total spread over the tool surface
            # (floored at 3 so a 1-2 tool server with a single finding is not
            # catapulted to F). The earlier density multiplier double-counted
            # findings-per-tool and turned uniform schema-laxity into grade F on
            # otherwise-clean servers (e.g. chrome-devtools-mcp).
            weighted = sev["critical"] * 10 + sev["high"] * 7 + sev["medium"] * 4
            if meaningful == 0:
                score, grade = 0.0, "A"
            else:
                raw = weighted / max(tools, 3)
                # A genuine critical/high should never round down to a clean
                # grade: floor the score so any high is at least C, any critical
                # at least D.
                if sev["critical"]:
                    raw = max(raw, 5.0)
                elif sev["high"]:
                    raw = max(raw, 3.0)
                score = min(10.0, round(raw, 1))
                if score <= 0.9:
                    grade = "A"
                elif score <= 2.9:
                    grade = "B"
                elif score <= 4.9:
                    grade = "C"
                elif score <= 6.9:
                    grade = "D"
                else:
                    grade = "F"

            # Detail lists the MEDIUM+ findings that drive the grade.
            findings_detail = [
                {
                    "rule_id": f.get("rule_id", "?"),
                    "severity": f.get("severity", "?"),
                    "title": f.get("title", "")[:80],
                    "description": f.get("description", "")[:120],
                }
                for f in findings_list
                if f.get("severity", "") in ("critical", "high", "medium")
            ]

            # Tool hash: SHA-256 of the sorted tool names. Prefer computing it
            # directly from the result file's tools; fall back to the store.
            tool_hash = ""
            tool_objs = data.get("tools", [])
            if tool_objs:
                names = sorted(t.get("name", "") for t in tool_objs if isinstance(t, dict))
                tool_hash = hashlib.sha256(",".join(names).encode()).hexdigest()[:16]
            elif scan_id:
                try:
                    from mcpradar.storage.store import Store

                    store = Store()
                    report = store.load(scan_id)
                    store.close()
                    if report.tools:
                        names = sorted(t.name for t in report.tools)
                        tool_hash = hashlib.sha256(",".join(names).encode()).hexdigest()[:16]
                except Exception as exc:
                    import logging

                    logging.getLogger("mcpradar").warning(
                        "Failed to compute tool hash for %s: %s", scan_id, exc
                    )

            rows.append(
                {
                    "server": name,
                    "display_name": name.replace("@", "").replace("/", " / "),
                    "version": data.get("version", ""),
                    "aivss_score": score,
                    "grade": grade,
                    "confidence": 1.0
                    if meaningful == 0
                    else round(
                        min(
                            1.0,
                            (sev["critical"] * 0.3 + sev["high"] * 0.2 + sev["medium"] * 0.1)
                            / max(meaningful, 1)
                            + 0.7,
                        ),
                        2,
                    ),
                    "tools": tools,
                    "tools_detail": [
                        {
                            "name": t.get("name", ""),
                            "description": (t.get("description", "") or "")[:400],
                            "input_schema": t.get("input_schema", {}),
                            "output_schema": t.get("output_schema", {}),
                        }
                        for t in tool_objs
                        if isinstance(t, dict)
                    ],
                    "findings": meaningful,
                    "low_findings": low_findings,
                    "by_severity": {
                        "critical": sev["critical"],
                        "high": sev["high"],
                        "medium": sev["medium"],
                        "low": sev["low"],
                    },
                    "findings_detail": findings_detail,
                    "tool_hash": tool_hash,
                    "last_scanned": data.get("scanned_at", "")[:10]
                    if data.get("scanned_at")
                    else "-",
                    "scanner_version": __version__,
                    "status": "scanned",
                }
            )

    # Deduplicate by server name. The catalog carries the same server under two
    # filename conventions (e.g. "@anthropic_server-time.json" and
    # "anthropic-server-time.json"), which otherwise renders as duplicate rows.
    # Keep the most-informative copy: scanned over pending, then more tools.
    by_name: dict[str, dict[str, Any]] = {}
    for r in rows:
        key = r["server"]
        existing = by_name.get(key)
        if existing is None:
            by_name[key] = r
            continue
        cur_rank = (existing["status"] != "pending", existing["tools"])
        new_rank = (r["status"] != "pending", r["tools"])
        if new_rank > cur_rank:
            by_name[key] = r
    rows = list(by_name.values())

    # Deduplicate scanned servers by tool fingerprint: the same real server can
    # be reached under several package aliases (e.g. "context7" and
    # "@upstash/context7-mcp"), which produce identical tool sets. Collapse them
    # to one row, preferring a canonical name (not an "@anthropic/*" catalog
    # guess, then shorter). Pending stubs have no tools, so they are never
    # collapsed here.
    def _canonical_rank(r: dict[str, Any]) -> tuple[bool, int]:
        name = r["server"]
        return (name.startswith("@anthropic/"), len(name))

    by_hash: dict[str, dict[str, Any]] = {}
    passthrough: list[dict[str, Any]] = []
    for r in rows:
        h = r.get("tool_hash") or ""
        if r["status"] == "pending" or not h:
            passthrough.append(r)
            continue
        existing = by_hash.get(h)
        if existing is None or _canonical_rank(r) < _canonical_rank(existing):
            by_hash[h] = r
    rows = list(by_hash.values()) + passthrough

    # Scanned servers first (by ascending risk), pending servers last.
    rows.sort(key=lambda r: (r["status"] == "pending", r["aivss_score"] or 0.0, -r["tools"]))

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")

    # Regenerate the README badges from the current data so an embedded badge
    # always reflects the server's real grade (they used to be static files
    # that drifted out of sync). Filename matches the detail page's derivation:
    # strip "@", turn "/" into "-".
    _grade_color = {
        "A": "#3fb950",
        "B": "#56d364",
        "C": "#d29922",
        "D": "#db6d28",
        "F": "#f85149",
    }
    badges_dir = output.parent / "badges"
    badges_dir.mkdir(parents=True, exist_ok=True)
    # Clear stale badges (dropped aliases, renamed servers) — they are fully
    # derived from the current data, so a clean rebuild keeps them in sync.
    for old in badges_dir.glob("*.svg"):
        old.unlink()
    badge_count = 0
    for r in rows:
        slug = r["server"].replace("@", "").replace("/", "-")
        if not slug:
            continue
        if r["status"] == "pending":
            color, right, aria = "#8b949e", "not scanned", "not scanned"
        else:
            g = r["grade"]
            color = _grade_color.get(g, "#8b949e")
            right = f"{g} · {r['aivss_score']:.1f}"
            aria = f"{g} - {r['aivss_score']:.1f}/10"
        # Right panel widens for the longer "not scanned" label.
        right_w = 96 if r["status"] == "pending" else 72
        total_w = 68 + right_w
        svg = (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="20" '
            f'role="img" aria-label="MCPRadar Security: {aria}">\n'
            f"  <title>MCPRadar Security Score: {aria}</title>\n"
            '  <linearGradient id="bg" x1="0" y1="0" x2="1" y2="0">\n'
            '    <stop offset="0%" stop-color="#444"/>\n'
            '    <stop offset="100%" stop-color="#333"/>\n'
            "  </linearGradient>\n"
            f'  <rect width="{total_w}" height="20" rx="3" fill="url(#bg)"/>\n'
            f'  <rect x="68" width="{right_w}" height="20" fill="{color}" fill-opacity="0.15"/>\n'
            '  <text x="34" y="14" fill="#c9d1d9" font-size="10" font-family="sans-serif" '
            'text-anchor="middle" font-weight="600">MCPRadar</text>\n'
            f'  <text x="{68 + right_w // 2}" y="14" fill="{color}" font-size="10" '
            f'font-family="sans-serif" text-anchor="middle" font-weight="600">{right}</text>\n'
            "</svg>\n"
        )
        (badges_dir / f"{slug}.svg").write_text(svg, encoding="utf-8")
        badge_count += 1

    scanned_rows = [r for r in rows if r["status"] != "pending"]
    pending_rows = [r for r in rows if r["status"] == "pending"]
    console.print(
        f"[green]Generated {output}[/] — "
        f"{len(scanned_rows)} scanned, {len(pending_rows)} pending, {len(rows)} total; "
        f"{badge_count} badges"
    )
    for r in scanned_rows:
        grade_color = {
            "A": "green",
            "B": "bright_green",
            "C": "yellow",
            "D": "orange1",
            "F": "bold red",
        }.get(r["grade"], "")
        console.print(f"  [{grade_color}]{r['grade']}[/] | {r['aivss_score']:4.1f} | {r['server']}")
    if pending_rows:
        console.print(f"  [dim]+ {len(pending_rows)} pending (not yet scanned)[/]")


# ---------------------------------------------------------------------------
# feed
# ---------------------------------------------------------------------------


@app.command()
def feed_update(
    full: bool = typer.Option(  # noqa: B008
        False, "--full", help="Full NVD API sync instead of seed-only update"
    ),
) -> None:
    """Update the CVE feed."""
    from mcpradar.output.console import console

    if full:
        from mcpradar.cvefeed.syncer import NVDAPISyncer

        console.print("[bold]Running full NVD API sync...[/]")
        try:
            syncer = NVDAPISyncer()
            count = syncer.sync_all()
            console.print(f"[green]Synced {count} CVEs from NVD.[/]")
        except Exception as exc:
            console.print(f"[yellow]NVD sync failed: {exc}[/]")
            console.print("[dim]Falling back to seed data...[/]")
            from mcpradar.cvefeed.syncer import save_feed, sync_feed

            entries = sync_feed()
            save_feed(entries)
            console.print(f"[green]Synced {len(entries)} CVEs (seed only).[/]")
    else:
        from mcpradar.cvefeed.syncer import save_feed, sync_feed

        entries = sync_feed()
        save_feed(entries)
        console.print(f"[green]{len(entries)} CVEs synced.[/]")


# init
# ---------------------------------------------------------------------------


@app.command()
def init(
    path: Path = typer.Option(  # noqa: B008
        Path("mcpradar.toml"), "--output", "-o", help="Configuration file path"
    ),
) -> None:
    """Create mcpradar.toml configuration file."""
    from mcpradar.init.initializer import Initializer
    from mcpradar.output.console import console

    init_ = Initializer()
    init_.generate(path)
    console.print(f"[green]OK[/] Configuration file created: [bold]{path}[/]")
