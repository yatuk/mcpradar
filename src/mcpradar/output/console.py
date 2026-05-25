"""Rich tabanli terminal cikti — scan raporu + git-diff style diff."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcpradar.scanner.report import ScanReport, Severity

SEVERITY_COLORS: dict[Severity, str] = {
    Severity.LOW: "dim cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "orange1",
    Severity.CRITICAL: "bold red",
}

SEVERITY_LABELS: dict[Severity, str] = {
    Severity.LOW: "LOW",
    Severity.MEDIUM: "MED",
    Severity.HIGH: "HIGH",
    Severity.CRITICAL: "CRIT",
}

CHANGE_COLORS = {
    "cosmetic": "dim",
    "behavioral": "yellow",
    "security": "bold red",
}

CHANGE_LABELS = {
    "cosmetic": "cosmetic",
    "behavioral": "behavioral",
    "security": "SECURITY",
}


class RadarConsole:
    def __init__(self) -> None:
        self._console = Console(force_terminal=True, legacy_windows=False)

    @property
    def console(self) -> Console:
        return self._console

    def status(self, message: str) -> Any:
        return self._console.status(message)

    def print(self, *args: Any, **kwargs: Any) -> None:
        self._console.print(*args, **kwargs)

    # ------------------------------------------------------------------
    # Scan Report
    # ------------------------------------------------------------------

    def print_report(self, report: ScanReport) -> None:
        self._console.print()
        self._console.rule("[bold]MCPRadar Scan Report[/]")

        meta = Table.grid(padding=(0, 2))
        meta.add_column(style="dim")
        meta.add_column()
        meta.add_row("Target   ", report.target)
        meta.add_row("Transport", report.transport)
        meta.add_row("Snapshot ", report.id)
        meta.add_row("Time     ", report.scanned_at)
        meta.add_row("Tools    ", str(report.summary.get("total_tools", 0)))
        meta.add_row("Prompts  ", str(report.summary.get("total_prompts", 0)))
        meta.add_row("Resources", str(report.summary.get("total_resources", 0)))
        self._console.print(meta)

        parts: list[Text] = []
        parts.append(Text("FINDINGS  ", style="bold"))
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
            count = report.summary.get(sev.value, 0)
            if count > 0:
                color = SEVERITY_COLORS[sev]
                parts.append(Text(f"[{SEVERITY_LABELS[sev]}:{count}]", style=color))
                parts.append(Text(" "))
        clean = report.summary.get("clean", 0)
        if clean > 0:
            parts.append(Text(f"[CLEAN:{clean}]", style="green"))
        if not any(report.summary.get(s.value, 0) for s in Severity):
            parts.append(Text("All clean", style="green"))
        self._console.print(Text.assemble(*parts))
        self._console.print()

        if report.tools:
            self._print_tools(report)
        if report.prompts:
            self._print_prompts(report)
        if report.resources:
            self._print_resources(report)
        if report.findings:
            self._print_findings(report)
        self._console.print()

    def _print_tools(self, report: ScanReport) -> None:
        table = Table(title="Tools", show_header=True, header_style="bold")
        table.add_column("#", width=3, style="dim")
        table.add_column("Name", width=24)
        table.add_column("Description")
        table.add_column("Input", width=5)
        table.add_column("Output", width=5)

        for i, t in enumerate(report.tools, 1):
            has_input = "YES" if t.input_schema else "-"
            has_output = "YES" if t.output_schema else "-"
            desc = t.description[:120] + ("..." if len(t.description) > 120 else "")
            table.add_row(str(i), t.name, desc, has_input, has_output)

        self._console.print(table)

    def _print_prompts(self, report: ScanReport) -> None:
        table = Table(title="Prompts", show_header=True, header_style="bold")
        table.add_column("#", width=3, style="dim")
        table.add_column("Name", width=24)
        table.add_column("Description")
        table.add_column("Args", width=6)
        for i, p in enumerate(report.prompts, 1):
            desc = p.description[:100] + ("..." if len(p.description) > 100 else "")
            table.add_row(str(i), p.name, desc, str(len(p.arguments)))
        self._console.print(table)

    def _print_resources(self, report: ScanReport) -> None:
        table = Table(title="Resources", show_header=True, header_style="bold")
        table.add_column("#", width=3, style="dim")
        table.add_column("URI", width=36)
        table.add_column("Name", width=18)
        table.add_column("Description")
        for i, r in enumerate(report.resources, 1):
            desc = r.description[:100] + ("..." if len(r.description) > 100 else "")
            table.add_row(str(i), r.uri, r.name, desc)
        self._console.print(table)

    def _print_findings(self, report: ScanReport) -> None:
        self._console.print()
        table = Table(
            title="Findings",
            show_header=True,
            header_style="bold",
            show_lines=True,
        )
        table.add_column("Rule", width=6)
        table.add_column("Severity", width=6)
        table.add_column("Target", width=18)
        table.add_column("Description")
        table.add_column("Evidence", width=30)

        for f in report.findings:
            color = SEVERITY_COLORS[f.severity]
            sev_label = SEVERITY_LABELS[f.severity]
            evidence = f.evidence[:80] if f.evidence else f.detail.get("matched", "")[:80]
            table.add_row(
                Text(f.rule_id, style=color),
                Text(sev_label, style=color),
                f.target,
                f.description,
                evidence,
            )

        self._console.print(table)

    # ------------------------------------------------------------------
    # Git-diff style diff output
    # ------------------------------------------------------------------

    def print_diff(self, delta: Any) -> None:
        self._console.print()
        self._console.rule("[bold]MCPRadar Diff[/]")

        # Header
        hdr = Table.grid(padding=(0, 3))
        hdr.add_column(style="dim")
        hdr.add_column()
        hdr.add_column(style="dim")
        hdr.add_column()
        hdr.add_row("--- a", f"{delta.server} @ {delta.scanned_at_a}", "", "")
        hdr.add_row("+++ b", f"{delta.server} @ {delta.scanned_at_b}", "", "")
        self._console.print(hdr)

        # Summary stats
        counts = delta.summary_counts()
        stats = "  ".join(
            f"[green]+{counts.get('added',0)} added[/]"
            f"  [red]-{counts.get('removed',0)} removed[/]"
            f"  [dim]~{counts.get('cosmetic',0)} cosmetic[/]"
            f"  [yellow]~{counts.get('behavioral',0)} behavioral[/]"
            f"  [bold red]~{counts.get('security',0)} security[/]"
        )
        self._console.print(stats)
        self._console.print()

        if not delta.has_changes:
            self._console.print("[green]No changes detected.[/]")
            self._console.print()
            return

        # Tool diffs — git diff style
        for td in delta.tool_diffs:
            self._print_tool_diff(td)

        # Findings
        if delta.new_findings:
            self._console.print("[orange1]New findings:[/]")
            for f in delta.new_findings:
                color = SEVERITY_COLORS[f.severity]
                self._console.print(f"  [{color}]+ {f.rule_id}[/] {f.title} → {f.target}")
            self._console.print()

        if delta.resolved_findings:
            self._console.print("[green]Resolved findings:[/]")
            for f in delta.resolved_findings:
                self._console.print(f"  [green]- {f}[/]")
            self._console.print()

        # Prompts / Resources
        if delta.prompt_added or delta.prompt_removed:
            self._print_resource_changes(
                "Prompts", delta.prompt_added, delta.prompt_removed
            )

        if delta.resource_added or delta.resource_removed:
            self._print_resource_changes(
                "Resources", delta.resource_added, delta.resource_removed
            )

        self._console.print()

    def _print_tool_diff(self, td: Any) -> None:
        if td.added:
            self._console.print(
                Panel(
                    self._format_added_tool(td),
                    title=f"[green]+++ {td.tool_name}[/]",
                    border_style="green",
                )
            )
            return

        if td.removed:
            self._console.print(
                Panel(
                    self._format_removed_tool(td),
                    title=f"[red]--- {td.tool_name}[/]",
                    border_style="red",
                )
            )
            return

        # Changed tool
        sev = td.max_severity.value
        border = CHANGE_COLORS.get(sev, "yellow")
        self._console.print(
            Panel(
                self._format_changed_tool(td),
                title=f"[yellow]~ {td.tool_name}[/]  [{CHANGE_COLORS[sev]}]{CHANGE_LABELS[sev]}[/]",
                border_style=border,
            )
        )

    def _format_added_tool(self, td: Any) -> Text:
        t = Text()
        for c in td.changes:
            if c.field == "input_schema":
                t.append("  input_schema:\n", style="dim")
                t.append(self._format_schema(c.new, prefix="    + "), style="green")
                t.append("\n")
            elif c.field == "output_schema" and c.new:
                t.append("  output_schema:\n", style="dim")
                t.append(self._format_schema(c.new, prefix="    + "), style="green")
                t.append("\n")
            else:
                val = str(c.new)[:200]
                t.append(f"  [green]+ {c.field}:[/] [green]{val}[/]\n")
        return t

    def _format_removed_tool(self, td: Any) -> Text:
        t = Text()
        for c in td.changes:
            val = str(c.old)[:200] if c.old else "(none)"
            if c.field == "name":
                t.append(f"  [red]- {c.field}:[/] [red]{val}[/] (removed)\n")
        return t

    def _format_changed_tool(self, td: Any) -> Text:
        t = Text()
        for c in td.changes:
            sev_color = CHANGE_COLORS.get(c.severity.value, "yellow")
            tag = CHANGE_LABELS.get(c.severity.value, c.severity.value)

            if c.field in ("input_schema", "output_schema"):
                label = f"  [{sev_color}]~ {c.field}[/] [{sev_color}]({tag})[/]"
                t.append(label + "\n")
                t.append(self._format_schema_diff(c.old, c.new, sev_color))
            else:
                old_s = str(c.old)[:120]
                new_s = str(c.new)[:120]
                t.append(
                    f"  [red]- {c.field}: {old_s}[/]\n"
                    f"  [green]+ {c.field}: {new_s}[/]"
                    f"  [{sev_color}]({tag})[/]\n"
                )
        return t

    def _format_schema(self, schema: Any, prefix: str) -> str:
        if not schema:
            return f"{prefix}(empty)"
        compact = json.dumps(schema, indent=2, ensure_ascii=False)
        lines = compact.split("\n")
        return "\n".join(f"{prefix}{line}" for line in lines[:20])

    def _format_schema_diff(self, old: Any, new: Any, sev_color: str) -> str:
        """Show schema property-level diff."""
        lines: list[str] = []
        old_p = old.get("properties", {}) if isinstance(old, dict) else {}
        new_p = new.get("properties", {}) if isinstance(new, dict) else {}
        all_keys = set(old_p) | set(new_p)

        for key in sorted(all_keys):
            ov = old_p.get(key)
            nv = new_p.get(key)
            if ov is None and nv is not None:
                # New property
                lines.append(f"    [green]+ {key}[/] → {_prop_summary(nv)}")
            elif ov is not None and nv is None:
                lines.append(f"    [red]- {key}[/]")
            elif ov != nv:
                lines.append(
                    f"    [yellow]~ {key}[/]: {_prop_summary(ov)} → {_prop_summary(nv)}"
                )

        return "\n".join(lines) if lines else "    (no property-level changes)"

    def _print_resource_changes(
        self, label: str, added: list[str], removed: list[str]
    ) -> None:
        self._console.print(f"[bold]{label}:[/]")
        for name in added:
            self._console.print(f"  [green]+ {name}[/]")
        for name in removed:
            self._console.print(f"  [red]- {name}[/]")
        self._console.print()


def _prop_summary(val: Any) -> str:
    if isinstance(val, dict):
        t = val.get("type", "?")
        desc = val.get("description", "")
        return f"[dim]{t}[/]" + (f" {desc[:60]}" if desc else "")
    return str(val)[:60]


console = RadarConsole()
