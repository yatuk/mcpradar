"""MCPRadar CLI — Typer uygulaması ve komut tanımları."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import typer

from mcpradar import __version__
from mcpradar.storage.store import Store

app = typer.Typer(
    name="mcpradar",
    help="MCP server güvenlik tarayıcısı — tool poisoning ve zaafiyet tespiti",
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
        help="Sürüm bilgisi göster",
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
        "veya stdio komutu ('uvx my-mcp-server --port 0')"
    ),
    transport: str = typer.Option(  # noqa: B008
        "http",
        "--transport",
        "-t",
        help="Transport tipi: http, sse, stdio",
    ),
    output: Path | None = typer.Option(  # noqa: B008
        None, "--output", "-o", help="Sonuçları JSON dosyasına yaz"
    ),
    severity: str = typer.Option(  # noqa: B008
        "medium",
        "--severity",
        "-s",
        help="Minimum severity esigi (low/medium/high/critical)",
    ),
    json_only: bool = typer.Option(  # noqa: B008
        False,
        "--json",
        hidden=True,
        help="Deprecated: --format json kullanın",
    ),
    output_format: str = typer.Option(  # noqa: B008
        "rich",
        "--format",
        "-f",
        help="Çıktı formatı: rich, json, sarif",
    ),
    no_save: bool = typer.Option(  # noqa: B008
        False, "--no-save", help="Snapshot'i veritabanina kaydetme"
    ),
) -> None:
    """MCP server'i güvenlik açısından tara ve SQLite'a kaydet."""
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
        console.print(f"[red]Gecersiz transport: {transport}. Gecerli: {valid_transports}[/]")
        raise typer.Exit(code=1)

    sev = Severity.from_str(severity)
    scanner = Scanner(target=target, transport=transport, min_severity=sev)

    with console.status(f"[bold blue]{target}[/] taranıyor..."):
        report = asyncio.run(scanner.run())

    if json_only or output_format == "json":
        console.print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    elif output_format == "sarif":
        from mcpradar.output.sarif import to_sarif

        sarif_data = to_sarif(report)
        console.print(json.dumps(sarif_data, indent=2, ensure_ascii=False))
    else:
        console.print_report(report)

    # Auto-save to DB
    if not no_save:
        store = Store()
        store.save(report)
        count = store.scan_count(target)
        store.close()
        console.print(f"\n[dim]DB'ye kaydedildi: {report.id} (sunucuda #{count} scan)[/]")

    if output:
        _save_output(report, output, output_format)


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------


@app.command()
def diff(
    server: str | None = typer.Argument(
        default=None,
        help="Karsilastirilacak server URL'si (bos birakilirsa tum server'lar listelenir)",
    ),
    snapshot_a: str | None = typer.Option(  # noqa: B008
        None, "--snapshot-a", "-a", help="Ilk snapshot ID (manuel kiyas)"
    ),
    snapshot_b: str | None = typer.Option(  # noqa: B008
        None, "--snapshot-b", "-b", help="Ikinci snapshot ID (manuel kiyas)"
    ),
    since: str | None = typer.Option(  # noqa: B008
        None, "--since", help="Bu timestamp veya scan ID'den beri degisiklikleri goster"
    ),
    output: Path | None = typer.Option(  # noqa: B008
        None, "--output", "-o", help="Diff sonucunu JSON dosyasina yaz"
    ),
    json_only: bool = typer.Option(  # noqa: B008
        False, "--json", help="Yalnizca JSON cikti"
    ),
) -> None:
    """Iki scan snapshot'u arasindaki schema degisikliklerini karsilastir.

    Ornekler:
        mcpradar diff                    # tum sunuculari listele
        mcpradar diff http://x           # en son 2 scan'i kiyasla
        mcpradar diff http://x --since 2026-01-01
        mcpradar diff -a abc -b def      # belirli iki snapshot
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
            console.print("[dim]Henuz hic scan yok. Once 'mcpradar scan <url>' calistirin.[/]")
        else:
            console.print("[bold]Taranan sunucular:[/]")
            for t in targets:
                count = store.scan_count(t)
                last = store.latest_scans(t, 1)
                last_id = last[0][:12] if last else "-"
                console.print(f"  [cyan]{t}[/] — {count} scan, son: {last_id}")
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
            console.print(f"[dim]{server} icin '{since}' sonrasi scan yok.[/]")
            store.close()
            return
        if len(ids) >= 2:
            ids = [ids[0], ids[-1]]  # newest vs oldest in range
            console.print(
                f"[dim]{len(store.scan_since(server, since))} scan, "
                f"en yeni vs en eski kiyaslaniyor[/]"
            )

    if len(ids) < 2:
        console.print(
            f"[dim]{server} icin en az 2 scan gerekli (su an {len(ids)}). "
            "Once birden fazla 'mcpradar scan' calistirin.[/]"
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
    console.print(f"[dim]Çıktı: {out_path}[/]")


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
# list / show / export / purge — snapshot browser
# ---------------------------------------------------------------------------


@app.command(name="list")
def list_snapshots(
    target: str | None = typer.Argument(
        default=None,
        help="Sunucu URL'si (bos birakilirsa tum sunuculari listeler)",
    ),
    limit: int = typer.Option(  # noqa: B008
        20, "--limit", "-n", help="Gösterilecek maksimum snapshot sayısı"
    ),
) -> None:
    """Bir sunucunun tüm snapshot'larını listele."""
    from rich.table import Table

    from mcpradar.output.console import console

    store = Store()

    if target is None:
        targets = store.list_targets()
        if not targets:
            console.print("[dim]Henüz hiç scan yok.[/]")
        else:
            table = Table(title="Taranan Sunucular", show_header=True)
            table.add_column("Sunucu")
            table.add_column("Scan Sayısı", justify="right")
            table.add_column("Son Scan")
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
        console.print(f"[dim]{target} için snapshot bulunamadı.[/]")
        store.close()
        return

    table = Table(title=f"Snapshots: {target}", show_header=True)
    table.add_column("ID", width=14)
    table.add_column("Tarih", width=22)
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
    scan_id: str = typer.Argument(help="Gösterilecek snapshot ID'si"),
) -> None:
    """Tek bir snapshot'ın detaylı raporunu göster."""
    from mcpradar.output.console import console

    store = Store()
    try:
        report = store.load(scan_id)
        console.print_report(report)
    except LookupError:
        console.print(f"[red]Snapshot bulunamadı: {scan_id}[/]")
    finally:
        store.close()


@app.command()
def export(
    scan_id: str = typer.Argument(help="Export edilecek snapshot ID'si"),
    output_format: str = typer.Option(  # noqa: B008
        "json", "--format", "-f", help="Format: json, sarif, csv"
    ),
    output: Path = typer.Option(  # noqa: B008
        ..., "--output", "-o", help="Çıktı dosyası"
    ),
) -> None:
    """Bir snapshot'ı JSON, SARIF veya CSV formatında dışa aktar."""
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
        else:
            p = output if output.suffix == ".json" else output.with_suffix(".json")
            store.export_json(report, p)
        console.print(f"[green]Export: {p}[/]")
    except LookupError:
        console.print(f"[red]Snapshot bulunamadı: {scan_id}[/]")
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
        None, "--older-than", help="Bu tarihten eski snapshot'ları sil (örn: 30d, 7d, 2026-01-01)"
    ),
    keep_last: int | None = typer.Option(  # noqa: B008
        None, "--keep-last", help="Sadece son N snapshot'ı tut, eskileri sil"
    ),
    target: str | None = typer.Option(  # noqa: B008
        None, "--target", help="Sadece bu sunucu için temizlik yap"
    ),
    dry_run: bool = typer.Option(  # noqa: B008
        False, "--dry-run", help="Silme işlemini yapmadan göster"
    ),
) -> None:
    """Eski snapshot'ları temizle."""
    from mcpradar.output.console import console

    store = Store()

    if older_than:
        cutoff = _parse_duration(older_than)
        ids = store.scans_older_than(cutoff, target)
    elif keep_last:
        ids = store.scans_beyond_keep(target, keep_last)
    else:
        console.print("[dim]--older-than veya --keep-last belirtmelisiniz.[/]")
        store.close()
        return

    if not ids:
        console.print("[dim]Silinecek snapshot yok.[/]")
        store.close()
        return

    console.print(f"[yellow]{len(ids)} snapshot silinecek:[/]")
    for sid in ids[:10]:
        console.print(f"  [dim]- {sid}[/]")
    if len(ids) > 10:
        console.print(f"  [dim]... ve {len(ids) - 10} tane daha[/]")

    if not dry_run:
        store.delete_scans(ids)
        console.print(f"[green]{len(ids)} snapshot silindi.[/]")
    else:
        console.print("[dim](--dry-run: işlem yapılmadı)[/]")

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
# scan-all — config dosyasındaki tüm server'ları tara
# ---------------------------------------------------------------------------


@app.command()
def scan_all(
    config_path: Path | None = typer.Option(  # noqa: B008
        None, "--config", help="Konfigürasyon dosyası yolu (varsayılan: mcpradar.toml)"
    ),
    severity: str = typer.Option(  # noqa: B008
        "medium",
        "--severity",
        "-s",
        help="Minimum severity eşiği (low/medium/high/critical)",
    ),
    json_only: bool = typer.Option(  # noqa: B008
        False, "--json", help="Yalnızca JSON çıktı"
    ),
) -> None:
    """mcpradar.toml'daki tüm sunucuları sırayla tara."""
    from mcpradar.config import MCPRadarConfig
    from mcpradar.output.console import console

    cfg = MCPRadarConfig.from_file(config_path)
    if cfg is None or not cfg.servers:
        console.print(
            "[red]Konfigürasyon bulunamadı. Önce 'mcpradar init' çalıştırın "
            "veya mcpradar.toml oluşturun.[/]"
        )
        raise typer.Exit(code=1)

    console.print(f"[bold]mcpradar scan-all[/] — {len(cfg.servers)} sunucu taranacak\n")
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
            console.print(f"[red]Hata: {srv.url} — {exc}[/]")


# ---------------------------------------------------------------------------
# analyze-context
# ---------------------------------------------------------------------------


@app.command()
def analyze_context(
    config_path: Path | None = typer.Option(  # noqa: B008
        None, "--config", help="Konfigürasyon dosyası yolu"
    ),
    json_only: bool = typer.Option(  # noqa: B008
        False, "--json", help="Yalnızca JSON çıktı"
    ),
) -> None:
    """Birden fazla MCP server'ının birlikte güvenliğini analiz et.

    Cross-server contamination risklerini tespit eder:
    tool ismi çakışmaları, shadowing, veri sızdırma zincirleri.
    """
    import asyncio

    from mcpradar.analyzer.context import ContextAnalyzer
    from mcpradar.config import MCPRadarConfig
    from mcpradar.output.console import console
    from mcpradar.scanner.engine import Scanner
    from mcpradar.scanner.report import Severity

    cfg = MCPRadarConfig.from_file(config_path)
    if cfg is None or not cfg.servers:
        console.print("[red]Konfigürasyon bulunamadı veya servers listesi boş.[/]")
        raise typer.Exit(code=1)

    servers = cfg.servers[:10]  # Max 10
    console.print(
        f"[bold]mcpradar analyze-context[/] — "
        f"{len(servers)} sunucu analiz ediliyor\n"
    )

    scans: list[Any] = []
    for srv in servers:
        with console.status(f"[dim]{srv.name or srv.url}[/] taranıyor..."):
            try:
                scanner = Scanner(
                    target=srv.url,
                    transport=srv.transport,
                    min_severity=Severity("low"),
                )
                report = asyncio.run(scanner.run())
                scans.append(report)
                console.print(
                    f"  [green]{srv.name or srv.url}[/] "
                    f"— {len(report.tools)} tools"
                )
            except Exception as exc:
                console.print(
                    f"  [red]{srv.name or srv.url}[/] — hata: {exc}"
                )

    if len(scans) < 2:
        console.print("[red]En az 2 sunucu taranabilmeli.[/]")
        raise typer.Exit(code=1)

    analyzer = ContextAnalyzer(scans)
    ctx_report = analyzer.analyze()

    if json_only:
        console.print(
            json.dumps(ctx_report.to_dict(), indent=2, ensure_ascii=False)
        )
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

    console.print()


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
    rule_id: str = typer.Argument(help="Rule ID (örnek: R102)"),
) -> None:
    """Show detailed info for a specific rule."""
    from mcpradar.output.console import console
    from mcpradar.scanner.report import Severity
    from mcpradar.scanner.rules import RuleEngine

    engine = RuleEngine(min_severity=Severity("low"))
    for r in engine._rules:
        if r.rule_id == rule_id.upper():
            console.print(f"[bold]{r.rule_id}[/] — {r.title}")
            console.print(f"  Severity: {r.severity.value}")
            console.print(f"  Class: {type(r).__module__}.{type(r).__name__}")
            return
    console.print(f"[red]Rule '{rule_id}' not found.[/]")


@rules_app.command(name="disable")
def rules_disable(
    rule_id: str = typer.Argument(help="Disable edilecek rule ID"),
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
    name: str = typer.Argument(help="Plugin ismi (ornek: my-custom-sqli)"),
    output: Path = typer.Option(  # noqa: B008
        Path("plugins"),
        "--output",
        "-o",
        help="Cikti dizini (varsayilan: ./plugins)",
    ),
) -> None:
    """Yeni bir MCPRadar plugin paketi olustur."""
    from mcpradar.output.console import console
    from mcpradar.plugin.scaffolder import Scaffolder

    scaffolder = Scaffolder()
    try:
        created = scaffolder.scaffold(name, output)
    except FileNotFoundError as exc:
        console.print(f"[red]Hata:[/] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(f"[green]OK[/] Plugin olusturuldu: [bold]{created}[/]")
    console.print(f"  cd {created}")
    console.print("  pip install -e .")
    console.print(f"  mcpradar plugin validate {created}")


@plugin_app.command(name="validate")
def plugin_validate(
    directory: Path = typer.Argument(  # noqa: B008
        help="Plugin dizini (ornek: ./plugins/mcpradar-rule-my-custom)",
    ),
    run_tests: bool = typer.Option(  # noqa: B008
        False,
        "--run-tests",
        "-t",
        help="pytest ile testleri de calistir",
    ),
) -> None:
    """Plugin yapisini dogrula."""
    from mcpradar.output.console import console
    from mcpradar.plugin.validator import PluginValidator

    if not directory.exists():
        console.print(f"[red]Dizin bulunamadi: {directory}[/]")
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
        console.print("  [green][✓][/] Testler basarili")
    elif report.tests_passed is False:
        console.print("  [red][✗][/] Testler basarisiz")

    if report.is_valid:
        console.print("\n[green]Tum kontroller basarili.[/]")
    else:
        console.print("\n[red]Bazi kontroller basarisiz.[/]")
        raise typer.Exit(code=1)


@plugin_app.command(name="list")
def plugin_list() -> None:
    """Yuklu community plugin'leri listele."""
    from rich.table import Table

    from mcpradar.output.console import console
    from mcpradar.plugin.manager import PluginManager

    manager = PluginManager()
    plugins = manager.list_plugins()

    if not plugins:
        console.print("[dim]Henuz hic community plugin yuklu degil.[/]")
        console.print("[dim]Plugin kurmak icin: mcpradar plugin install <paket>[/]")
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
    package: str = typer.Argument(help="Paket ismi (ornek: mcpradar-rule-sqli)"),
) -> None:
    """Bir community plugin'i pip ile kur ve dogrula."""
    from mcpradar.output.console import console
    from mcpradar.plugin.manager import PluginManager

    manager = PluginManager()
    console.print(f"[dim]{package} kuruluyor...[/]")
    success, message = manager.install(package)

    if success:
        console.print(f"[green]OK[/] {message}")
    else:
        console.print(f"[red]Hata:[/] {message}")
        raise typer.Exit(code=1)


@plugin_app.command(name="uninstall")
def plugin_uninstall(
    package: str = typer.Argument(help="Paket ismi"),
) -> None:
    """Bir community plugin'i kaldir."""
    from mcpradar.output.console import console
    from mcpradar.plugin.manager import PluginManager

    manager = PluginManager()
    console.print(f"[dim]{package} kaldiriliyor...[/]")
    success, message = manager.uninstall(package)

    if success:
        console.print(f"[green]OK[/] {message}")
    else:
        console.print(f"[red]Hata:[/] {message}")
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# fingerprint
# ---------------------------------------------------------------------------

fingerprint_app = typer.Typer(
    help="Server fingerprint and identity tracking", no_args_is_help=True
)
app.add_typer(fingerprint_app, name="fingerprint")


@fingerprint_app.command(name="create")
def fingerprint_create(
    target: str = typer.Argument(help="MCP sunucu adresi"),
    transport: str = typer.Option(  # noqa: B008
        "http",
        "--transport",
        "-t",
        help="Transport protokolu (http, sse, stdio)",
    ),
) -> None:
    """Sunucu parmak izi olustur ve kaydet."""
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
    with console.status(f"[bold blue]{target}[/] taranıyor..."):
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
    console.print("\n[bold]Parmak Izi (Fingerprint)[/]")
    console.print(f"  Server ID:      [bold cyan]{fp.server_id}[/]")
    console.print(f"  Endpoint:       {fp.endpoint}")
    console.print(f"  Transport:      {fp.transport}")
    console.print(f"  Server Version: {fp.server_version or '(bilinmiyor)'}")
    console.print(f"  Protocol:       {fp.protocol_version or '(bilinmiyor)'}")
    console.print(f"  Tool Count:     {fp.tool_count}")
    console.print(f"  Tools Hash:     [dim]{fp.tool_names_hash[:16]}...[/]")
    if tls_info and tls_info.version != "N/A":
        console.print(f"  TLS Version:    {tls_info.version}")
        if tls_info.cert_issuer:
            console.print(f"  Cert Issuer:    {tls_info.cert_issuer}")
        cert_ok = "[green]Evet[/]" if tls_info.cert_valid else "[red]Hayir[/]"
        console.print(f"  Cert Valid:     {cert_ok}")
        ss_ok = "[yellow]Evet[/]" if tls_info.self_signed else "[green]Hayir[/]"
        console.print(f"  Self-Signed:    {ss_ok}")
    elif tls_info and tls_info.version == "plain":
        console.print("  TLS:            [red]Plain HTTP (sifresiz)[/]")

    console.print("\n[green]Parmak izi kaydedildi.[/]")
    console.print(f"Karsilastirma icin: mcpradar fingerprint compare {target} -t {transport}")


@fingerprint_app.command(name="compare")
def fingerprint_compare(
    target: str = typer.Argument(help="MCP sunucu adresi"),
    transport: str = typer.Option(  # noqa: B008
        "http",
        "--transport",
        "-t",
        help="Transport protokolu (http, sse, stdio)",
    ),
) -> None:
    """Onceki parmak izi ile karsilastir."""
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
        console.print("[yellow]Bu sunucu icin daha once parmak izi kaydi yok.[/]")
        console.print(
            f"Parmak izi olusturmak icin: "
            f"mcpradar fingerprint create {target} -t {transport}"
        )
        return

    # Current scan
    sev = Severity.from_str("low")
    scanner = Scanner(target=target, transport=transport, min_severity=sev)
    with console.status(f"[bold blue]{target}[/] taranıyor..."):
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
    console.print("\n[bold]Parmak Izi Karsilastirmasi[/]")
    console.print(f"  [dim]Onceki:[/] {baseline.first_seen}")
    console.print(f"  [dim]Simdi: [/] {current.first_seen}")

    if diff.is_first_scan:
        console.print("\n[yellow]Ilk tarama — karsilastirma yapilamadi.[/]")
        return

    if not any([
        diff.tool_names_changed, diff.version_change, diff.protocol_changed,
        diff.capabilities_changed, diff.tls_changed, diff.endpoint_changed,
    ]):
        console.print("\n[green]Degisiklik tespit edilmedi.[/]")
        return

    console.print("\n[bold]Tespit Edilen Degisiklikler:[/]")

    if diff.version_change:
        color = "red" if diff.version_change == "rollback" else "yellow"
        label = {
            "rollback": "SURUM DUSURME (rollback)",
            "major_upgrade": "Major surum atlamasi",
            "minor_upgrade": "Minor surum degisikligi",
        }.get(diff.version_change, diff.version_change)
        console.print(
            f"  [{color}][!][/] {label}: "
            f"{diff.previous_version} → {diff.current_version}"
        )

    if diff.tool_names_changed:
        console.print("  [yellow][!][/] Tool listesi degisti")

    if diff.tls_downgrade:
        console.print("  [red][!][/] TLS downgrade tespit edildi")
    elif diff.tls_changed:
        console.print("  [yellow][!][/] TLS bilgisi degisti")

    if diff.endpoint_changed:
        console.print("  [red][!][/] Sunucu adresi degisti")

    if diff.protocol_changed:
        console.print("  [dim][i][/] MCP protokol versiyonu degisti")

    if diff.capabilities_changed:
        console.print("  [dim][i][/] Yetenekler (capabilities) degisti")


@fingerprint_app.command(name="list")
def fingerprint_list() -> None:
    """Kayitli parmak izlerini listele."""
    from rich.table import Table

    from mcpradar.output.console import console
    from mcpradar.storage.store import Store

    store = Store()
    fingerprints = store.list_fingerprints()

    if not fingerprints:
        console.print("[dim]Henuz hic parmak izi kaydi yok.[/]")
        console.print("[dim]Parmak izi olusturmak icin: mcpradar fingerprint create <hedef>[/]")
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
# watch
# ---------------------------------------------------------------------------


@app.command()
def watch(
    target: str = typer.Argument(help="MCP server URL veya stdio komutu"),
    transport: str = typer.Option(  # noqa: B008
        "http", "--transport", "-t", help="Transport tipi: http, sse, stdio"
    ),
    interval: int = typer.Option(  # noqa: B008
        300, "--interval", "-i", help="Tarama araligi (saniye, varsayilan 300)"
    ),
    alert_cmd: str | None = typer.Option(  # noqa: B008
        None,
        "--alert-cmd",
        "-c",
        help="Değişiklikte çalıştırılacak komut (shlex, shell=False)",
    ),
    alert_webhook: str | None = typer.Option(  # noqa: B008
        None, "--alert-webhook", "-w", help="Degisiklikte POST yapilacak webhook URL"
    ),
) -> None:
    """MCP server'i periyodik olarak tara, degisiklikleri bildir."""
    from mcpradar.output.console import console
    from mcpradar.watch.watcher import Watcher

    watcher = Watcher(
        target,
        transport=transport,
        interval=interval,
        alert_cmd=alert_cmd,
        alert_webhook=alert_webhook,
    )

    console.print(f"[bold]mcpradar watch baslatildi: {target}[/]")
    console.print(f"[dim]Aralik: {interval}s | Cikmak icin Ctrl+C[/]\n")

    try:
        asyncio.run(watcher.run())
    except KeyboardInterrupt:
        console.print("\n[dim]Watch durduruldu.[/]")


# ---------------------------------------------------------------------------
# registry-scan
# ---------------------------------------------------------------------------


@app.command()
def registry_scan(
    output: Path = typer.Option(  # noqa: B008
        Path("leaderboard.md"),
        "--output",
        "-o",
        help="Markdown çıktı dosyası",
    ),
) -> None:
    """Popüler MCP sunucu kayıtlarını tara ve leaderboard oluştur."""
    from mcpradar.output.console import console
    from mcpradar.registry.scanner import render_leaderboard, scan_registry

    console.print("[bold]MCP Registry Scan[/]\n")
    results = scan_registry()
    md = render_leaderboard(results)
    output.write_text(md, encoding="utf-8")
    console.print(md)
    console.print(f"\n[green]Leaderboard: {output}[/]")


# ---------------------------------------------------------------------------
# feed
# ---------------------------------------------------------------------------


@app.command()
def feed_update() -> None:
    """CVE feed'ini güncelle (MCP-related CVE'ler)."""
    from mcpradar.cvefeed.syncer import save_feed, sync_feed
    from mcpradar.output.console import console

    entries = sync_feed()
    save_feed(entries)
    console.print(
        f"[green]{len(entries)} CVE synced.[/]"
    )


# init
# ---------------------------------------------------------------------------


@app.command()
def init(
    path: Path = typer.Option(  # noqa: B008
        Path("mcpradar.toml"), "--output", "-o", help="Konfigurasyon dosyasi yolu"
    ),
) -> None:
    """mcpradar.toml konfigürasyon dosyası oluştur."""
    from mcpradar.init.initializer import Initializer
    from mcpradar.output.console import console

    init_ = Initializer()
    init_.generate(path)
    console.print(f"[green]OK[/] Konfigürasyon dosyası oluşturuldu: [bold]{path}[/]")
