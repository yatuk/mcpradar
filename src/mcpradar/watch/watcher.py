"""Periodic scanning and change notification — SQLite support."""

from __future__ import annotations

import asyncio
import contextlib
import shlex
import subprocess
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from mcpradar.audit.auditor import AuditLogger

from mcpradar.scanner.engine import Scanner
from mcpradar.scanner.report import ScanReport
from mcpradar.storage.store import Store


class Watcher:
    def __init__(
        self,
        target: str,
        transport: str = "http",
        interval: int = 300,
        alert_cmd: str | None = None,
        alert_webhook: str | None = None,
        audit: AuditLogger | None = None,
    ) -> None:
        self.target = target
        self.transport = transport
        self.interval = interval
        self.alert_cmd = alert_cmd
        self.alert_webhook = alert_webhook
        self.audit = audit
        self.last_report: ScanReport | None = None
        self._store = Store()

    async def run(self) -> None:
        from mcpradar.diff.differ import Differ
        from mcpradar.output.console import console

        scanner = Scanner(
            self.target,
            transport=self.transport,
            audit=self.audit,
        )

        try:
            while True:
                report = await scanner.run()
                console.print_report(report)

                self._store.save(report)

                if self.last_report is not None:
                    differ = Differ()
                    delta = differ.compare(self.last_report, report)
                    if delta.has_changes:
                        console.print("\n[bold yellow][!] Change detected![/]")
                        console.print_diff(delta)
                        if self.audit:
                            counts = delta.summary_counts()
                            self.audit.log_diff(
                                report.target,
                                sum(counts.values()),
                                counts.get("security", 0),
                            )
                        if self.alert_cmd:
                            self._run_alert(delta)
                            if self.audit:
                                self.audit.log_alert(self.target, "shell_cmd")
                        if self.alert_webhook:
                            self._run_webhook(delta)
                            if self.audit:
                                self.audit.log_alert(self.target, "webhook")

                self.last_report = report
                await asyncio.sleep(self.interval)
        finally:
            self._store.close()

    def _run_alert(self, delta: Any) -> None:
        import json

        with contextlib.suppress(Exception):
            if not self.alert_cmd:
                return
            cmd_parts = shlex.split(self.alert_cmd)
            subprocess.run(
                cmd_parts,
                input=json.dumps(delta.to_dict()),
                text=True,
                timeout=30,
                shell=False,
            )

    def _run_webhook(self, delta: Any) -> None:
        if not self.alert_webhook:
            return
        with contextlib.suppress(Exception):
            httpx.post(
                self.alert_webhook,
                json=delta.to_dict(),
                timeout=10,
            )
