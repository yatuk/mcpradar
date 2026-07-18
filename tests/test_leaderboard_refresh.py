"""Daily leaderboard refresh: pending discovery, safety, and honest status."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from validation import run_trending


def _write(path: Path, data: dict) -> None:  # noqa: ANN401
    path.write_text(json.dumps(data), encoding="utf-8")


def test_load_target_commands_accepts_scan_and_command(tmp_path: Path) -> None:
    targets = tmp_path / "targets.yaml"
    targets.write_text(
        """servers:
  - name: first
    scan: npx -y first
  - name: second
    command: uvx second
  - name: empty
""",
        encoding="utf-8",
    )
    assert run_trending.load_target_commands(targets) == {
        "first": "npx -y first",
        "second": "uvx second",
    }


def test_load_target_commands_normalizes_install_pipeline(tmp_path: Path) -> None:
    targets = tmp_path / "targets.yaml"
    targets.write_text(
        "servers:\n  - name: py\n    scan: pip install py-mcp && python -m py_mcp\n",
        encoding="utf-8",
    )
    assert run_trending.load_target_commands(targets) == {"py": "uvx py-mcp"}


def test_collect_pending_deduplicates_and_skips_scanned_copy(tmp_path: Path) -> None:
    results = tmp_path / "results"
    results.mkdir()
    targets = tmp_path / "targets.yaml"
    targets.write_text(
        "servers:\n  - name: pending\n    scan: npx -y pending\n",
        encoding="utf-8",
    )
    _write(results / "pending.json", {"name": "pending", "status": "registry-pending"})
    _write(results / "unmapped.json", {"name": "unmapped", "status": "registry-pending"})
    _write(results / "done-stub.json", {"name": "done", "status": "registry-pending"})
    _write(results / "done.json", {"name": "done", "scanned_at": "2026-01-01", "tools": []})
    _write(
        results / "scoped.json",
        {"target": "npx -y @scope/scanned", "scanned_at": "2026-01-01", "tools": []},
    )
    _write(
        results / "scoped-stub.json",
        {"name": "@scope/scanned", "status": "registry-pending"},
    )

    pending, unmapped = run_trending.collect_pending_targets(
        results,
        targets,
        now=datetime(2026, 7, 18, tzinfo=UTC),
    )
    assert [(item.name, item.command) for item in pending] == [("pending", "npx -y pending")]
    assert unmapped == ["unmapped"]


def test_collect_pending_honors_incomplete_retry_cooldown(tmp_path: Path) -> None:
    results = tmp_path / "results"
    results.mkdir()
    targets = tmp_path / "targets.yaml"
    targets.write_text("servers:\n  - name: x\n    scan: npx -y x\n", encoding="utf-8")
    _write(
        results / "x.json",
        {
            "name": "x",
            "incomplete": True,
            "last_attempted_at": "2026-07-17T00:00:00+00:00",
        },
    )
    _write(results / "x-stale.json", {"name": "x", "status": "registry-pending"})
    pending, _ = run_trending.collect_pending_targets(
        results,
        targets,
        retry_after_days=7,
        now=datetime(2026, 7, 18, tzinfo=UTC),
    )
    assert pending == []


@pytest.mark.parametrize(
    ("kind", "identifier", "version", "expected"),
    [
        ("npm", "@scope/server", "1.2.3", "npx -y @scope/server@1.2.3"),
        ("pypi", "mcp_server", "2.0", "uvx mcp_server==2.0"),
        ("npm", "server;whoami", "1", None),
    ],
)
def test_package_command_is_pinned_and_rejects_shell_metacharacters(
    kind: str, identifier: str, version: str, expected: str | None
) -> None:
    assert run_trending._package_command(kind, identifier, version) == expected


def test_scan_target_marks_failed_empty_scan_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        run_trending,
        "_live_scan",
        lambda *args, **kwargs: run_trending.ScanAttempt(None, "launch failed"),
    )
    monkeypatch.setattr(
        "mcpradar.enrich.enrich_result",
        lambda data: (False, "fetch failed"),
    )
    target = run_trending.ScanTarget("x", "npx -y x", tmp_path / "x.json")
    result = run_trending.scan_target(target, 10, allow_host_exec=False)
    saved = json.loads(target.output.read_text(encoding="utf-8"))
    assert result.coverage == "incomplete"
    assert saved["status"] == "incomplete"
    assert saved["incomplete"] is True
    assert saved["live_scan"] == {"ok": False, "error": "launch failed"}


def test_scan_target_keeps_package_findings_when_live_launch_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        run_trending,
        "_live_scan",
        lambda *args, **kwargs: run_trending.ScanAttempt(None, "needs API key"),
    )

    def enrich(data: dict) -> tuple[bool, str]:
        data["findings"].append({"rule_id": "D001", "severity": "high", "target": "dependency"})
        return True, "+1 finding"

    monkeypatch.setattr("mcpradar.enrich.enrich_result", enrich)
    target = run_trending.ScanTarget("x", "npx -y x", tmp_path / "x.json")
    result = run_trending.scan_target(target, 10, allow_host_exec=False)
    saved = json.loads(target.output.read_text(encoding="utf-8"))
    assert result.coverage == "package-only"
    assert saved["status"] == "scanned"
    assert saved["scan_coverage"] == "package-only"
    assert saved["findings"][0]["rule_id"] == "D001"


def test_retire_old_trending_preserves_scan(tmp_path: Path) -> None:
    old = tmp_path / "trending_old.json"
    current = tmp_path / "trending_current.json"
    _write(old, {"name": "old", "trending": True, "tools": [{"name": "x"}]})
    _write(current, {"name": "current", "trending": True})
    assert run_trending.retire_old_trending({"current"}, tmp_path) == 1
    assert json.loads(old.read_text(encoding="utf-8"))["trending"] is False
    assert json.loads(current.read_text(encoding="utf-8"))["trending"] is True
