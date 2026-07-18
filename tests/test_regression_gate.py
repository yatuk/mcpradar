"""Regression gate tests — validates MCPRadar against ground-truth corpus."""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"
CORPUS_PATH = FIXTURES_DIR / "cve_corpus.yaml"
GRADE_ORDER = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}


def load_corpus() -> list[dict]:
    import yaml  # lazy import — pyyaml only needed when running (not collecting)

    with open(CORPUS_PATH, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data.get("targets", [])


def scan_server(command: str, transport: str, timeout: int = 120) -> dict:
    """Scan a server via temp output file and return the JSON result dict.

    Uses -o/--output to write clean JSON (bypassing Rich console wrapping).
    """
    fd, tmp_path = tempfile.mkstemp(suffix=".json", prefix="mcpradar_test_")
    os.close(fd)
    try:
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "mcpradar",
                "scan",
                command,
                "-t",
                transport,
                "-s",
                "low",
                "--no-save",
                "--allow-host-exec",
                "-o",
                tmp_path,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=timeout,
        )
        if proc.returncode != 0:
            return {
                "error": f"exit code {proc.returncode}: {proc.stderr[:500]}",
            }
        with open(tmp_path, encoding="utf-8") as f:
            return json.load(f)
    except subprocess.TimeoutExpired:
        return {"error": f"scan timed out after {timeout}s"}
    except json.JSONDecodeError as e:
        return {"error": f"JSON parse failed in output file: {e}"}
    except OSError as e:
        return {"error": f"file IO error: {e}"}
    finally:
        with contextlib.suppress(OSError):
            Path(tmp_path).unlink(missing_ok=True)


def compute_grade(sev_counts: dict[str, int], tool_count: int) -> str:
    total = sum(sev_counts.values())
    if total == 0:
        return "A"
    tc = max(tool_count, 1)
    weighted = (
        sev_counts.get("critical", 0) * 10
        + sev_counts.get("high", 0) * 7
        + sev_counts.get("medium", 0) * 4
        + sev_counts.get("low", 0) * 1
    )
    density = total / tc
    density_factor = max(0.5, min(2.0, density * 5))
    raw = weighted / tc * density_factor
    score = min(10.0, round(raw, 1))
    if score <= 0.9:
        return "A"
    elif score <= 2.9:
        return "B"
    elif score <= 4.9:
        return "C"
    elif score <= 6.9:
        return "D"
    return "F"


class TestLayer1Pinned:
    @pytest.mark.network
    @pytest.mark.slow
    def test_filesystem_pre_patch(self) -> None:
        target = None
        for t in load_corpus():
            if (
                t["server"] == "@modelcontextprotocol/server-filesystem"
                and t["pinned_version"] != "latest"
            ):
                target = t
                break
        if target is None:
            pytest.skip("target not found")
        result = scan_server(target["scan_command"], target["transport"])
        assert "error" not in result, str(result.get("error"))
        findings = result.get("findings", [])
        tools = result.get("summary", {}).get("total_tools", 0)
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        detected = set()
        for f in findings:
            s = f.get("severity", "")
            if s in sev_counts:
                sev_counts[s] += 1
            detected.add(f.get("rule_id", ""))
        grade = compute_grade(sev_counts, tools)
        exp = target["expected"]
        assert len(findings) >= exp["min_findings"], f"{len(findings)} < {exp['min_findings']}"
        assert sev_counts["critical"] + sev_counts["high"] >= exp["min_critical_or_high"]
        assert GRADE_ORDER[grade] >= GRADE_ORDER[exp["max_grade"]], f"Grade {grade}"
        from mcpradar.cvefeed.osv import OSVClient

        osv = OSVClient()
        vulns = osv.query_package(
            target["package"]["ecosystem"], target["package"]["name"], target["pinned_version"]
        )
        found_cves = []
        for v in vulns:
            found_cves.extend(v.aliases)
        for cve in exp["cve_ids"]:
            assert cve in found_cves, f"{cve} not in {found_cves}"


class TestLayer2Latest:
    @pytest.mark.network
    @pytest.mark.slow
    def test_filesystem_latest(self) -> None:
        target = None
        for t in load_corpus():
            if (
                t["server"] == "@modelcontextprotocol/server-filesystem"
                and t["pinned_version"] == "latest"
            ):
                target = t
                break
        if target is None:
            pytest.skip("target not found")
        result = scan_server(target["scan_command"], target["transport"])
        assert "error" not in result, str(result.get("error"))
        findings = result.get("findings", [])
        tools = result.get("summary", {}).get("total_tools", 0)
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        detected = set()
        for f in findings:
            s = f.get("severity", "")
            if s in sev_counts:
                sev_counts[s] += 1
            detected.add(f.get("rule_id", ""))
        grade = compute_grade(sev_counts, tools)
        exp = target["expected"]
        assert len(findings) >= exp["min_findings"], (
            f"{len(findings)} < {exp['min_findings']}. Rules: {detected}"
        )
        for rule in exp["rules_triggered"]:
            assert rule in detected, f"{rule} missing. Detected: {detected}"
        assert GRADE_ORDER[grade] >= GRADE_ORDER[exp["max_grade"]], f"Grade {grade}"


class TestLayer3Benign:
    def test_benign_no_critical(self) -> None:
        target = None
        for t in load_corpus():
            if t["server"] == "benign-echo-server":
                target = t
                break
        if target is None:
            pytest.skip("target not found")
        result = scan_server(target["scan_command"], target["transport"])
        assert "error" not in result, str(result.get("error"))
        findings = result.get("findings", [])
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        assert critical == 0, (
            f"{critical} CRITICAL: {[(f['rule_id'], f['title']) for f in findings]}"
        )
        exp = target["expected"]
        if "max_findings" in exp:
            assert len(findings) <= exp["max_findings"], f"{len(findings)} > {exp['max_findings']}"
