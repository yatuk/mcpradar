"""JavaScript/TypeScript static-analysis coverage."""

from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired

from mcpradar.source import analyze_path
from mcpradar.source.javascript import JavaScriptAnalyzer


def test_javascript_dangerous_sinks_are_detected(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("mcpradar.source.javascript.shutil.which", lambda _name: None)
    source = tmp_path / "server.ts"
    source.write_text(
        """
import { exec } from "child_process";
export async function tool(url: string, command: string) {
  const response = await fetch(url);
  exec(command);
  eval(command);
  return await fetch(url);
}
""",
        encoding="utf-8",
    )
    findings = JavaScriptAnalyzer().analyze_file(source)
    rule_ids = {finding.rule_id for finding in findings}
    assert {"S002", "S004", "S006", "S011"} <= rule_ids


def test_npm_style_directory_scans_js_and_ts(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("mcpradar.source.javascript.shutil.which", lambda _name: None)
    (tmp_path / "index.js").write_text("fetch(userUrl);", encoding="utf-8")
    (tmp_path / "server.ts").write_text("eval(input);", encoding="utf-8")
    result = analyze_path(tmp_path)
    assert result.files_scanned == 2
    assert result.files_by_language == {"javascript": 2}
    assert {finding.rule_id for finding in result.findings} >= {"S002", "S004"}


def test_node_modules_are_excluded(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("mcpradar.source.javascript.shutil.which", lambda _name: None)
    modules = tmp_path / "node_modules" / "dep"
    modules.mkdir(parents=True)
    (modules / "index.js").write_text("eval(input);", encoding="utf-8")
    assert analyze_path(tmp_path).files_scanned == 0


def test_semgrep_results_and_unicode_are_combined(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "server.js"
    source.write_text("const hidden = '\u202e';", encoding="utf-8")
    payload = {
        "results": [
            {
                "check_id": "mcpradar.S006",
                "start": {"line": 7},
                "extra": {
                    "message": "dynamic command",
                    "metadata": {"mcpradar_severity": "critical"},
                },
            }
        ]
    }
    monkeypatch.setattr("mcpradar.source.javascript.shutil.which", lambda _name: "semgrep")
    monkeypatch.setattr(
        "mcpradar.source.javascript.subprocess.run",
        lambda *_args, **_kwargs: CompletedProcess([], 0, __import__("json").dumps(payload), ""),
    )
    findings = JavaScriptAnalyzer().analyze_file(source)
    assert {(finding.rule_id, finding.detail["line"]) for finding in findings} == {
        ("S006", 7),
        ("S008", 1),
    }


def test_semgrep_failures_fall_back_to_builtin(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "server.ts"
    source.write_text("fetch(userUrl);", encoding="utf-8")
    analyzer = JavaScriptAnalyzer()
    monkeypatch.setattr("mcpradar.source.javascript.shutil.which", lambda _name: "semgrep")
    for outcome in (
        CompletedProcess([], 2, "", "failed"),
        CompletedProcess([], 0, "not-json", ""),
        TimeoutExpired("semgrep", 30),
    ):
        if isinstance(outcome, BaseException):
            monkeypatch.setattr(
                "mcpradar.source.javascript.subprocess.run",
                lambda *_args, _outcome=outcome, **_kwargs: (_ for _ in ()).throw(_outcome),
            )
        else:
            monkeypatch.setattr(
                "mcpradar.source.javascript.subprocess.run",
                lambda *_args, _outcome=outcome, **_kwargs: _outcome,
            )
        assert {finding.rule_id for finding in analyzer.analyze_file(source)} == {"S002"}


def test_builtin_detects_all_js_rule_patterns(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("mcpradar.source.javascript.shutil.which", lambda _name: None)
    source = tmp_path / "server.cjs"
    source.write_text(
        "\n".join(
            [
                "fetch('http://169.254.169.254/latest');",
                "fetch('https://metadata.google.internal/compute');",
                "db.query(`SELECT * FROM users WHERE id=${user}`);",
                "authorization = token; fetch(url);",
                "const app = { host: '0.0.0.0' };",
            ]
        ),
        encoding="utf-8",
    )
    assert {finding.rule_id for finding in JavaScriptAnalyzer().analyze_file(source)} >= {
        "S001",
        "S005",
        "S009",
        "S010",
    }


def test_non_javascript_and_unreadable_files_are_ignored(tmp_path: Path, monkeypatch) -> None:
    assert JavaScriptAnalyzer().analyze_file(tmp_path / "server.py") == []
    missing = tmp_path / "missing.js"
    monkeypatch.setattr("mcpradar.source.javascript.shutil.which", lambda _name: None)
    assert JavaScriptAnalyzer().analyze_file(missing) == []
