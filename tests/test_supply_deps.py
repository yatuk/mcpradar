"""Tests for dependency extraction and OSV vulnerability matching."""

from __future__ import annotations

import json
from pathlib import Path

from mcpradar.cvefeed.osv import OSVVulnerability, _cvss_base_score
from mcpradar.scanner.report import Severity
from mcpradar.supply import extract_dependencies, scan_dependencies
from mcpradar.supply.deps import _clean_version, _severity_from_score


class TestVersionCleaning:
    def test_npm_range_prefixes(self) -> None:
        assert _clean_version("^1.2.3") == "1.2.3"
        assert _clean_version("~4.12.0") == "4.12.0"
        assert _clean_version(">=2.31.0,<3") == "2.31.0"

    def test_unpinned_returns_none(self) -> None:
        assert _clean_version("*") is None
        assert _clean_version("latest") is None
        assert _clean_version("") is None


class TestExtraction:
    def test_package_json(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(
            json.dumps(
                {
                    "dependencies": {"axios": "^0.21.1", "left-pad": "1.3.0"},
                    "devDependencies": {"jest": "^29.0.0"},
                }
            ),
            encoding="utf-8",
        )
        deps = extract_dependencies(tmp_path)
        names = {(d.ecosystem, d.name, d.version) for d in deps}
        assert ("npm", "axios", "0.21.1") in names
        assert ("npm", "jest", "29.0.0") in names

    def test_requirements_txt(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text(
            "requests==2.31.0\n# comment\npyyaml>=6.0\n-e .\n", encoding="utf-8"
        )
        deps = extract_dependencies(tmp_path)
        names = {(d.name, d.version) for d in deps}
        assert ("requests", "2.31.0") in names
        assert ("pyyaml", "6.0") in names

    def test_pyproject(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["httpx>=0.28", "rich>=13.0,<14"]\n',
            encoding="utf-8",
        )
        deps = extract_dependencies(tmp_path)
        assert ("PyPI", "httpx", "0.28") in {(d.ecosystem, d.name, d.version) for d in deps}

    def test_lockfile_preferred_over_manifest(self, tmp_path: Path) -> None:
        # Both present: exact lock version wins, manifest range is skipped.
        (tmp_path / "package.json").write_text(
            json.dumps({"dependencies": {"axios": "^0.21.0"}}), encoding="utf-8"
        )
        (tmp_path / "package-lock.json").write_text(
            json.dumps({"packages": {"node_modules/axios": {"version": "0.21.4"}}}),
            encoding="utf-8",
        )
        deps = [d for d in extract_dependencies(tmp_path) if d.name == "axios"]
        assert len(deps) == 1
        assert deps[0].version == "0.21.4"
        assert deps[0].source == "package-lock.json"

    def test_pnpm_lock(self, tmp_path: Path) -> None:
        (tmp_path / "pnpm-lock.yaml").write_text(
            """
lockfileVersion: '9.0'
packages:
  axios@1.7.9:
    resolution:
      integrity: sha512-YWJj
""",
            encoding="utf-8",
        )
        deps = extract_dependencies(tmp_path)
        assert [(dep.name, dep.version, dep.source) for dep in deps] == [
            ("axios", "1.7.9", "pnpm-lock.yaml")
        ]

    def test_yarn_lock(self, tmp_path: Path) -> None:
        (tmp_path / "yarn.lock").write_text(
            'axios@^1.7.0:\n  version "1.7.9"\n  integrity sha512-YWJj\n',
            encoding="utf-8",
        )
        deps = extract_dependencies(tmp_path)
        assert [(dep.name, dep.version, dep.source) for dep in deps] == [
            ("axios", "1.7.9", "yarn.lock")
        ]

    def test_pdm_lock(self, tmp_path: Path) -> None:
        (tmp_path / "pdm.lock").write_text(
            '[[package]]\nname = "httpx"\nversion = "0.28.1"\n',
            encoding="utf-8",
        )
        deps = extract_dependencies(tmp_path)
        assert [(dep.name, dep.version, dep.source) for dep in deps] == [
            ("httpx", "0.28.1", "pdm.lock")
        ]


class TestCvss:
    def test_known_critical_vector(self) -> None:
        score = _cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert score == 9.8

    def test_known_low_vector(self) -> None:
        assert _cvss_base_score("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N") == 2.6

    def test_non_cvss_returns_none(self) -> None:
        assert _cvss_base_score("not a vector") is None

    def test_severity_from_score(self) -> None:
        assert _severity_from_score(9.8) == Severity.CRITICAL
        assert _severity_from_score(7.5) == Severity.HIGH
        assert _severity_from_score(5.0) == Severity.MEDIUM
        assert _severity_from_score(2.0) == Severity.LOW
        assert _severity_from_score(None) == Severity.MEDIUM


class _FakeOSV:
    """Fake OSV client: axios@0.21.1 is vulnerable, everything else clean."""

    def __init__(self) -> None:
        self._vuln = OSVVulnerability(
            id="GHSA-xxxx",
            summary="SSRF in axios",
            details="",
            aliases=["CVE-2021-3749"],
            severity_score=7.5,
            severity_vector="CVSS:3.1/...",
            cwe_ids=["CWE-918"],
            fixed_version="0.21.2",
            affected_versions=["0.21.1"],
            references=["https://example.com"],
        )

    def query_batch(self, queries):
        out = {}
        for _eco, name, _ver in queries:
            if name == "axios":
                out[name] = [OSVVulnerability("GHSA-xxxx", "", "", [], None, "", [], None, [], [])]
            else:
                out[name] = []
        return out

    def get_vuln(self, vuln_id):
        return self._vuln if vuln_id == "GHSA-xxxx" else None


class TestScanDependencies:
    def test_vulnerable_dep_becomes_finding(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(
            json.dumps({"dependencies": {"axios": "0.21.1", "safe-pkg": "1.0.0"}}),
            encoding="utf-8",
        )
        deps, findings = scan_dependencies(tmp_path, client=_FakeOSV())
        assert len(deps) == 2
        d001 = [f for f in findings if f.rule_id == "D001"]
        assert len(d001) == 1
        f = d001[0]
        assert f.severity == Severity.HIGH  # hydrated CVSS 7.5
        assert f.detail["cve"] == "CVE-2021-3749"
        assert f.detail["fixed_version"] == "0.21.2"
        assert "axios@0.21.1" in f.target

    def test_no_deps_no_findings(self, tmp_path: Path) -> None:
        deps, findings = scan_dependencies(tmp_path, client=_FakeOSV())
        assert deps == []
        assert findings == []
