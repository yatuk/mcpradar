"""Diff modulu testleri — SQLite destegi."""

from mcpradar.diff.differ import ChangeSeverity, Differ
from mcpradar.scanner.report import Finding, ScanReport, Severity, ToolInfo


class TestDiffer:
    def test_added_tool(self) -> None:
        a = ScanReport(id="a")
        a.tools.append(ToolInfo(name="weather", description="Get weather"))

        b = ScanReport(id="b")
        b.tools.append(ToolInfo(name="weather", description="Get weather"))
        b.tools.append(ToolInfo(name="eval", description="Run code"))

        differ = Differ()
        delta = differ.compare(a, b)

        added_names = [td.tool_name for td in delta.tool_diffs if td.added]
        assert "eval" in added_names
        assert len(added_names) == 1

    def test_removed_tool(self) -> None:
        a = ScanReport(id="a")
        a.tools.append(ToolInfo(name="weather", description="Get weather"))
        a.tools.append(ToolInfo(name="old_tool", description="Old"))

        b = ScanReport(id="b")
        b.tools.append(ToolInfo(name="weather", description="Get weather"))

        differ = Differ()
        delta = differ.compare(a, b)

        removed_names = [td.tool_name for td in delta.tool_diffs if td.removed]
        assert "old_tool" in removed_names

    def test_changed_description(self) -> None:
        a = ScanReport(id="a")
        a.tools.append(ToolInfo(name="api", description="Old desc"))

        b = ScanReport(id="b")
        b.tools.append(ToolInfo(name="api", description="New desc"))

        differ = Differ()
        delta = differ.compare(a, b)

        changed = [td for td in delta.tool_diffs if not td.added and not td.removed]
        assert len(changed) == 1
        assert changed[0].tool_name == "api"
        assert any(c.field == "description" for c in changed[0].changes)

    def test_no_changes(self) -> None:
        a = ScanReport(id="a")
        a.tools.append(ToolInfo(name="api", description="Same"))

        b = ScanReport(id="b")
        b.tools.append(ToolInfo(name="api", description="Same"))

        differ = Differ()
        delta = differ.compare(a, b)

        assert not delta.has_changes

    def test_new_finding(self) -> None:
        a = ScanReport(id="a")
        b = ScanReport(id="b")
        b.add_finding(
            Finding(
                rule_id="R001",
                title="Bad",
                description="Found",
                severity=Severity.CRITICAL,
                target="bad_tool",
            )
        )

        differ = Differ()
        delta = differ.compare(a, b)

        assert len(delta.new_findings) == 1

    def test_change_severity_cosmetic_description(self) -> None:
        a = ScanReport(id="a")
        a.tools.append(ToolInfo(name="x", description="Old"))

        b = ScanReport(id="b")
        b.tools.append(ToolInfo(name="x", description="New"))

        differ = Differ()
        delta = differ.compare(a, b)

        changed = [td for td in delta.tool_diffs if not td.added and not td.removed]
        assert len(changed) == 1
        assert changed[0].max_severity == ChangeSeverity.COSMETIC

    def test_change_severity_security_schema(self) -> None:
        a = ScanReport(id="a")
        a.tools.append(
            ToolInfo(
                name="x",
                description="desc",
                input_schema={"properties": {"safe": {"type": "string"}}},
            )
        )

        b = ScanReport(id="b")
        b.tools.append(
            ToolInfo(
                name="x",
                description="desc",
                input_schema={
                    "properties": {
                        "safe": {"type": "string"},
                        "command": {"type": "string"},
                    }
                },
            )
        )

        differ = Differ()
        delta = differ.compare(a, b)

        changed = [td for td in delta.tool_diffs if not td.added and not td.removed]
        assert len(changed) == 1
        assert changed[0].max_severity == ChangeSeverity.SECURITY

    def test_summary_counts(self) -> None:
        a = ScanReport(id="a")
        b = ScanReport(id="b")
        b.tools.append(ToolInfo(name="new_tool", description="Added"))

        differ = Differ()
        delta = differ.compare(a, b)

        assert delta.summary_counts()["added"] == 1

    def test_to_dict(self) -> None:
        a = ScanReport(id="a", target="srv")
        b = ScanReport(id="b", target="srv")
        b.tools.append(ToolInfo(name="new_tool", description="Added"))

        differ = Differ()
        delta = differ.compare(a, b)
        d = delta.to_dict()

        assert d["server"] == "srv"
        assert len(d["tool_diffs"]) == 1
        assert d["tool_diffs"][0]["added"] is True
