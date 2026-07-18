# Policy as code

MCPRadar policy files are strict YAML. Unknown keys, unknown rule IDs, malformed
dates, and incomplete suppression records are rejected instead of ignored.

```yaml
version: "1"
fail_on: high
deny_rules: [R106, S004, S006]
max_risk_score: 4.9
require_complete_scan: true
suppressions:
  - rule_id: R113
    target: read_project_file
    expires: 2026-09-30
    owner: appsec@example.com
    justification: Path is confined by a separately reviewed server allowlist.
```

`fail_on` is the minimum unsuppressed severity that fails. `deny_rules` fails on
the named rule regardless of its default severity. `max_risk_score` applies to
MRS-v1 after active suppressions are removed. An incomplete scan fails by
default because missing enumeration cannot prove a clean result.

Suppressions are matched by rule ID and shell-style target glob. Expired
suppressions both stop hiding findings and create an `expired-suppression`
violation, making stale exceptions visible in CI.

```bash
mcpradar policy check mcpradar-policy.yml --report scan.json
```
