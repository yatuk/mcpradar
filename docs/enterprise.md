# MCPRadar Enterprise Integration Guide

How to integrate MCPRadar security scan data into enterprise SOC/SIEM workflows.

## Data Sources

MCPRadar provides several machine-readable data formats:

| Format | URL / Command | Use Case |
|--------|--------------|----------|
| `data.json` | `https://yatuk.github.io/mcpradar/data.json` | Dashboard ingestion, automated polling |
| SARIF v2.1.0 | Detail page "Download SARIF" button, or `mcpradar scan --format sarif` | SIEM/SOAR ingestion |
| CycloneDX SBOM | `mcpradar scan --format sbom` | Supply chain tracking |

## SIEM/SOAR Integration

### Splunk

1. Install the [SARIF Add-on for Splunk](https://splunkbase.splunk.com/)
2. Configure a scripted input to fetch the latest SARIF:
   ```bash
   curl -s https://yatuk.github.io/mcpradar/data.json | \
     python -c "..." > /opt/splunk/var/lib/splunk/mcpradar/mcp_scan_results.sarif
   ```
3. Create alerts on AIVSS score increases or new critical findings.

### Elastic Security

1. Use the SARIF-to-Elastic pipeline:
   ```bash
   curl -s https://yatuk.github.io/mcpradar/data.json | jq -r '
     .[] | select(.aivss_score > 5) |
     {server: .server, score: .aivss_score, grade: .grade}
   ' | python sarif_to_elastic.py --index mcpradar-findings
   ```
2. Create Kibana dashboards tracking AIVSS score trends per server.

### Microsoft Sentinel

1. Create a Logic Apps workflow triggered weekly.
2. HTTP action: `GET https://yatuk.github.io/mcpradar/data.json`
3. Parse JSON, filter for grade D or F servers.
4. Create Sentinel incidents for servers requiring attention.

## Automated Monitoring via CI

Poll `data.json` weekly in your CI pipeline:

```yaml
# .github/workflows/mcpradar-monitor.yml
name: MCPRadar Monitor
on:
  schedule:
    - cron: "0 8 * * 1"  # Every Monday
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -sO https://yatuk.github.io/mcpradar/data.json
          python -c "
          import json
          data = json.load(open('data.json'))
          risky = [s for s in data if s.get('aivss_score', 0) > 5]
          if risky:
              print(f'WARNING: {len(risky)} servers scored D or F')
              for s in risky:
                  print(f'  {s[\"server\"]}: {s[\"grade\"]} ({s[\"aivss_score\"]})')
          "
```

## Programmatic Diffing

Use `mcpradar audit diff` to compare scans over time:

```bash
# Compare latest two scans of a server
mcpradar audit diff @modelcontextprotocol/server-filesystem

# Export all findings as SARIF
mcpradar scan <target> --format sarif -o results.sarif
```

## Hash-Based Drift Detection

The `tool_hash` field in `data.json` is a SHA-256 of sorted tool names. Monitor this for unexpected changes:

```python
import json, hashlib

data = json.load(open("data.json"))
prev = json.load(open("data.prev.json"))
prev_hashes = {s["server"]: s["tool_hash"] for s in prev}

for s in data:
    if s["server"] in prev_hashes:
        if s["tool_hash"] != prev_hashes[s["server"]]:
            print(f"TOOL DRIFT: {s['server']} hash changed")
```

## Questions?

Open an issue: https://github.com/yatuk/mcpradar/issues
