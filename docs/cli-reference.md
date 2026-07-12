# CLI Reference

## Global Options

| Flag | Description |
|---|---|
| `--version`, `-v` | Print version and exit |
| `--help` | Show help for any command |

## Commands

### `mcpradar scan`

Scan a single MCP server.

| Argument/Flag | Type | Default | Description |
|---|---|---|---|
| `target` | TEXT | required | Server URL or stdio command |
| `--transport`, `-t` | TEXT | `http` | `http`, `sse`, or `stdio` |
| `--output`, `-o` | PATH | — | Save JSON output to file |
| `--severity`, `-s` | TEXT | `medium` | Min severity: `low`, `medium`, `high`, `critical` |
| `--format`, `-f` | TEXT | `rich` | Output format: `rich`, `json`, `sarif` |
| `--no-save` | FLAG | — | Skip saving to database |
| `--sandbox` | FLAG | — | Run stdio servers in a disposable container (egress locked, ephemeral FS) and validate probe arguments |
| `--sandbox-image` | TEXT | auto | Container image for `--sandbox` (default auto-picked: `python:3.12-slim` / `node:22-slim`) |
| `--sandbox-network` | TEXT | `none` | Container network for `--sandbox`: `none` (egress lock) or `bridge` (needed for npx/uvx package download) |

**Examples:**
```bash
mcpradar scan http://localhost:8080
mcpradar scan stdio -- npx -y @modelcontextprotocol/server-filesystem /tmp
mcpradar scan http://x -s critical -f json

# Isolate an untrusted stdio server in a disposable container
mcpradar scan "python ./suspicious_server.py" -t stdio --sandbox

# Allow network for launchers that download the package at startup
mcpradar scan "npx -y @scope/server" -t stdio --sandbox --sandbox-network bridge
```

The container sandbox requires a running Docker or Podman daemon. Docker is
preferred when both are present. Isolation applied per scan: `--rm` (ephemeral
container + filesystem), `--network none` by default (egress lock),
`--cap-drop ALL`, `--security-opt no-new-privileges`, and bounded
pids/memory/cpu. The current directory is mounted read-only at `/workspace` so
relative script paths resolve. `--sandbox` only wraps `stdio` scans; for
`http`/`sse` targets it just enables probe-argument validation.

### `mcpradar scan-all`

Scan all servers defined in `mcpradar.toml`.

| Flag | Type | Default | Description |
|---|---|---|---|
| `--config` | PATH | `mcpradar.toml` | Path to config file |
| `--parallel` | FLAG | — | Scan servers concurrently |
| `--max-concurrency`, `-c` | INT | `5` | Max concurrent scans |
| `--output`, `-o` | PATH | — | Output file (per-server JSON) |

### `mcpradar sbom`

Generate CycloneDX 1.5 SBOM.

| Flag | Type | Default | Description |
|---|---|---|---|
| `--output`, `-o` | PATH | — | Output file path |

### `mcpradar probe`

Safe runtime probing of read-only MCP tools.

| Argument/Flag | Type | Default | Description |
|---|---|---|---|
| `target` | TEXT | required | Server URL or command |
| `--transport`, `-t` | TEXT | `http` | Transport type |
| `--safe-only` | FLAG | True | Only probe read-only tools |
| `--all` | FLAG | — | Probe all tools (use with caution) |
| `--max` | INT | `20` | Maximum tools to probe |
| `--timeout` | FLOAT | `5.0` | Per-tool timeout in seconds |
| `--json` | FLAG | — | JSON output |
| `--severity`, `-s` | TEXT | `medium` | Min severity |

### `mcpradar analyze-context`

Cross-server context analysis.

| Flag | Type | Default | Description |
|---|---|---|---|
| `--config` | PATH | `mcpradar.toml` | Config file with servers |
| `--deep` | FLAG | — | Deep analysis (C006, C007) |
| `--graph`, `-g` | PATH | — | Export GraphViz DOT to file |

### `mcpradar diff`

Compare two snapshots.

| Argument/Flag | Type | Default | Description |
|---|---|---|---|
| `server` | TEXT | optional | Filter by server URL |
| `--snapshot-a` | TEXT | — | First scan ID |
| `--snapshot-b` | TEXT | — | Second scan ID |
| `--since` | TEXT | — | Compare with scan since this time |
| `--json` | FLAG | — | JSON output |
| `--output`, `-o` | PATH | — | Save report to file |

### `mcpradar watch`

Periodic scan + diff + alert.

| Flag | Type | Default | Description |
|---|---|---|---|
| `--interval`, `-i` | INT | `300` | Seconds between scans |
| `--alert-cmd` | TEXT | — | Shell command to run on diff |
| `--alert-webhook` | TEXT | — | Webhook URL to POST on diff |

### `mcpradar audit`

View and export the audit trail.

| Flag | Type | Default | Description |
|---|---|---|---|
| `--target` | TEXT | — | Filter by target URL |
| `--type` | TEXT | — | Filter by event type |
| `--since` | TEXT | — | Show events since (ISO or 7d/24h/1w) |
| `--limit`, `-n` | INT | `50` | Maximum events |
| `--json` | FLAG | — | JSON output |
| `--export`, `-o` | PATH | — | Export to file |

### `mcpradar stats`

Security statistics and trend analysis.

| Argument/Flag | Type | Default | Description |
|---|---|---|---|
| `target` | TEXT | optional | For per-server stats (omit for global) |
| `--days`, `-d` | INT | `30` | Trend analysis window |
| `--json` | FLAG | — | JSON output |

### `mcpradar cve`

CVE feed management (sub-commands: `sync`, `match`, `list`).

```bash
mcpradar cve sync                      # Full NVD API sync
mcpradar cve match <scan_id>           # Match findings to CVEs
mcpradar cve list --severity critical  # List cached CVEs
```

### `mcpradar fingerprint`

Server identity tracking.

```bash
mcpradar fingerprint create <target>   # Create fingerprint
mcpradar fingerprint compare <target>  # Compare with baseline
mcpradar fingerprint list              # List stored fingerprints
```

### `mcpradar plugin`

Plugin lifecycle management.

```bash
mcpradar plugin init <name>            # Scaffold new plugin
mcpradar plugin validate <dir>         # Validate plugin
mcpradar plugin list                   # List installed plugins
mcpradar plugin install <pkg>          # Install plugin
mcpradar plugin uninstall <pkg>        # Remove plugin
```

### Data Management Commands

```bash
mcpradar list [target] [-n 10]         # List scan snapshots
mcpradar show <scan_id>                # Show scan details
mcpradar export <scan_id> [-f json|sarif|csv] [-o output]  # Export scan
mcpradar purge [--older-than 30d] [--keep-last 10]         # Clean old scans
mcpradar init [-o path]                # Create mcpradar.toml
mcpradar registry-scan                  # Generate leaderboard
mcpradar rules list                     # List all detection rules
mcpradar rules info <rule_id>           # Show rule details
mcpradar rules disable <rule_id>        # Disable a rule
mcpradar feed-update [--full]           # Update CVE feed
```
