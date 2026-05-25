# MCPRadar — VS Code Extension

Security scanner for MCP servers, integrated into VS Code.

## Features

- **Scan MCP server** — right-click or command palette → `MCPRadar: Scan this MCP server`
- **Diff scans** — `MCPRadar: Diff last two scans`
- **Syntax highlighting** for `mcpradar.toml` config files
- **Problem matcher** — findings appear in the Problems panel

## Requirements

- `mcpradar` CLI installed (`pip install mcpradar`)
- VS Code 1.85+

## Usage

1. Open command palette (`Ctrl+Shift+P`)
2. Run `MCPRadar: Scan this MCP server`
3. Enter the server URL or stdio command
4. Choose transport type
5. Results appear in the Output panel

## Publishing

```bash
npm install -g @vscode/vsce
vsce package
vsce publish
```
