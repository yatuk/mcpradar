const vscode = require("vscode");
const { exec } = require("child_process");

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
  console.log("MCPRadar extension activated");

  const scanCmd = vscode.commands.registerCommand("mcpradar.scan", async () => {
    const target = await vscode.window.showInputBox({
      prompt: "MCP server URL or stdio command",
      placeHolder: "http://localhost:8080 or npx -y @scope/server",
    });
    if (!target) return;

    const transport = await vscode.window.showQuickPick(
      ["http", "sse", "stdio"],
      { placeHolder: "Select transport type" }
    );
    if (!transport) return;

    const outputChannel = vscode.window.createOutputChannel("MCPRadar");
    outputChannel.show();
    outputChannel.appendLine(`Scanning ${target} via ${transport}...`);

    const cmd = `mcpradar scan "${target}" -t ${transport} --format json`;
    exec(cmd, { maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        outputChannel.appendLine(`Error: ${stderr}`);
        return;
      }
      try {
        const report = JSON.parse(stdout);
        outputChannel.appendLine(`Tools: ${report.summary?.total_tools || 0}`);
        outputChannel.appendLine(
          `Findings: ${report.findings?.length || 0}`
        );

        const diagCollection =
          vscode.languages.createDiagnosticCollection("mcpradar");
        report.findings?.forEach((f) => {
          const severity = {
            critical: vscode.DiagnosticSeverity.Error,
            high: vscode.DiagnosticSeverity.Warning,
            medium: vscode.DiagnosticSeverity.Information,
            low: vscode.DiagnosticSeverity.Hint,
          }[f.severity] || vscode.DiagnosticSeverity.Information;

          outputChannel.appendLine(
            `  [${f.severity.toUpperCase()}] ${f.rule_id} ${f.target} — ${f.description}`
          );
        });
      } catch (e) {
        outputChannel.appendLine(stdout);
      }
    });
  });

  const diffCmd = vscode.commands.registerCommand("mcpradar.diff", async () => {
    const server = await vscode.window.showInputBox({
      prompt: "Server URL to diff (leave empty to list targets)",
      placeHolder: "http://localhost:8080",
    });

    const outputChannel = vscode.window.createOutputChannel("MCPRadar Diff");
    outputChannel.show();

    const cmd = server
      ? `mcpradar diff "${server}" --json`
      : `mcpradar diff --json`;

    exec(cmd, { maxBuffer: 10 * 1024 * 1024 }, (err, stdout) => {
      if (err) return;
      try {
        const delta = JSON.parse(stdout);
        outputChannel.appendLine(
          `Changed tools: ${delta.tool_diffs?.length || 0}`
        );
        outputChannel.appendLine(
          `New findings: ${delta.new_findings?.length || 0}`
        );
      } catch (e) {
        outputChannel.appendLine(stdout);
      }
    });
  });

  context.subscriptions.push(scanCmd, diffCmd);
}

function deactivate() {}

module.exports = { activate, deactivate };
