Output docs/demo.gif

Set Shell "powershell"
Set FontSize 14
Set Width 1200
Set Height 720
Set Theme "Catppuccin Mocha"
Set TypingSpeed 50ms

Hide
Type "& .venv\Scripts\Activate.ps1"
Enter
Sleep 1s
Type "clear"
Enter
Sleep 500ms
Show

Type "# MCPRadar — security scanner for MCP servers"
Sleep 1200ms
Enter
Sleep 400ms

Type "mcpradar scan 'python demo/malicious_server.py' -t stdio"
Sleep 600ms
Enter
Sleep 6s

Type "# 6 findings caught. Second scan, then diff:"
Enter
Sleep 1s

Type "mcpradar scan 'python demo/malicious_server.py' -t stdio"
Sleep 400ms
Enter
Sleep 5s

Type "mcpradar diff"
Sleep 400ms
Enter
Sleep 4s

Type "# Drop into CI with one line — SARIF native. Star us on GitHub"
Sleep 2s
