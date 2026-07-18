# Detection rules

This file is generated from `mcpradar.rules.catalog`; edit the catalog, not this file.

Confidence estimates detection specificity (not impact). Protocol profiles are listed only when a rule is profile-specific.

| ID | Title | Severity | Confidence | Status | Surfaces | CWE | OWASP |
|---|---|---|---:|---|---|---|---|
| R001 | Dangerous tool name | critical | 0.9 | stable | tool | CWE-78 |  |
| R101 | Hidden Unicode character | high | 0.9 | stable | tool, prompt, resource, resource_template, server_instructions | CWE-116 |  |
| R102 | Prompt injection pattern | high | 0.7 | stable | tool, prompt, resource, resource_template, server_instructions |  | MCP05 |
| R103 | Encoded content blob | medium | 0.5 | stable | tool, prompt, resource, resource_template, server_instructions |  |  |
| R104 | Hidden HTML or Markdown content | high | 0.7 | stable | tool, prompt, resource, resource_template, server_instructions | CWE-79 |  |
| R105 | Permission scope mismatch | medium | 0.5 | stable | tool |  |  |
| R106 | Secret credential exposure | critical | 0.9 | stable | tool, prompt, resource, server_instructions | CWE-798 |  |
| R107 | Command injection in parameters | critical | 0.9 | stable | tool | CWE-78 |  |
| R108 | Supply-chain behavior indicator | medium | 0.7 | stable | tool, prompt, server_instructions | CWE-494 |  |
| R109 | Schema poisoning indicator | high | 0.7 | stable | tool | CWE-20 |  |
| R110 | Server identity or version anomaly | high | 0.5 | stable | fingerprint |  |  |
| R111 | Insecure transport | high | 0.7 | stable | transport | CWE-319 |  |
| R112 | Authorization hardening | high | 0.7 | stable | auth, transport | CWE-346 |  |
| R113 | Path traversal risk | medium | 0.7 | stable | tool | CWE-22, CWE-59 |  |
| R114 | Unbounded input | low | 0.7 | stable | tool | CWE-400 |  |
| C001 | Cross-server tool collision | critical | 0.7 | stable | context |  |  |
| C002 | Cross-server tool shadowing | high | 0.5 | stable | context |  |  |
| C003 | Cross-server exfiltration chain | critical | 0.7 | stable | context |  |  |
| C004 | Cross-server capability overlap | medium | 0.5 | stable | context |  |  |
| C005 | Cross-server permission gradient | high | 0.5 | stable | context |  |  |
| C006 | Cross-server attack path | high | 0.7 | stable | context |  |  |
| C007 | Cross-server privilege escalation | critical | 0.7 | stable | context |  |  |
| S001 | Cloud metadata SSRF | critical | 0.9 | stable | source | CWE-918 |  |
| S002 | Dynamic outbound URL | medium | 0.7 | stable | source | CWE-918 |  |
| S003 | Unsafe deserialization | high | 0.9 | stable | source | CWE-502 |  |
| S004 | Dynamic code execution | critical | 0.9 | stable | source | CWE-95 |  |
| S005 | SQL injection | high | 0.9 | stable | source | CWE-89 |  |
| S006 | Shell command execution | high | 0.9 | stable | source | CWE-78 |  |
| S007 | Description-code inconsistency | high | 0.5 | stable | source |  |  |
| S008 | Trojan Source Unicode | critical | 0.9 | stable | source | CWE-116 |  |
| S009 | Unrestricted network bind | medium | 0.9 | stable | source | CWE-668 |  |
| S010 | Token passthrough | high | 0.7 | stable | source | CWE-441 |  |
| S011 | Tool-output injection | medium | 0.5 | stable | source |  | MCP05 |
| M001 | Download-to-shell config RCE | critical | 0.7 | stable | config | CWE-494 |  |
| M002 | Encoded config RCE | critical | 0.7 | stable | config | CWE-506 |  |
| M003 | Credential exfiltration command | critical | 0.7 | stable | config | CWE-200 |  |
| M004 | Known collector exfiltration | high | 0.7 | stable | config |  |  |
| M005 | Reverse shell | critical | 0.7 | stable | config | CWE-78 |  |
| M006 | Over-broad agent permission | high | 0.7 | stable | config | CWE-250 |  |
| M007 | Destructive launch command | high | 0.7 | stable | config | CWE-78 |  |
| D001 | Known-vulnerable dependency | medium | 0.9 | stable | dependency | CWE-1395 |  |
| T001 | Package typosquatting | high | 0.7 | stable | config, dependency | CWE-506 |  |

## Rule details

### R001 — Dangerous tool name

Tool name matches a dangerous system command.

- Severity: `critical`
- Confidence: `0.9`
- Surfaces: `tool`
- CWE: CWE-78
- OWASP MCP: not assigned
- Protocol profiles: all

### R101 — Hidden Unicode character

Zero-width or bidirectional Unicode can conceal tool instructions.

- Severity: `high`
- Confidence: `0.9`
- Surfaces: `tool`, `prompt`, `resource`, `resource_template`, `server_instructions`
- CWE: CWE-116
- OWASP MCP: not assigned
- Protocol profiles: all

### R102 — Prompt injection pattern

Instruction-override language appears in MCP-controlled metadata.

- Severity: `high`
- Confidence: `0.7`
- Surfaces: `tool`, `prompt`, `resource`, `resource_template`, `server_instructions`
- CWE: not assigned
- OWASP MCP: MCP05
- Protocol profiles: all

### R103 — Encoded content blob

Large encoded content can conceal instructions or payloads.

- Severity: `medium`
- Confidence: `0.5`
- Surfaces: `tool`, `prompt`, `resource`, `resource_template`, `server_instructions`
- CWE: not assigned
- OWASP MCP: not assigned
- Protocol profiles: all

### R104 — Hidden HTML or Markdown content

Markup attempts to hide agent-visible content from users.

- Severity: `high`
- Confidence: `0.7`
- Surfaces: `tool`, `prompt`, `resource`, `resource_template`, `server_instructions`
- CWE: CWE-79
- OWASP MCP: not assigned
- Protocol profiles: all

### R105 — Permission scope mismatch

The declared tool purpose conflicts with its described capability scope.

- Severity: `medium`
- Confidence: `0.5`
- Surfaces: `tool`
- CWE: not assigned
- OWASP MCP: not assigned
- Protocol profiles: all

### R106 — Secret credential exposure

A credential, token, or connection secret appears in metadata.

- Severity: `critical`
- Confidence: `0.9`
- Surfaces: `tool`, `prompt`, `resource`, `server_instructions`
- CWE: CWE-798
- OWASP MCP: not assigned
- Protocol profiles: all

### R107 — Command injection in parameters

Tool parameter defaults or constraints contain command-injection payloads.

- Severity: `critical`
- Confidence: `0.9`
- Surfaces: `tool`
- CWE: CWE-78
- OWASP MCP: not assigned
- Protocol profiles: all

### R108 — Supply-chain behavior indicator

Metadata requests dynamic installation or unverified code download.

- Severity: `medium`
- Confidence: `0.7`
- Surfaces: `tool`, `prompt`, `server_instructions`
- CWE: CWE-494
- OWASP MCP: not assigned
- Protocol profiles: all

### R109 — Schema poisoning indicator

Input schema structure weakens validation or hides unsafe inputs.

- Severity: `high`
- Confidence: `0.7`
- Surfaces: `tool`
- CWE: CWE-20
- OWASP MCP: not assigned
- Protocol profiles: all

### R110 — Server identity or version anomaly

Fingerprint drift indicates rollback, replacement, or unexpected capability change.

- Severity: `high`
- Confidence: `0.5`
- Surfaces: `fingerprint`
- CWE: not assigned
- OWASP MCP: not assigned
- Protocol profiles: all

### R111 — Insecure transport

Transport lacks current TLS and certificate protections.

- Severity: `high`
- Confidence: `0.7`
- Surfaces: `transport`
- CWE: CWE-319
- OWASP MCP: not assigned
- Protocol profiles: all

### R112 — Authorization hardening

OAuth metadata or negotiated protocol violates MCP authorization requirements.

- Severity: `high`
- Confidence: `0.7`
- Surfaces: `auth`, `transport`
- CWE: CWE-346
- OWASP MCP: not assigned
- Protocol profiles: 2025-11-25, 2026-07-28

### R113 — Path traversal risk

Path-like parameters lack traversal and boundary constraints.

- Severity: `medium`
- Confidence: `0.7`
- Surfaces: `tool`
- CWE: CWE-22, CWE-59
- OWASP MCP: not assigned
- Protocol profiles: all

### R114 — Unbounded input

String or collection input lacks size or content bounds.

- Severity: `low`
- Confidence: `0.7`
- Surfaces: `tool`
- CWE: CWE-400
- OWASP MCP: not assigned
- Protocol profiles: all

### C001 — Cross-server tool collision

Multiple servers expose the same tool name.

- Severity: `critical`
- Confidence: `0.7`
- Surfaces: `context`
- CWE: not assigned
- OWASP MCP: not assigned
- Protocol profiles: all

### C002 — Cross-server tool shadowing

Similar tool names across servers can misroute agent calls.

- Severity: `high`
- Confidence: `0.5`
- Surfaces: `context`
- CWE: not assigned
- OWASP MCP: not assigned
- Protocol profiles: all

### C003 — Cross-server exfiltration chain

Combined server capabilities form a data-exfiltration path.

- Severity: `critical`
- Confidence: `0.7`
- Surfaces: `context`
- CWE: not assigned
- OWASP MCP: not assigned
- Protocol profiles: all

### C004 — Cross-server capability overlap

Many servers expose overlapping sensitive capabilities.

- Severity: `medium`
- Confidence: `0.5`
- Surfaces: `context`
- CWE: not assigned
- OWASP MCP: not assigned
- Protocol profiles: all

### C005 — Cross-server permission gradient

Read and write capabilities combine into an escalation path.

- Severity: `high`
- Confidence: `0.5`
- Surfaces: `context`
- CWE: not assigned
- OWASP MCP: not assigned
- Protocol profiles: all

### C006 — Cross-server attack path

Schema-compatible tools form a multi-server attack chain.

- Severity: `high`
- Confidence: `0.7`
- Surfaces: `context`
- CWE: not assigned
- OWASP MCP: not assigned
- Protocol profiles: all

### C007 — Cross-server privilege escalation

Read-only output feeds a write or execution sink.

- Severity: `critical`
- Confidence: `0.7`
- Surfaces: `context`
- CWE: not assigned
- OWASP MCP: not assigned
- Protocol profiles: all

### S001 — Cloud metadata SSRF

Source references a cloud metadata endpoint.

- Severity: `critical`
- Confidence: `0.9`
- Surfaces: `source`
- CWE: CWE-918
- OWASP MCP: not assigned
- Protocol profiles: all

### S002 — Dynamic outbound URL

A network sink receives a non-constant URL without proven validation.

- Severity: `medium`
- Confidence: `0.7`
- Surfaces: `source`
- CWE: CWE-918
- OWASP MCP: not assigned
- Protocol profiles: all

### S003 — Unsafe deserialization

Source uses an unsafe object deserializer.

- Severity: `high`
- Confidence: `0.9`
- Surfaces: `source`
- CWE: CWE-502
- OWASP MCP: not assigned
- Protocol profiles: all

### S004 — Dynamic code execution

Source executes non-literal code.

- Severity: `critical`
- Confidence: `0.9`
- Surfaces: `source`
- CWE: CWE-95
- OWASP MCP: not assigned
- Protocol profiles: all

### S005 — SQL injection

SQL text is assembled from dynamic string content.

- Severity: `high`
- Confidence: `0.9`
- Surfaces: `source`
- CWE: CWE-89
- OWASP MCP: not assigned
- Protocol profiles: all

### S006 — Shell command execution

Source executes a dynamic command through a shell.

- Severity: `high`
- Confidence: `0.9`
- Surfaces: `source`
- CWE: CWE-78
- OWASP MCP: not assigned
- Protocol profiles: all

### S007 — Description-code inconsistency

A read-only description conflicts with filesystem or execution behavior.

- Severity: `high`
- Confidence: `0.5`
- Surfaces: `source`
- CWE: not assigned
- OWASP MCP: not assigned
- Protocol profiles: all

### S008 — Trojan Source Unicode

Source contains bidirectional or invisible Unicode controls.

- Severity: `critical`
- Confidence: `0.9`
- Surfaces: `source`
- CWE: CWE-116
- OWASP MCP: not assigned
- Protocol profiles: all

### S009 — Unrestricted network bind

Server source binds to all network interfaces.

- Severity: `medium`
- Confidence: `0.9`
- Surfaces: `source`
- CWE: CWE-668
- OWASP MCP: not assigned
- Protocol profiles: all

### S010 — Token passthrough

Caller authorization is forwarded to a downstream service.

- Severity: `high`
- Confidence: `0.7`
- Surfaces: `source`
- CWE: CWE-441
- OWASP MCP: not assigned
- Protocol profiles: all

### S011 — Tool-output injection

Untrusted fetched content is returned directly to the agent.

- Severity: `medium`
- Confidence: `0.5`
- Surfaces: `source`
- CWE: not assigned
- OWASP MCP: MCP05
- Protocol profiles: all

### M001 — Download-to-shell config RCE

A config command pipes a network download to a shell.

- Severity: `critical`
- Confidence: `0.7`
- Surfaces: `config`
- CWE: CWE-494
- OWASP MCP: not assigned
- Protocol profiles: all

### M002 — Encoded config RCE

A config command decodes and executes an encoded payload.

- Severity: `critical`
- Confidence: `0.7`
- Surfaces: `config`
- CWE: CWE-506
- OWASP MCP: not assigned
- Protocol profiles: all

### M003 — Credential exfiltration command

A config command reads credential files and sends data externally.

- Severity: `critical`
- Confidence: `0.7`
- Surfaces: `config`
- CWE: CWE-200
- OWASP MCP: not assigned
- Protocol profiles: all

### M004 — Known collector exfiltration

A config command sends data to a known collection endpoint.

- Severity: `high`
- Confidence: `0.7`
- Surfaces: `config`
- CWE: not assigned
- OWASP MCP: not assigned
- Protocol profiles: all

### M005 — Reverse shell

A config command opens an interactive reverse shell.

- Severity: `critical`
- Confidence: `0.7`
- Surfaces: `config`
- CWE: CWE-78
- OWASP MCP: not assigned
- Protocol profiles: all

### M006 — Over-broad agent permission

Agent configuration auto-approves a broad command or tool class.

- Severity: `high`
- Confidence: `0.7`
- Surfaces: `config`
- CWE: CWE-250
- OWASP MCP: not assigned
- Protocol profiles: all

### M007 — Destructive launch command

MCP server configuration contains a destructive launch command.

- Severity: `high`
- Confidence: `0.7`
- Surfaces: `config`
- CWE: CWE-78
- OWASP MCP: not assigned
- Protocol profiles: all

### D001 — Known-vulnerable dependency

A target dependency matches an authoritative OSV advisory.

- Severity: `medium`
- Confidence: `0.9`
- Surfaces: `dependency`
- CWE: CWE-1395
- OWASP MCP: not assigned
- Protocol profiles: all

### T001 — Package typosquatting

A launched package name is suspiciously similar to a known MCP package.

- Severity: `high`
- Confidence: `0.7`
- Surfaces: `config`, `dependency`
- CWE: CWE-506
- OWASP MCP: not assigned
- Protocol profiles: all
