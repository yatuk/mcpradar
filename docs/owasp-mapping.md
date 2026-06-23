# OWASP MCP Top 10 Coverage

MCPRadar targets full coverage of the [OWASP MCP Top 10 (2025)](https://owasp.org/www-project-mcp-top-10/).

| # | Risk | Covered By | Coverage |
|---|---|---|---|
| **MCP01** | Token Mismanagement & Secret Exposure | R106 (Secret/Token Exposure) | ✅ Strong |
| **MCP02** | Privilege Escalation via Scope Creep | R105 (Scope Mismatch), C005 (Permission Gradient), C007 (Privilege Escalation Chain) | ✅ Strong |
| **MCP03** | Tool Poisoning | R001 (Dangerous Tool Name), R104 (Hidden Content), R109 (Schema Poisoning), C006 (Attack Path Chain) | ✅ Strong |
| **MCP04** | Supply Chain Attacks & Dependency Tampering | R108 (Supply Chain Risk), SBOM export | ✅ Strong |
| **MCP05** | Command Injection & Execution | R001, R107 (Command Injection via Parameters) | ✅ Strong |
| **MCP06** | Prompt Injection via Contextual Payloads | R101 (Zero-Width Unicode), R102 (Prompt Injection), R103 (Encoded Blob), R104 | ✅ Strong |
| **MCP07** | Insufficient AuthN/AuthZ | R111 (Insecure Transport) | ✅ Strong |
| **MCP08** | Lack of Audit & Telemetry | Audit trail, Stats engine | ✅ Strong |
| **MCP09** | Shadow MCP Servers | R110 (Version Anomaly), Fingerprint | ✅ Strong |
| **MCP10** | Context Injection & Over-Sharing | C001–C007 (7 cross-server rules) | ✅ Strong |

## Rule Coverage Detail

### R-Series (12 detection rules)

| ID | Rule | OWASP | Severity |
|---|---|---|---|
| R001 | Dangerous Tool Name | MCP03, MCP05 | CRITICAL |
| R101 | Zero-Width Unicode Detection | MCP06 | HIGH/CRITICAL |
| R102 | Prompt Injection Detection | MCP06 | HIGH/CRITICAL |
| R103 | Encoded Blob Detection | MCP06 | MEDIUM/HIGH |
| R104 | Hidden Content Detection | MCP03, MCP06 | HIGH |
| R105 | Permission Scope Mismatch | MCP02 | LOW/MEDIUM |
| R106 | Secret/Token Exposure | MCP01 | CRITICAL/HIGH |
| R107 | Command Injection via Parameters | MCP05 | CRITICAL/HIGH |
| R108 | Supply Chain Risk Indicator | MCP04 | HIGH/MEDIUM |
| R109 | Schema Poisoning Indicator | MCP03 | HIGH/MEDIUM |
| R110 | Version Anomaly | MCP09 | HIGH/CRITICAL |
| R111 | Insecure Transport | MCP07 | HIGH/CRITICAL |

### C-Series (7 cross-server rules)

| ID | Rule | OWASP | Severity |
|---|---|---|---|
| C001 | Tool Name Collision | MCP10 | CRITICAL |
| C002 | Tool Name Shadowing | MCP10 | HIGH |
| C003 | Exfiltration Chain | MCP10 | CRITICAL |
| C004 | Capability Overlap | MCP10 | MEDIUM |
| C005 | Permission Gradient | MCP02 | MEDIUM |
| C006 | Attack Path Chain | MCP03/MCP10 | CRITICAL/HIGH/MEDIUM |
| C007 | Privilege Escalation Chain | MCP02 | CRITICAL |

## CWE Mapping

MCPRadar findings map to the following CWE IDs:

| Rule | CWE |
|---|---|
| R001 | CWE-78 (OS Command Injection) |
| R101 | CWE-451 (UI Misrepresentation) |
| R102 | CWE-74 (Injection) |
| R103 | CWE-506 (Embedded Malicious Code) |
| R104 | CWE-451 (UI Misrepresentation) |
| R105 | CWE-863 (Incorrect Authorization) |
| R106 | CWE-798 (Hardcoded Credentials) |
| R107 | CWE-77 (Command Injection) |
| R108 | CWE-494 (Download of Code Without Integrity Check) |
| R109 | CWE-20 (Improper Input Validation) |
| R110 | CWE-441 (Unintended Proxy) |
| R111 | CWE-319 (Cleartext Transmission) |
| C003 | CWE-918 (SSRF) |
| C006 | CWE-923 (Improper Restriction of Communication Channel) |
| C007 | CWE-269 (Improper Privilege Management) |
