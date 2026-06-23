# Security Policy

MCPRadar is currently at **v1.0.0-rc1 (Release Candidate)**. We recommend upgrading to the latest release for the most complete security coverage, including all 12 detection rules, 7 cross-server analysis checks, and full OWASP MCP Top 10 coverage.

## Supported Versions

| Version | Supported |
|---|---|
| 1.0.0-rc1 | ✅ |
| < 1.0.0 | ⚠️ Pre-release |

## Reporting a Vulnerability

If you discover a security vulnerability in MCPRadar itself, please
**do not open a public issue**.

Contact the maintainers via:
- GitHub Security Advisories: https://github.com/yatuk/mcpradar/security/advisories/new
- Or open a private vulnerability report

We aim to respond within 48 hours and resolve critical issues within 7 days.

## Scope

This policy covers:
- MCPRadar CLI tool vulnerabilities
- Detection rule bypass methods
- False negatives in security scanning

This policy does NOT cover:
- Vulnerabilities in third-party MCP servers (report those to their maintainers)
- Vulnerabilities in dependencies (report upstream)

## Disclosure Timeline

1. **Day 0:** Report received
2. **Day 2:** Initial response + triage
3. **Day 7:** Fix ready for critical issues
4. **Day 30:** Public disclosure + CVE

## Responsible Use

MCPRadar is a security tool. Use it to protect your own systems and do
responsible disclosure for others. Do not use it for unauthorized scanning.
