# Vulnerability Disclosure Policy

MCPRadar scans publicly listed MCP servers for security vulnerabilities. This policy
governs how we responsibly disclose findings to affected server maintainers.

## Scope

- MCP servers listed in the [official MCP registry](https://registry.modelcontextprotocol.io)
- Community MCP servers submitted via our [leaderboard](https://yatuk.github.io/mcpradar/)
- Publicly accessible, unauthenticated MCP server installations

## Disclosure Timeline

| Phase | Duration | Action |
|-------|----------|--------|
| **Private disclosure** | 30 days | Notify server maintainers privately via GitHub issue, email, or security contact |
| **Extension** | +30 days | Granted if maintainer demonstrates active remediation progress |
| **Public disclosure** | After 90 days | Findings published on MCPRadar leaderboard with MRS score and details |

## CVE Process

For CRITICAL-severity findings (MRS >= 7.0):
1. Request a CVE ID from [MITRE](https://cve.mitre.org/) or via [GitHub Security Advisories](https://github.com/yatuk/mcpradar/security/advisories)
2. Reference the CVE in the disclosure communication
3. Publish the CVE record after the disclosure window

## Safe Harbor

Good-faith security research conducted on **publicly listed** MCP servers is protected under
this policy. We will not pursue legal action against researchers who:
- Do not exploit findings beyond proof-of-concept
- Do not access, modify, or delete user data
- Privately disclose findings before any public mention
- Follow the timeline above

## Reporting a Vulnerability

If you discover a vulnerability in an MCP server scanned by MCPRadar:

1. **Open a GitHub Security Advisory**: https://github.com/yatuk/mcpradar/security/advisories/new
2. **Email**: Create a GitHub issue with `[SECURITY]` in the title for non-sensitive matters
3. **PGP Key**: (Available on request for highly sensitive findings)

## Found by MCPRadar

If MCPRadar found a vulnerability in your MCP server and you were notified:

- The finding will appear on the [MCPRadar leaderboard](https://yatuk.github.io/mcpradar/) with its MRS score
- You have 30 days to remediate before the finding is publicly visible in detail
- After remediation, re-scanning will update your score automatically (weekly CI)
- You can request a review of any finding by opening a GitHub issue

## Acknowledgments

We thank all researchers and server maintainers who participate in responsible disclosure.
Notable findings will be acknowledged on the leaderboard and in our CHANGELOG.

---

*Policy last updated: July 2026*
*Based on Google Project Zero 90-day model and CERT/CC Vulnerability Disclosure Guidelines*
