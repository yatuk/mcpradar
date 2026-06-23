# False Positive Guide

Understanding and triaging MCPRadar findings.

## How to Triage

Each finding includes a rule ID, severity, title, and evidence. Not every finding
is a real vulnerability — MCPRadar is a pattern detector, not an exploitability
oracle. Review findings in context.

## Per-Rule FP Risk

| Rule | Detection Method | FP Risk | Common Causes |
|---|---|---|---|
| R001 | Exact name match | Low | — |
| R101 | Unicode codepoint match | Low | Emoji ZWJ sequences, BOM in files |
| R102 | Regex pattern match | Medium | "You must..." in docs, "system:" in OS references |
| R103 | Base64/hex length + entropy | Medium | API tokens in examples, config snippets |
| R104 | HTML/MD hidden content | Medium | Short markdown links, CSS examples |
| R105 | Scope mismatch heuristics | High | Legitimate file+network tools, read+write tools |
| R106 | Secret patterns + entropy | Medium | Placeholder keys, example tokens, high-entropy IDs |
| R107 | Shell metachar sequences | Medium | Build scripts, command examples in docs |
| R108 | Supply chain patterns | High | Install instructions, npx commands, eval in docs |
| R109 | Schema weakness checks | Medium | Flexible schemas, large limits by design |

## Quick Triage Checklist

1. Is the finding in a **tool description**? (higher FP risk)
2. Is the finding in a **tool name**? (higher TP confidence)  
3. Does the tool have **bridge/adapter/proxy** in its description? (likely FP for R105)
4. Is the matched text **documentation/example** rather than actual code? (likely FP for R107/R108)
5. Does the finding reference a **placeholder** value (`<token>`, `YOUR_KEY`)? (likely FP for R106)

## Suppressing False Positives

Add findings to `validation/labels.json` `expected_rules: []` for known-clean servers.
Use `mcpradar scan --severity high` to filter out MEDIUM findings during triage.
