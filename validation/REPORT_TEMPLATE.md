# MCPRadar Validation Report

> {N} servers tested on {date}

## Key Findings

- **Total tools scanned:** {total_tools}
- **Total findings:** {total_findings}
- **True positives:** {true_positives}
- **False positives:** {false_positives}
- **Needs review:** {needs_review}
- **FP rate:** {fp_rate}%

## Summary

| Server | Tools | Findings | Crit | High | Med | Low | TP | FP | ? | Status |
|--------|-------|----------|------|------|-----|-----|----|----|---|--------|
<!-- per-server rows -->

## Rule-by-Rule Breakdown

| Rule | Times Triggered | TP | FP | ? | Most Common Target |
|------|----------------|----|----|---|--------------------|
<!-- rule rows -->

## Server-by-Server Detail

<!-- Per-server: tool list, each finding with severity, description, triage classification, reason -->

## Methodology

1. Each server was installed via `npx -y` or `uvx`
2. Scanned with `mcpradar scan "<command>" -t stdio -s low`
3. Findings were auto-triaged using known false positive patterns:
   - Filesystem server's `read_file` → R105 expected (FP)
   - Tool name containing both scope keywords in description → likely bridge tool (FP)
   - ZWSP in description on known servers → likely emoji (needs review)
4. Manual review was applied to all `needs_review` items
5. Severity distribution and FP rate calculated

## Recommendations for Rule Tuning

<!-- Suggestions based on findings -->
