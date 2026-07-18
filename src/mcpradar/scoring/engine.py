"""MCPRadar Risk Score (MRS) engine.

Computes a 0.0--10.0 security score for an MCP server based on its scan
findings, along with a letter grade and confidence rating.
"""

from __future__ import annotations

from mcpradar.scanner.report import Finding
from mcpradar.scoring.confidence import CONFIDENCE_MAP, confidence_for

# Confidence lives in mcpradar.scoring.confidence (single source of truth,
# low-level so the scanner report can read it too). Re-exported here for
# backward compatibility.
_DEFAULT_CONFIDENCE = 0.5

__all__ = ["CONFIDENCE_MAP", "confidence_for"]

# Severity weights for the MRS weighted sum
_SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 1,
}


# ---------------------------------------------------------------------------
# MRS score computation
# ---------------------------------------------------------------------------


def compute_mrs(findings: list[Finding], tool_count: int) -> float:
    """Compute MCPRadar Risk Score v1 (0.0--10.0).

    Algorithm:
      1. Count findings by severity.
      2. Compute weighted sum: critical*10 + high*7 + medium*4 + low*1.
      3. Compute density: len(findings) / max(tool_count, 1).
      4. Normalize density factor to [0.5, 2.0] so even a single finding
         on a server with few tools gets a meaningful score.
      5. Raw score: weighted / max(tool_count, 1) * density_factor.
      6. Cap at 10.0 and round to one decimal place.

    Args:
        findings: List of scan findings.
        tool_count: Number of tools exposed by the MCP server.
            If 0 but findings exist, falls back to 1 to avoid division by zero.

    Returns:
        MRS-v1 score in the range [0.0, 10.0].
    """
    if not findings:
        return 0.0

    # Fallback to 1 tool when findings exist but no tools are listed
    actual_tool_count = max(tool_count, 1)

    # 1. Count findings by severity
    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.severity.value
        if sev in severity_counts:
            severity_counts[sev] += 1

    # 2. Weighted sum
    weighted = sum(severity_counts[sev] * _SEVERITY_WEIGHTS.get(sev, 0) for sev in severity_counts)

    # 3. Density
    density = len(findings) / actual_tool_count

    # 4. Density factor clamped to [0.5, 2.0]
    density_factor = max(0.5, min(2.0, density * 5))

    # 5. Raw score
    raw = weighted / actual_tool_count * density_factor

    # 6. Cap at 10.0, round to one decimal place
    return min(10.0, round(raw, 1))


# ---------------------------------------------------------------------------
# Grade mapping
# ---------------------------------------------------------------------------


def compute_mrs_capability(findings: list[Finding], tools: list[object]) -> float:
    """Compute capability-aware MRS-v1.

    ``base`` is the severity-weighted MEDIUM+ finding load over the tool surface
    (critical → floor 5.0, high → 3.0); ``AARS`` is the agentic capability blast
    radius of the server's tools; ``ThM`` is the environmental multiplier. The
    ``max`` ensures capability can only raise risk, never discount a real
    finding. See docs/scoring-model.md.
    """
    from mcpradar.scoring.capability import compute_aars

    sev = {"critical": 0, "high": 0, "medium": 0}
    for f in findings:
        if f.severity.value in sev:
            sev[f.severity.value] += 1
    weighted = sev["critical"] * 10 + sev["high"] * 7 + sev["medium"] * 4
    base = weighted / max(len(tools), 3)
    if sev["critical"]:
        base = max(base, 5.0)
    elif sev["high"]:
        base = max(base, 3.0)

    aars = compute_aars(tools)
    thm = 1.15 if any(f.rule_id == "R111" for f in findings) else 1.0
    return min(10.0, round(max(base, (base + aars) / 2 * thm), 1))


def compute_grade(score: float) -> str:
    """Convert an MRS score to a letter grade (A--F).

    Mapping:
      - 0.0 -- 0.9  → A  Exceptional — no significant findings
      - 1.0 -- 2.9  → B  Good — minor issues only
      - 3.0 -- 4.9  → C  Fair — moderate issues present
      - 5.0 -- 6.9  → D  Weak — serious issues found
      - 7.0 -- 10.0 → F  Critical — severe vulnerabilities

    Args:
        score: MRS score in [0.0, 10.0].

    Returns:
        Single-character letter grade.
    """
    if score <= 0.9:
        return "A"
    elif score <= 2.9:
        return "B"
    elif score <= 4.9:
        return "C"
    elif score <= 6.9:
        return "D"
    else:
        return "F"


# ---------------------------------------------------------------------------
# Confidence computation
# ---------------------------------------------------------------------------


def compute_confidence(findings: list[Finding]) -> float:
    """Compute overall confidence score (0.0--1.0) based on rule specificity.

    Each finding's rule_id is mapped to a confidence value:
      - 0.9: exact pattern / entropy-based detection (R001, R101, R106, R107)
      - 0.7: heuristic / keyword-based detection (R102, R104, R108, R109,
              R111, C001, C003, C006, C007)
      - 0.5: requires context / fingerprint comparison (R103, R105, R110,
              C002, C004, C005)
      - Unknown rule_ids default to 0.5

    The overall confidence is the arithmetic mean across all findings.
    If there are no findings, confidence is 1.0 (nothing to doubt).

    Args:
        findings: List of scan findings.

    Returns:
        Confidence score in the range [0.0, 1.0].
    """
    if not findings:
        return 1.0

    total = sum(CONFIDENCE_MAP.get(f.rule_id, _DEFAULT_CONFIDENCE) for f in findings)
    return total / len(findings)


# ---------------------------------------------------------------------------
# Convenience: all scores in one call
# ---------------------------------------------------------------------------


def score_server(
    findings: list[Finding], tool_count: int, tools: list[object] | None = None
) -> dict[str, object]:
    """Compute all MCPRadar Risk Score outputs for a server.

    Args:
        findings: List of scan findings.
        tool_count: Number of tools exposed by the MCP server.
        tools: The tool objects, if available. When provided, the score is
            capability-aware (a powerful server is non-A even with no finding);
            otherwise it falls back to the finding-only score.

    Returns:
        Dictionary with keys:
          - risk_score: float        — the MRS-v1 score (0.0--10.0)
          - scoring_model: str       — stable score model identifier
          - grade: str               — letter grade (A--F)
          - confidence: float        — overall confidence (0.0--1.0)
          - findings_by_severity: dict — counts per severity level
          - total_findings: int      — total number of findings
          - tools: int               — tool count passed in
    """
    risk_score = (
        compute_mrs_capability(findings, tools)
        if tools is not None
        else compute_mrs(findings, tool_count)
    )
    grade = compute_grade(risk_score)
    confidence = compute_confidence(findings)

    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.severity.value
        if sev in severity_counts:
            severity_counts[sev] += 1

    return {
        "risk_score": risk_score,
        "scoring_model": "mrs-v1",
        "grade": grade,
        "confidence": confidence,
        "findings_by_severity": severity_counts,
        "total_findings": len(findings),
        "tools": tool_count,
    }


# Compatibility aliases for callers of pre-1.0 release candidates. They retain
# behavior but no public output is labelled as OWASP AIVSS.
compute_aivss = compute_mrs
compute_aivss_capability = compute_mrs_capability
