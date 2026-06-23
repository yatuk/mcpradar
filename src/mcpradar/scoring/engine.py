"""AIVSS (AI Vulnerability Severity Score) scoring engine.

Computes a 0.0--10.0 security score for an MCP server based on its scan
findings, along with a letter grade and confidence rating.
"""

from __future__ import annotations

from mcpradar.scanner.report import Finding

# ---------------------------------------------------------------------------
# Confidence map — per-rule confidence based on detection specificity
# ---------------------------------------------------------------------------

CONFIDENCE_MAP: dict[str, float] = {
    # High confidence (0.9) — exact pattern or entropy-based detection
    "R001": 0.9,
    "R101": 0.9,
    "R106": 0.9,
    "R107": 0.9,
    # Medium confidence (0.7) — heuristic / keyword-based detection
    "R102": 0.7,
    "R104": 0.7,
    "R108": 0.7,
    "R109": 0.7,
    "R111": 0.7,
    "C001": 0.7,
    "C003": 0.7,
    "C006": 0.7,
    "C007": 0.7,
    # Lower confidence (0.5) — requires context / fingerprint comparison
    "R103": 0.5,
    "R105": 0.5,
    "R110": 0.5,
    "C002": 0.5,
    "C004": 0.5,
    "C005": 0.5,
}

# Default confidence for rule IDs not explicitly listed
_DEFAULT_CONFIDENCE = 0.5

# Severity weights for AIVSS weighted sum
_SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 1,
}


# ---------------------------------------------------------------------------
# AIVSS score computation
# ---------------------------------------------------------------------------


def compute_aivss(findings: list[Finding], tool_count: int) -> float:
    """Compute AIVSS score (0.0--10.0) from scan findings and tool count.

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
        AIVSS score in the range [0.0, 10.0].
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


def compute_grade(score: float) -> str:
    """Convert an AIVSS score to a letter grade (A--F).

    Mapping:
      - 0.0 -- 0.9  → A  Exceptional — no significant findings
      - 1.0 -- 2.9  → B  Good — minor issues only
      - 3.0 -- 4.9  → C  Fair — moderate issues present
      - 5.0 -- 6.9  → D  Weak — serious issues found
      - 7.0 -- 10.0 → F  Critical — severe vulnerabilities

    Args:
        score: AIVSS score in [0.0, 10.0].

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


def score_server(findings: list[Finding], tool_count: int) -> dict[str, object]:
    """Compute all AIVSS scores for a server in a single call.

    Args:
        findings: List of scan findings.
        tool_count: Number of tools exposed by the MCP server.

    Returns:
        Dictionary with keys:
          - aivss_score: float       — the AIVSS score (0.0--10.0)
          - grade: str               — letter grade (A--F)
          - confidence: float        — overall confidence (0.0--1.0)
          - findings_by_severity: dict — counts per severity level
          - total_findings: int      — total number of findings
          - tools: int               — tool count passed in
    """
    aivss = compute_aivss(findings, tool_count)
    grade = compute_grade(aivss)
    confidence = compute_confidence(findings)

    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.severity.value
        if sev in severity_counts:
            severity_counts[sev] += 1

    return {
        "aivss_score": aivss,
        "grade": grade,
        "confidence": confidence,
        "findings_by_severity": severity_counts,
        "total_findings": len(findings),
        "tools": tool_count,
    }
