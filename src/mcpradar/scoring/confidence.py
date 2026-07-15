"""Per-finding detection confidence.

Confidence answers "how likely is this finding a true positive?" — a separate
axis from severity ("how bad if true?"). It is a function of *how* a rule
detects, not what it detects:

  - 0.9 — exact/deterministic: a regex+entropy secret, an AST node match, an
    authoritative CVE lookup. Little room for a false positive.
  - 0.7 — heuristic: keyword/pattern matching, or a precise match whose
    *reachability* or *exploitability* is unproven (SSRF behind an allowlist,
    a config smell).
  - 0.5 — contextual/inferential: cross-signal correlation, fingerprint drift,
    description-vs-code inconsistency. Needs a human to confirm intent.

Kept in one map so confidence is never hardcoded at a call site, and in a
low-level module (no scanner imports) so both the scanner report and the
scoring engine can read it without a circular import.
"""

from __future__ import annotations

CONFIDENCE_MAP: dict[str, float] = {
    # 0.9 — exact pattern / entropy / AST-precise / authoritative lookup
    "R001": 0.9,  # secret regex + Shannon entropy
    "R101": 0.9,  # zero-width / bidi unicode (exact codepoints)
    "R106": 0.9,  # high-entropy credential in schema
    "R107": 0.9,  # dangerous default (exact prefix set)
    "R113": 0.9,
    "R114": 0.9,
    "S002": 0.9,  # unsafe deserialization (pickle/yaml.load AST node)
    "S003": 0.9,  # eval/exec (AST call node)
    "S004": 0.9,  # SQLi via f-string (AST)
    "S005": 0.9,  # shell=True / os.system (AST)
    "S006": 0.9,  # path traversal (AST)
    "S008": 0.9,  # Trojan Source bidi unicode (exact codepoints)
    "S009": 0.9,  # 0.0.0.0 bind (exact literal)
    "D001": 0.9,  # dependency CVE from OSV (authoritative advisory)
    # 0.7 — heuristic / keyword / reachability-or-exploitability unproven
    "R102": 0.7,
    "R104": 0.7,
    "R108": 0.7,
    "R109": 0.7,
    "R111": 0.7,
    "R112": 0.7,  # OAuth metadata hardening (spec heuristic)
    "C001": 0.7,
    "C003": 0.7,
    "C006": 0.7,
    "C007": 0.7,
    "S001": 0.7,  # SSRF — pattern precise, reachability unknown
    "S010": 0.7,  # token passthrough (intra-function taint)
    "M001": 0.7,
    "M002": 0.7,
    "M003": 0.7,
    "M004": 0.7,
    "M005": 0.7,
    "M006": 0.7,
    "M007": 0.7,
    "T001": 0.7,  # typosquat (edit distance — can collide legitimately)
    # 0.5 — contextual / inferential / cross-signal
    "R103": 0.5,
    "R105": 0.5,
    "R110": 0.5,
    "C002": 0.5,
    "C004": 0.5,
    "C005": 0.5,
    "S007": 0.5,  # description-code inconsistency (intent inference)
    "S011": 0.5,  # tool-output/response injection (heuristic dataflow)
}

# Rule IDs not listed default here: unknown detectors get the benefit of the
# doubt withheld, matching the "needs confirmation" tier.
DEFAULT_CONFIDENCE = 0.5


def confidence_for(rule_id: str) -> float:
    """Detection confidence in [0.0, 1.0] for a rule id."""
    return CONFIDENCE_MAP.get(rule_id, DEFAULT_CONFIDENCE)
