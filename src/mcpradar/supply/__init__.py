"""Supply-chain analysis: extract an MCP server's dependencies and check them
against the OSV vulnerability database (GitHub Advisory / PyPA / npm / …).

This is the end-to-end path the SBOM export always implied: take a server's
manifest, resolve its dependency list, batch-query OSV, and report each
known-vulnerable dependency as a finding (rule D001).
"""

from mcpradar.supply.deps import (
    Dependency,
    extract_dependencies,
    scan_dependencies,
)
from mcpradar.supply.typosquat import (
    TyposquatHit,
    check_typosquat,
    typosquat_finding,
)

__all__ = [
    "Dependency",
    "TyposquatHit",
    "check_typosquat",
    "extract_dependencies",
    "scan_dependencies",
    "typosquat_finding",
]
