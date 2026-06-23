"""Setup external benchmark corpus — clones appsecco/vulnerable-mcp-servers-lab
and registers its servers as labeled validation targets.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

APP_SECCO_REPO = "https://github.com/appsecco/vulnerable-mcp-servers-lab.git"
CORPUS_DIR = Path(__file__).parent / "corpus" / "appsecco"

# Per-server labels mapping vulnerabilities to expected MCPRadar rule triggers
APPSECCO_LABELS = {
    "vulnerable-mcp-server-filesystem-workspace-actions": {
        "expected_rules": ["R107"],
        "expected_findings_min": 1,
        "expected_findings_max": 5,
        "notes": (
            "Path traversal via naive path joining. Should trigger command injection patterns."
        ),
    },
    "vulnerable-mcp-server-indirect-prompt-injection": {
        "expected_rules": ["R102", "R104"],
        "expected_findings_min": 2,
        "expected_findings_max": 8,
        "notes": "Document retrieval returning untrusted content with hidden instructions.",
    },
    "vulnerable-mcp-server-malicious-code-exec": {
        "expected_rules": ["R107", "R108"],
        "expected_findings_min": 2,
        "expected_findings_max": 8,
        "notes": "eval()-based RCE. Should trigger command injection and supply chain rules.",
    },
    "vulnerable-mcp-server-secrets-pii": {
        "expected_rules": ["R106"],
        "expected_findings_min": 1,
        "expected_findings_max": 6,
        "notes": "Embedded credentials in source code and log leakage.",
    },
    "vulnerable-mcp-server-outdated-packages": {
        "expected_rules": ["R108"],
        "expected_findings_min": 0,
        "expected_findings_max": 4,
        "notes": (
            "Vulnerable dependencies. Supply chain rules may or may not trigger on static analysis."
        ),
    },
}


def main() -> None:
    if CORPUS_DIR.exists():
        print(f"Corpus already exists at {CORPUS_DIR}")
        print("To re-clone: rm -rf", CORPUS_DIR)
    else:
        CORPUS_DIR.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", "--depth", "1", APP_SECCO_REPO, str(CORPUS_DIR)],
            check=True,
        )
        print(f"Cloned appsecco corpus to {CORPUS_DIR}")

    # Print server structure for manual review
    for server_dir in sorted(CORPUS_DIR.iterdir()):
        if server_dir.is_dir() and not server_dir.name.startswith("."):
            readme = server_dir / "README.md"
            has_readme = readme.exists()
            print(f"  {server_dir.name} {'(has README)' if has_readme else ''}")
            if server_dir.name in APPSECCO_LABELS:
                label = APPSECCO_LABELS[server_dir.name]
                rules = label["expected_rules"]
                lo = label["expected_findings_min"]
                hi = label["expected_findings_max"]
                print(f"    -> expected: {rules}, findings: {lo}-{hi}")

    # TODO: Future phase — auto-discover package.json / pyproject.toml in each server
    # to register scannable commands in targets.yaml


if __name__ == "__main__":
    main()
