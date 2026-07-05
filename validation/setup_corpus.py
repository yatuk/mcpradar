"""Setup external benchmark corpus — clones appsecco/vulnerable-mcp-servers-lab
and registers its servers as labeled validation targets.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

APP_SECCO_REPO = "https://github.com/appsecco/vulnerable-mcp-servers-lab.git"
CORPUS_DIR = Path(__file__).parent / "corpus" / "appsecco"


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

    print()
    print("Ground-truth labels live in validation/labels.json.")
    print("Node servers need dependencies before scanning:")
    print("  for each node server dir: npm install")
    print("Then run: python validation/run_benchmark.py")


if __name__ == "__main__":
    main()
