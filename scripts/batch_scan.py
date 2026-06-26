"""Batch scan pending MCP servers — try to get real data for each."""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

RESULTS_DIR = Path(__file__).resolve().parent.parent / "validation/results"

# ---------------------------------------------------------------------------
# Server → transport/command mapping
# ---------------------------------------------------------------------------
STDIO_SERVERS = {
    # modelcontextprotocol servers (well-known, published on npm)
    "@modelcontextprotocol/server-brave-search": "npx -y @modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-github": "npx -y @modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-google-maps": "npx -y @modelcontextprotocol/server-google-maps",
    "@modelcontextprotocol/server-postgres": "npx -y @modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-slack": "npx -y @modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-puppeteer": "npx -y @modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-sentry": "npx -y @modelcontextprotocol/server-sentry",
    "@modelcontextprotocol/server-gitlab": "npx -y @modelcontextprotocol/server-gitlab",
    "@modelcontextprotocol/server-sqlite": "npx -y @modelcontextprotocol/server-sqlite",
    "@modelcontextprotocol/server-everart": "npx -y @modelcontextprotocol/server-everart",
    "@modelcontextprotocol/server-fetch": "npx -y @modelcontextprotocol/server-fetch",
    # Anthropic servers
    "@anthropic/mcp-server-google-sheets": "npx -y @anthropic/mcp-server-google-sheets",
    "@anthropic/mcp-server-slack": "npx -y @anthropic/mcp-server-slack",
    "@anthropic/mcp-server-gdrive": "npx -y @anthropic/mcp-server-gdrive",
    "@anthropic/mcp-server-outlook": "npx -y @anthropic/mcp-server-outlook",
    "@anthropic/mcp-server-zendesk": "npx -y @anthropic/mcp-server-zendesk",
    "@anthropic/mcp-server-jira": "npx -y @anthropic/mcp-server-jira",
    "@anthropic/mcp-server-linear": "npx -y @anthropic/mcp-server-linear",
    "@anthropic/mcp-server-notion": "npx -y @anthropic/mcp-server-notion",
    "@anthropic/mcp-server-intercom": "npx -y @anthropic/mcp-server-intercom",
    "@anthropic/mcp-server-asana": "npx -y @anthropic/mcp-server-asana",
    "@anthropic/mcp-server-hubspot": "npx -y @anthropic/mcp-server-hubspot",
    "@anthropic/mcp-server-servicenow": "npx -y @anthropic/mcp-server-servicenow",
    # Third-party
    "@stripe/mcp": "npx -y @stripe/mcp",
    "@supabase/mcp-server-supabase": "npx -y @supabase/mcp-server-supabase",
    "@vercel/mcp-server-ai-sdk": "npx -y @vercel/mcp-server-ai-sdk",
    "@langchain/mcp-server": "npx -y @langchain/mcp-server",
    "@browserbase/mcp-server-browserbase": "npx -y @browserbase/mcp-server-browserbase",
    "@cloudflare/mcp-server-workers": "npx -y @cloudflare/mcp-server-workers",
    "@openai/mcp-server": "npx -y @openai/mcp-server",
    "@smithery/cli": "npx -y @smithery/cli",
    "puppeteer-mcp-server": "npx -y puppeteer-mcp-server",
    "mcp-server-chart": "npx -y mcp-server-chart",
}


async def scan_one_stdio(server_name: str, cmd: str) -> dict | None:
    """Scan one server via stdio. Returns parsed JSON result or None on failure."""
    try:
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "mcpradar",
            "scan",
            cmd,
            "-t",
            "stdio",
            "-f",
            "json",
            "--no-save",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60.0)
        if proc.returncode != 0:
            stderr_text = stderr.decode()[:200] if stderr else ""
            return {"error": f"exit {proc.returncode}: {stderr_text}"}

        text = stdout.decode()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Try to extract JSON from output
            for line in text.split("\n"):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
            return {"error": f"not json: {text[:200]}"}
    except TimeoutError:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)[:200]}


def sanitize_filename(name: str) -> str:
    return name.replace("/", "-").replace("@", "").replace(":", "-")[:80]


async def main():
    # Find pending servers
    pending = {}
    for fp in sorted(RESULTS_DIR.glob("*.json")):
        data = json.loads(fp.read_text(encoding="utf-8"))
        status = data.get("status", "")
        if "pending" in status.lower():
            name = data.get("name", fp.stem)
            pending[name] = fp

    print(f"Pending servers: {len(pending)}")

    # Match with known commands
    scan_tasks = []
    for name, fp in pending.items():
        cmd = STDIO_SERVERS.get(name)
        if cmd:
            scan_tasks.append((name, cmd, fp))
        else:
            print(f"  SKIP {name} — no known stdio command")

    print(f"Will scan {len(scan_tasks)} servers via stdio...")
    print()

    # Scan concurrently with semaphore
    sem = asyncio.Semaphore(3)  # Max 3 concurrent npx downloads

    async def scan_with_sem(name, cmd, fp):
        async with sem:
            print(f"  Scanning {name}...")
            result = await scan_one_stdio(name, cmd)
            if result and "error" not in result:
                # Update the validation result file with real data
                try:
                    result["status"] = "scanned"
                    result["name"] = name
                    fp.write_text(
                        json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
                    )
                    tools = len(result.get("tools", []))
                    findings = len(result.get("findings", []))
                    print(f"    OK: {tools} tools, {findings} findings -> {fp.name}")
                    return "ok"
                except Exception as e:
                    print(f"    WRITE ERROR: {e}")
                    return "error"
            else:
                err = result.get("error", "unknown") if result else "no result"
                print(f"    FAIL: {err[:100]}")
                return "fail"

    tasks = [scan_with_sem(name, cmd, fp) for name, cmd, fp in scan_tasks]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    ok = sum(1 for r in results if r == "ok")
    fail = sum(1 for r in results if r == "fail")
    print(f"\nDone: {ok} scanned, {fail} failed, {len(scan_tasks)} total")


if __name__ == "__main__":
    asyncio.run(main())
