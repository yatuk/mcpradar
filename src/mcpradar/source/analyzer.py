"""AST-based static analyzer for MCP server source code.

Rule IDs use the ``S`` (Source) namespace to keep them distinct from the
schema rules (``R``) and cross-server rules (``C``):

- S001  Cloud-metadata SSRF (169.254.169.254 / metadata.google.internal)
- S002  Unguarded outbound fetch (network sink on a non-constant URL)
- S003  Unsafe deserialization (pickle / yaml.load / marshal)
- S004  Dynamic code execution (eval / exec / compile on non-literal)
- S005  SQL injection (execute() with an f-string / concat / %-format)
- S006  Shell execution (subprocess shell=True / os.system / os.popen)
- S007  Description-Code Inconsistency (read-only tool that writes / sends /
        executes) — the flagship differentiator
- S008  Trojan Source: bidirectional / invisible unicode (CVE-2021-42574)
- S009  Network exposure: server binds to all interfaces (0.0.0.0 / DNS rebinding)
- S010  Token passthrough / confused deputy (forwards the caller's auth token)
- S011  Tool-output / response injection (returns raw content fetched from a
        caller-controlled URL straight to the agent — indirect prompt injection)
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from mcpradar.scanner.report import Finding, Severity

# ---------------------------------------------------------------------------
# Sink classification
# ---------------------------------------------------------------------------

# Dotted-name suffixes that egress data to the network.
_NETWORK_SINKS = (
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.patch",
    "requests.delete",
    "requests.request",
    "requests.head",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.patch",
    "httpx.delete",
    "httpx.request",
    "httpx.stream",
    "urllib.request.urlopen",
    "urlopen",
    "aiohttp.request",
    "socket.create_connection",
    "session.get",
    "session.post",
    "session.request",
    "client.get",
    "client.post",
)

# Deserialization sinks (yaml.load handled specially for SafeLoader).
_DESERIALIZE_SINKS = ("pickle.loads", "pickle.load", "marshal.loads", "cloudpickle.loads")

# Dynamic-execution sinks.
_EXEC_SINKS = ("eval", "exec")

# Shell/command sinks.
_SHELL_SINKS = ("os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput")
_SUBPROCESS_SINKS = (
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_output",
    "subprocess.check_call",
)

# SQL execute sinks (method name match, receiver-agnostic).
_SQL_METHODS = ("execute", "executemany", "executescript")

_CLOUD_METADATA = ("169.254.169.254", "metadata.google.internal", "100.100.100.200")

# Trojan Source (CVE-2021-42574): bidirectional-control and invisible unicode
# that make source read differently from how it compiles/executes.
# Bidi: LRE/RLE/PDF/LRO/RLO (202A-202E) and isolates LRI/RLI/FSI/PDI (2066-2069).
_BIDI_CHARS = frozenset(chr(c) for c in [*range(0x202A, 0x202F), *range(0x2066, 0x206A)])
# Zero-width / directional marks / word joiner / BOM.
_INVISIBLE_CHARS = frozenset(
    chr(c) for c in (0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060, 0xFEFF)
)
_TROJAN_CHARS = _BIDI_CHARS | _INVISIBLE_CHARS

# Tool-name / description tokens that promise read-only behavior.
_READONLY_TOKENS = (
    "read",
    "get",
    "list",
    "fetch",
    "search",
    "query",
    "browse",
    "show",
    "describe",
    "view",
    "lookup",
    "find",
    "retrieve",
    "count",
    "check",
    "status",
)
# Tokens that legitimately imply a write/side effect (suppress DCI).
_WRITE_TOKENS = (
    "write",
    "create",
    "update",
    "delete",
    "remove",
    "edit",
    "modify",
    "set",
    "put",
    "post",
    "send",
    "upload",
    "insert",
    "run",
    "exec",
    "execute",
    "install",
    "deploy",
    "publish",
    "save",
    "sync",
    "submit",
)

# Decorator dotted-name suffixes that register an MCP tool.
_TOOL_DECORATORS = ("tool", "mcp.tool", "server.tool", "app.tool", "add_tool")


@dataclass
class _ToolFn:
    name: str
    description: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    lineno: int


def _dotted_name(node: ast.AST) -> str:
    """Return the dotted name of a call target, e.g. ``requests.get``."""
    parts: list[str] = []
    cur: ast.AST | None = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _root_name(node: ast.AST | None) -> str | None:
    """The base identifier of an attribute/subscript/call chain.

    ``resp.json()`` → ``resp``; ``r.headers["x"]`` → ``r``; ``x`` → ``x``.
    """
    cur = node
    while True:
        if isinstance(cur, (ast.Attribute, ast.Subscript, ast.Await)):
            cur = cur.value
        elif isinstance(cur, ast.Call):
            cur = cur.func
        else:
            break
    return cur.id if isinstance(cur, ast.Name) else None


def _is_constant_str(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


# Literal addresses that bind a server to every network interface.
_ALL_INTERFACES = {"0.0.0.0", "::", "0000:0000:0000:0000:0000:0000:0000:0000"}


def _is_all_interfaces(node: ast.AST | None) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.strip() in _ALL_INTERFACES
    )


def _const(node: ast.AST | None) -> object:
    return node.value if isinstance(node, ast.Constant) else None


# Header names that carry an auth credential (lowercased).
_AUTH_HEADER_KEYS = {
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "bearer",
    "token",
}


def _key_is_auth_or_unknown(key: ast.AST | None) -> bool:
    """An auth-ish constant key, or a non-constant key we can't rule out."""
    if isinstance(key, ast.Constant) and isinstance(key.value, str):
        return key.value.lower() in _AUTH_HEADER_KEYS
    return key is not None  # variable key — can't tell, treat as possible


def _is_incoming_header_read(node: ast.AST | None) -> bool:
    """True if the expression reads an auth value from an incoming request's
    headers: ``req.headers["Authorization"]`` or ``req.headers.get("...")``."""
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute):
        return node.value.attr == "headers" and _key_is_auth_or_unknown(node.slice)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and isinstance(node.func.value, ast.Attribute)
        and node.func.value.attr == "headers"
    ):
        return _key_is_auth_or_unknown(node.args[0] if node.args else None)
    return False


def _url_host_is_dynamic(node: ast.AST | None) -> bool:
    """True only when the request URL's *host* could be attacker-controlled.

    A constant string, or an f-string / concat that begins with a literal
    ``scheme://host`` prefix, is host-pinned (only the path/query varies) and is
    not an SSRF risk. A bare variable or a URL built host-first from input is.
    """
    import re

    def _starts_with_fixed_host(s: str) -> bool:
        return re.match(r"\s*[a-zA-Z][a-zA-Z0-9+.-]*://[^/{}\s]+", s) is not None

    if node is None or _is_constant_str(node):
        return False
    if isinstance(node, ast.JoinedStr):
        first = node.values[0] if node.values else None
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return not _starts_with_fixed_host(first.value)
        return True  # f-string starts with a formatted value → host is dynamic
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _url_host_is_dynamic(node.left)
    # A non-str constant is not a URL host; a bare Name/Attribute/Call is not
    # provably fixed, so treat it as dynamic.
    return not isinstance(node, ast.Constant)


def _looks_dynamic(node: ast.AST | None) -> bool:
    """True if an argument is built dynamically (f-string, concat, %/format)."""
    if isinstance(node, ast.JoinedStr):  # f-string
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    # "...".format(x)
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    )


class _CapabilityVisitor(ast.NodeVisitor):
    """Collects the side-effecting capabilities used inside a function body."""

    def __init__(self) -> None:
        self.network = False
        self.fs_write = False
        self.exec = False
        self.network_lines: list[int] = []
        self.fs_write_lines: list[int] = []
        self.exec_lines: list[int] = []

    def visit_Call(self, node: ast.Call) -> None:
        name = _dotted_name(node.func)
        short = name.split(".")[-1]

        if name in _NETWORK_SINKS or name.endswith(".urlopen"):
            self.network = True
            self.network_lines.append(node.lineno)
        if (
            name in _SHELL_SINKS
            or name in _SUBPROCESS_SINKS
            or name in _EXEC_SINKS
            or short in ("system", "popen")
        ):
            self.exec = True
            self.exec_lines.append(node.lineno)
        # filesystem writes
        if short == "open":
            mode = self._open_mode(node)
            if any(c in mode for c in ("w", "a", "x", "+")):
                self.fs_write = True
                self.fs_write_lines.append(node.lineno)
        if name in (
            "os.remove",
            "os.unlink",
            "os.rmdir",
            "os.mkdir",
            "os.makedirs",
            "os.rename",
            "shutil.rmtree",
            "shutil.move",
            "shutil.copy",
            "shutil.copyfile",
        ) or short in ("write_text", "write_bytes", "unlink", "mkdir", "rmdir"):
            self.fs_write = True
            self.fs_write_lines.append(node.lineno)
        self.generic_visit(node)

    @staticmethod
    def _open_mode(node: ast.Call) -> str:
        # open(path, "w") or open(path, mode="w")
        if len(node.args) >= 2 and _is_constant_str(node.args[1]):
            return str(node.args[1].value)  # type: ignore[attr-defined]
        for kw in node.keywords:
            if kw.arg == "mode" and _is_constant_str(kw.value):
                return str(kw.value.value)  # type: ignore[attr-defined]
        return "r"


class SourceAnalyzer:
    """Analyzes MCP server source files for security issues."""

    def analyze_file(self, path: Path) -> list[Finding]:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        rel = path.name
        findings: list[Finding] = []
        # S008 works on raw text and does not need a parseable AST.
        findings += self._scan_trojan_source(source, rel)
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            return findings
        findings += self._scan_sinks(tree, rel)
        findings += self._scan_dci(tree, rel)
        findings += self._scan_bind_exposure(tree, rel)
        findings += self._scan_token_passthrough(tree, rel)
        findings += self._scan_response_injection(tree, rel)
        return findings

    # ------------------------------------------------------------------
    # S010: token passthrough / confused deputy
    # ------------------------------------------------------------------
    def _scan_token_passthrough(self, tree: ast.AST, loc: str) -> list[Finding]:
        found: list[Finding] = []
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # Variables tainted with a value read from the *incoming* request's
            # headers (one-level propagation). The server's own os.getenv token
            # is deliberately NOT tainted.
            tainted: set[str] = set()
            for node in ast.walk(fn):
                if isinstance(node, ast.Assign) and len(node.targets) == 1:
                    tgt = node.targets[0]
                    if isinstance(tgt, ast.Name) and (
                        _is_incoming_header_read(node.value)
                        or (isinstance(node.value, ast.Name) and node.value.id in tainted)
                    ):
                        tainted.add(tgt.id)

            for node in ast.walk(fn):
                if not isinstance(node, ast.Call):
                    continue
                name = _dotted_name(node.func)
                if name not in _NETWORK_SINKS and not name.endswith(".urlopen"):
                    continue
                if self._forwards_incoming_auth(node, tainted):
                    found.append(
                        self._f(
                            "S010",
                            "Token passthrough / confused deputy",
                            Severity.HIGH,
                            loc,
                            node.lineno,
                            f"'{fn.name}' forwards the incoming request's Authorization "
                            "token into an outbound request; token passthrough is "
                            "forbidden by the MCP spec (confused deputy — validate the "
                            "audience and use the server's own credential instead)",
                            tool=fn.name,
                        )
                    )
        return found

    @staticmethod
    def _forwards_incoming_auth(call: ast.Call, tainted: set[str]) -> bool:
        """True if an outbound call sets an auth header from an incoming token."""

        def value_is_incoming(v: ast.AST) -> bool:
            if isinstance(v, ast.Name) and v.id in tainted:
                return True
            if _is_incoming_header_read(v):
                return True
            if isinstance(v, ast.JoinedStr):  # f"Bearer {token}"
                return any(
                    isinstance(p, ast.FormattedValue) and value_is_incoming(p.value)
                    for p in v.values
                )
            if isinstance(v, ast.BinOp):  # "Bearer " + token
                return value_is_incoming(v.left) or value_is_incoming(v.right)
            return False

        for kw in call.keywords:
            if kw.arg == "headers" and isinstance(kw.value, ast.Dict):
                for k, v in zip(kw.value.keys, kw.value.values, strict=False):
                    if (
                        isinstance(k, ast.Constant)
                        and isinstance(k.value, str)
                        and k.value.lower() in _AUTH_HEADER_KEYS
                        and value_is_incoming(v)
                    ):
                        return True
            if kw.arg == "auth" and value_is_incoming(kw.value):
                return True
        return False

    # ------------------------------------------------------------------
    # S011: tool-output / response injection
    # ------------------------------------------------------------------
    def _scan_response_injection(self, tree: ast.AST, loc: str) -> list[Finding]:
        """Flag a tool handler that returns content fetched from a
        *caller-controlled* URL straight back to the agent.

        Tool output is a trust boundary: whatever a tool returns is read by the
        LLM as instructions-eligible text. A handler that fetches an arbitrary
        user-supplied URL and hands back the raw body is a textbook indirect
        prompt-injection channel — the attacker controls both the destination
        and the returned content.

        FP guard: we only look at fetches whose URL *host* is dynamic
        (``_url_host_is_dynamic``). A pinned API client (``get_weather`` calling
        a fixed endpoint and returning JSON) is the common benign case and is
        deliberately not flagged.
        """
        found: list[Finding] = []
        for fn in self._tool_functions(tree):
            # Pre-filter: the handler must contain at least one dynamic-host
            # fetch, otherwise there is nothing untrusted to return.
            if not any(
                isinstance(n, ast.Call) and self._is_dynamic_fetch(n) for n in ast.walk(fn.node)
            ):
                continue

            # Response objects from a dynamic-host fetch: ``resp = httpx.get(u)``.
            resp_vars: set[str] = set()
            for node in ast.walk(fn.node):
                if isinstance(node, ast.Assign) and len(node.targets) == 1:
                    tgt = node.targets[0]
                    val = node.value.value if isinstance(node.value, ast.Await) else node.value
                    if (
                        isinstance(tgt, ast.Name)
                        and isinstance(val, ast.Call)
                        and self._is_dynamic_fetch(val)
                    ):
                        resp_vars.add(tgt.id)

            # Body vars derived from a response (one level): ``body = resp.text``,
            # ``data = resp.json()``, or a plain alias ``out = resp``.
            body_vars: set[str] = set()
            for node in ast.walk(fn.node):
                if isinstance(node, ast.Assign) and len(node.targets) == 1:
                    tgt = node.targets[0]
                    val = node.value.value if isinstance(node.value, ast.Await) else node.value
                    if isinstance(tgt, ast.Name) and _root_name(val) in resp_vars:
                        body_vars.add(tgt.id)

            for node in ast.walk(fn.node):
                if not isinstance(node, ast.Return) or node.value is None:
                    continue
                if self._returns_external(node.value, resp_vars, body_vars):
                    found.append(
                        self._f(
                            "S011",
                            "Tool-output / response injection",
                            Severity.MEDIUM,
                            loc,
                            node.lineno,
                            f"Tool '{fn.name}' returns content fetched from a "
                            "caller-controlled URL directly to the agent without "
                            "sanitization; the raw response can carry embedded "
                            "instructions (indirect prompt injection)",
                            tool=fn.name,
                        )
                    )
                    break  # one finding per tool
        return found

    @staticmethod
    def _fetch_url_arg(call: ast.Call) -> ast.AST | None:
        for kw in call.keywords:
            if kw.arg == "url":
                return kw.value
        return call.args[0] if call.args else None

    def _is_dynamic_fetch(self, call: ast.Call) -> bool:
        """A network fetch whose URL host could be attacker-controlled."""
        name = _dotted_name(call.func)
        if name not in _NETWORK_SINKS and not name.endswith(".urlopen"):
            return False
        return _url_host_is_dynamic(self._fetch_url_arg(call))

    def _returns_external(self, v: ast.AST, resp_vars: set[str], body_vars: set[str]) -> bool:
        """True if a returned expression derives from an untrusted response."""
        if isinstance(v, ast.Await):
            v = v.value
        # Inline fetch: ``return httpx.get(user_url).text``.
        for sub in ast.walk(v):
            if isinstance(sub, ast.Call) and self._is_dynamic_fetch(sub):
                return True
        if isinstance(v, ast.Name):
            return v.id in resp_vars or v.id in body_vars
        if isinstance(v, (ast.Attribute, ast.Subscript)):
            return _root_name(v) in resp_vars or _root_name(v) in body_vars
        if isinstance(v, ast.Call):
            root = _root_name(v.func)
            if root in resp_vars or root in body_vars:
                return True
            return any(self._returns_external(a, resp_vars, body_vars) for a in v.args)
        if isinstance(v, ast.JoinedStr):
            return any(
                isinstance(p, ast.FormattedValue)
                and self._returns_external(p.value, resp_vars, body_vars)
                for p in v.values
            )
        if isinstance(v, ast.BinOp):
            return self._returns_external(v.left, resp_vars, body_vars) or self._returns_external(
                v.right, resp_vars, body_vars
            )
        return False

    # ------------------------------------------------------------------
    # S009: network exposure — binding to 0.0.0.0 / all interfaces
    # ------------------------------------------------------------------
    def _scan_bind_exposure(self, tree: ast.AST, loc: str) -> list[Finding]:
        found: list[Finding] = []
        seen: set[int] = set()

        def flag(lineno: int, how: str) -> None:
            if lineno in seen:
                return
            seen.add(lineno)
            found.append(
                self._f(
                    "S009",
                    "Network exposure: server binds to all interfaces (0.0.0.0)",
                    Severity.HIGH,
                    loc,
                    lineno,
                    f"{how} exposes the MCP server on all network interfaces; a "
                    "local-only server reachable over the network enables DNS "
                    "rebinding and remote access (cf. CVE-2025-49596)",
                    binding="0.0.0.0",
                )
            )

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            # host="0.0.0.0" / bind_host="::" keyword on run()/serve()/FastMCP()
            for kw in node.keywords:
                if kw.arg in ("host", "bind_host", "listen_host") and _is_all_interfaces(kw.value):
                    flag(node.lineno, f"host={_const(kw.value)!r}")
            # socket .bind(("0.0.0.0", port)) or .bind(("", port))
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "bind"
                and node.args
                and isinstance(node.args[0], ast.Tuple)
                and node.args[0].elts
                and _is_all_interfaces(node.args[0].elts[0])
            ):
                flag(node.lineno, "socket bind")

        # `X.host = "0.0.0.0"` (e.g. mcp.settings.host)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                targets = node.targets
            elif isinstance(node, ast.AnnAssign):
                targets = [node.target]
            else:
                continue
            for t in targets:
                if (
                    isinstance(t, ast.Attribute)
                    and t.attr in ("host", "bind_host")
                    and node.value is not None
                    and _is_all_interfaces(node.value)
                ):
                    flag(node.lineno, "host assignment")
        return found

    # ------------------------------------------------------------------
    # S008: Trojan Source (CVE-2021-42574) — bidi / invisible unicode
    # ------------------------------------------------------------------
    def _scan_trojan_source(self, source: str, loc: str) -> list[Finding]:
        found: list[Finding] = []
        for lineno, line in enumerate(source.splitlines(), start=1):
            hits = {ch for ch in line if ch in _TROJAN_CHARS}
            if hits:
                names = ", ".join(f"U+{ord(c):04X}" for c in sorted(hits))
                bidi = any(c in _BIDI_CHARS for c in hits)
                found.append(
                    self._f(
                        "S008",
                        "Trojan Source: bidirectional / invisible unicode in code",
                        Severity.HIGH if bidi else Severity.MEDIUM,
                        loc,
                        lineno,
                        (
                            "Source line contains "
                            + ("bidirectional-control" if bidi else "invisible")
                            + f" unicode ({names}); code may not read as it executes "
                            "(CVE-2021-42574)"
                        ),
                        chars=names,
                    )
                )
        return found

    # ------------------------------------------------------------------
    # S001-S006: sink-based checks
    # ------------------------------------------------------------------
    def _scan_sinks(self, tree: ast.AST, loc: str) -> list[Finding]:
        found: list[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                for meta in _CLOUD_METADATA:
                    if meta in node.value:
                        found.append(
                            self._f(
                                "S001",
                                "Cloud-metadata SSRF target in source",
                                Severity.CRITICAL,
                                loc,
                                node.lineno,
                                f"Cloud metadata endpoint '{meta}' referenced in source",
                                matched=meta,
                            )
                        )
            if not isinstance(node, ast.Call):
                continue
            name = _dotted_name(node.func)
            short = name.split(".")[-1]

            # S002 — unguarded outbound fetch (attacker-controllable host)
            if name in _NETWORK_SINKS or name.endswith(".urlopen"):
                url_arg = node.args[0] if node.args else None
                if url_arg is not None and _url_host_is_dynamic(url_arg):
                    found.append(
                        self._f(
                            "S002",
                            "Outbound request to a non-constant URL (SSRF risk)",
                            Severity.MEDIUM,
                            loc,
                            node.lineno,
                            f"{name}(...) called with a dynamic URL; validate against an allowlist",
                            sink=name,
                        )
                    )

            # S003 — unsafe deserialization
            if name in _DESERIALIZE_SINKS:
                found.append(
                    self._f(
                        "S003",
                        "Unsafe deserialization",
                        Severity.HIGH,
                        loc,
                        node.lineno,
                        f"{name}(...) can execute arbitrary code on crafted input",
                        sink=name,
                    )
                )
            if name in ("yaml.load", "yaml.load_all") and not self._yaml_is_safe(node):
                found.append(
                    self._f(
                        "S003",
                        "Unsafe YAML deserialization",
                        Severity.HIGH,
                        loc,
                        node.lineno,
                        "yaml.load without SafeLoader runs arbitrary code; use yaml.safe_load",
                        sink="yaml.load",
                    )
                )

            # S004 — dynamic code execution
            if name in _EXEC_SINKS and node.args and not _is_constant_str(node.args[0]):
                found.append(
                    self._f(
                        "S004",
                        "Dynamic code execution",
                        Severity.CRITICAL,
                        loc,
                        node.lineno,
                        f"{name}(...) on a non-literal argument executes attacker-controlled code",
                        sink=name,
                    )
                )

            # S005 — SQL injection
            if short in _SQL_METHODS and node.args and _looks_dynamic(node.args[0]):
                found.append(
                    self._f(
                        "S005",
                        "Possible SQL injection",
                        Severity.HIGH,
                        loc,
                        node.lineno,
                        f"{short}(...) builds its query with string formatting; use parameters",
                        sink=short,
                    )
                )

            # S006 — shell execution
            if name in _SHELL_SINKS:
                found.append(
                    self._f(
                        "S006",
                        "Shell command execution",
                        Severity.HIGH,
                        loc,
                        node.lineno,
                        f"{name}(...) runs a shell command",
                        sink=name,
                    )
                )
            if name in _SUBPROCESS_SINKS and self._has_shell_true(node):
                found.append(
                    self._f(
                        "S006",
                        "subprocess with shell=True",
                        Severity.HIGH,
                        loc,
                        node.lineno,
                        f"{name}(..., shell=True) is vulnerable to command injection",
                        sink=name,
                    )
                )
        return found

    @staticmethod
    def _yaml_is_safe(node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == "Loader":
                loader = _dotted_name(kw.value) if isinstance(kw.value, ast.Attribute) else ""
                name = _dotted_name(kw.value) if isinstance(kw.value, ast.Name) else loader
                return "Safe" in name or "safe" in name
        return False

    @staticmethod
    def _has_shell_true(node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
        return False

    # ------------------------------------------------------------------
    # S007: Description-Code Inconsistency
    # ------------------------------------------------------------------
    def _scan_dci(self, tree: ast.AST, loc: str) -> list[Finding]:
        found: list[Finding] = []
        for fn in self._tool_functions(tree):
            text = f"{fn.name} {fn.description}".lower()
            # Only flag tools that *present* as read-only and never signal a write.
            reads = any(_token_in(t, text) for t in _READONLY_TOKENS)
            writes = any(_token_in(t, text) for t in _WRITE_TOKENS)
            if not reads or writes:
                continue
            cap = _CapabilityVisitor()
            cap.visit(fn.node)
            # Network I/O is intentionally NOT a DCI signal: a read-only tool
            # fetching from an API to return data is normal (search_*, get_*,
            # fetch_*), so flagging it produces false positives on every API
            # client. Only a read-only tool that WRITES to disk or EXECUTES
            # commands is genuinely inconsistent with its presentation.
            mismatches: list[str] = []
            if cap.fs_write:
                mismatches.append("writes to the filesystem")
            if cap.exec:
                mismatches.append("executes commands")
            if mismatches:
                found.append(
                    self._f(
                        "S007",
                        "Description-Code Inconsistency (read-only tool with side effects)",
                        Severity.HIGH,
                        loc,
                        fn.lineno,
                        f"Tool '{fn.name}' presents as read-only but its handler "
                        f"{', '.join(mismatches)}",
                        tool=fn.name,
                        capabilities=mismatches,
                    )
                )
        return found

    def _tool_functions(self, tree: ast.AST) -> list[_ToolFn]:
        out: list[_ToolFn] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            desc = self._tool_decorator_description(node)
            if desc is None:
                continue  # not a tool handler
            if not desc:
                desc = ast.get_docstring(node) or ""
            out.append(_ToolFn(name=node.name, description=desc, node=node, lineno=node.lineno))
        return out

    @staticmethod
    def _tool_decorator_description(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
        """Return the tool description if ``fn`` is decorated as an MCP tool,
        else None. An empty string means 'is a tool, description in docstring'."""
        for dec in fn.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            name = _dotted_name(target)
            short = name.split(".")[-1]
            if short not in ("tool", "add_tool") and name not in _TOOL_DECORATORS:
                continue
            # description= kwarg or first string positional arg
            if isinstance(dec, ast.Call):
                for kw in dec.keywords:
                    if kw.arg == "description" and _is_constant_str(kw.value):
                        return str(kw.value.value)  # type: ignore[attr-defined]
                for a in dec.args:
                    if _is_constant_str(a):
                        return str(a.value)  # type: ignore[attr-defined]
            return ""
        return None

    @staticmethod
    def _f(
        rule_id: str,
        title: str,
        severity: Severity,
        loc: str,
        lineno: int,
        description: str,
        **detail: object,
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            title=title,
            description=description,
            severity=severity,
            target=f"{loc}:{lineno}",
            location="source",
            detail={"line": lineno, **detail},
        )


def _token_in(token: str, text: str) -> bool:
    """Word-ish membership: token as a standalone segment of name/description."""
    import re

    return re.search(rf"(?:^|[^a-z]){re.escape(token)}(?:[^a-z]|$)", text) is not None


@dataclass
class SourceScanResult:
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)


def analyze_path(path: Path, max_files: int = 500) -> SourceScanResult:
    """Analyze a single .py file or every .py file under a directory."""
    analyzer = SourceAnalyzer()
    result = SourceScanResult()
    if path.is_file():
        files = [path] if path.suffix == ".py" else []
    else:
        files = sorted(
            p
            for p in path.rglob("*.py")
            if not any(
                part in {".venv", "venv", "node_modules", ".git", "__pycache__", "test", "tests"}
                for part in p.parts
            )
        )[:max_files]
    for f in files:
        result.findings.extend(analyzer.analyze_file(f))
        result.files_scanned += 1
    return result
