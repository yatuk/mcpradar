"""Protocol adapters for legacy session and MCP 2026 stateless HTTP."""

from __future__ import annotations

from types import TracebackType
from typing import Any

import httpx

from mcpradar.scanner.protocol import MCP_V2_PROFILE


class ProtocolNotSupportedError(RuntimeError):
    """The endpoint does not support the requested MCP protocol profile."""


class ProtocolResponseError(RuntimeError):
    """The endpoint returned a malformed or failed MCP response."""


class ResultView:
    """Attribute view over JSON objects returned by a stateless server."""

    def __init__(self, value: dict[str, Any]) -> None:
        self._value = value

    def __getattr__(self, name: str) -> object:
        try:
            return _view(self._value[name])
        except KeyError as exc:
            raise AttributeError(name) from exc

    def model_dump(self) -> dict[str, Any]:
        return self._value


def _view(value: object) -> object:
    if isinstance(value, dict):
        return ResultView(value)
    if isinstance(value, list):
        return [_view(item) for item in value]
    return value


class StatelessHttpSession:
    """Minimal MCP 2026-07-28 stateless client used by the scanner."""

    def __init__(
        self,
        url: str,
        *,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.url = url
        self._client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            transport=transport,
        )
        self._request_id = 0

    async def __aenter__(self) -> StatelessHttpSession:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self._client.aclose()

    async def discover(self) -> ResultView:
        return await self._rpc("server/discover", {})

    async def list_tools(self, cursor: str | None = None) -> ResultView:
        return await self._rpc("tools/list", _cursor_params(cursor))

    async def list_prompts(self, cursor: str | None = None) -> ResultView:
        return await self._rpc("prompts/list", _cursor_params(cursor))

    async def list_resources(self, cursor: str | None = None) -> ResultView:
        return await self._rpc("resources/list", _cursor_params(cursor))

    async def list_resource_templates(self, cursor: str | None = None) -> ResultView:
        return await self._rpc("resources/templates/list", _cursor_params(cursor))

    async def call_tool(self, name: str, arguments: dict[str, object]) -> ResultView:
        return await self._rpc("tools/call", {"name": name, "arguments": arguments})

    async def _rpc(self, method: str, params: dict[str, object]) -> ResultView:
        self._request_id += 1
        request_params = dict(params)
        request_params["_meta"] = {
            "io.modelcontextprotocol/protocolVersion": MCP_V2_PROFILE,
            "io.modelcontextprotocol/clientInfo": {
                "name": "mcpradar",
                "version": _scanner_version(),
            },
            "io.modelcontextprotocol/clientCapabilities": {},
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "MCP-Protocol-Version": MCP_V2_PROFILE,
            "Mcp-Method": method,
        }
        name = params.get("name")
        if isinstance(name, str):
            headers["Mcp-Name"] = name
        response = await self._client.post(
            self.url,
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": self._request_id,
                "method": method,
                "params": request_params,
            },
        )
        if response.status_code in {400, 404, 405, 426}:
            raise ProtocolNotSupportedError(f"server rejected MCP {MCP_V2_PROFILE}")
        try:
            payload = response.json()
        except ValueError:
            raise ProtocolResponseError("stateless MCP response is not JSON") from None
        if not isinstance(payload, dict):
            raise ProtocolResponseError("stateless MCP response is not an object")
        error = payload.get("error")
        if isinstance(error, dict):
            if error.get("code") == -32601:
                raise ProtocolNotSupportedError("server/discover is not supported")
            raise ProtocolResponseError(str(error.get("message", "MCP request failed")))
        result = payload.get("result")
        if not isinstance(result, dict):
            raise ProtocolResponseError("stateless MCP response has no result object")
        return ResultView(result)


def _cursor_params(cursor: str | None) -> dict[str, object]:
    return {"cursor": cursor} if cursor else {}


def _scanner_version() -> str:
    from mcpradar import __version__

    return __version__
