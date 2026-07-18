"""MCP 2026 stateless HTTP adapter tests."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from mcpradar.scanner.protocol_adapter import (
    ProtocolNotSupportedError,
    ProtocolResponseError,
    ResultView,
    StatelessHttpSession,
)


def test_discovery_and_list_requests_carry_per_request_metadata() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        body = json.loads(request.content)
        method = body["method"]
        if method == "server/discover":
            result = {
                "supportedVersions": ["2026-07-28"],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "demo", "version": "1.0"},
            }
        else:
            result = {"tools": [], "nextCursor": None, "ttlMs": 500}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": result})

    async def run() -> None:
        async with StatelessHttpSession(
            "https://server.example/mcp",
            transport=httpx.MockTransport(handler),
        ) as session:
            discovery = await session.discover()
            assert discovery.supportedVersions == ["2026-07-28"]
            tools = await session.list_tools()
            assert tools.ttlMs == 500

    asyncio.run(run())
    assert [request.headers["mcp-method"] for request in requests] == [
        "server/discover",
        "tools/list",
    ]
    assert all(request.headers["mcp-protocol-version"] == "2026-07-28" for request in requests)
    for request in requests:
        body = json.loads(request.content)
        assert body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] == ("2026-07-28")


def test_named_call_has_mcp_name_header() -> None:
    seen_name = ""

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal seen_name
        seen_name = request.headers.get("mcp-name", "")
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

    async def run() -> None:
        async with StatelessHttpSession(
            "https://server.example/mcp",
            transport=httpx.MockTransport(handler),
        ) as session:
            await session.call_tool("search", {"query": "otters"})

    asyncio.run(run())
    assert seen_name == "search"


def test_method_not_found_allows_legacy_fallback() -> None:
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "error": {"code": -32601, "message": "Method not found"},
            },
        )
    )

    async def run() -> None:
        async with StatelessHttpSession(
            "https://server.example/mcp", transport=transport
        ) as session:
            with pytest.raises(ProtocolNotSupportedError):
                await session.discover()

    asyncio.run(run())


def test_result_view_wraps_nested_data_and_missing_attributes() -> None:
    view = ResultView({"nested": {"value": 1}, "items": [{"name": "a"}]})
    assert view.nested.value == 1  # type: ignore[union-attr]
    assert view.items[0].name == "a"  # type: ignore[index, union-attr]
    assert view.model_dump()["nested"] == {"value": 1}
    with pytest.raises(AttributeError):
        _ = view.missing


@pytest.mark.parametrize("status", [400, 404, 405, 426])
def test_http_rejection_is_not_supported(status: int) -> None:
    transport = httpx.MockTransport(lambda _request: httpx.Response(status))

    async def run() -> None:
        async with StatelessHttpSession(
            "https://server.example/mcp", transport=transport
        ) as session:
            with pytest.raises(ProtocolNotSupportedError):
                await session.list_tools()

    asyncio.run(run())


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (httpx.Response(200, text="not-json"), "not JSON"),
        (httpx.Response(200, json=[]), "not an object"),
        (
            httpx.Response(
                200,
                json={"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "bad"}},
            ),
            "bad",
        ),
        (httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": []}), "no result"),
    ],
)
def test_malformed_rpc_responses_raise(response: httpx.Response, message: str) -> None:
    transport = httpx.MockTransport(lambda _request: response)

    async def run() -> None:
        async with StatelessHttpSession(
            "https://server.example/mcp", transport=transport
        ) as session:
            with pytest.raises(ProtocolResponseError, match=message):
                await session.list_resources()

    asyncio.run(run())


def test_all_list_methods_and_cursor_are_serialized() -> None:
    methods: list[tuple[str, dict[str, object]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        methods.append((body["method"], body["params"]))
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": {}})

    async def run() -> None:
        async with StatelessHttpSession(
            "https://server.example/mcp", transport=httpx.MockTransport(handler)
        ) as session:
            await session.list_tools("next")
            await session.list_prompts("next")
            await session.list_resources("next")
            await session.list_resource_templates("next")

    asyncio.run(run())
    assert [method for method, _params in methods] == [
        "tools/list",
        "prompts/list",
        "resources/list",
        "resources/templates/list",
    ]
    assert all(params["cursor"] == "next" for _method, params in methods)
