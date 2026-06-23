"""MCP Registry API client — fetch and parse the official MCP server registry."""

from __future__ import annotations

import contextlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from platformdirs import user_data_dir


@dataclass
class PackageRef:
    """An installable package reference for an MCP server."""

    registry_type: str
    identifier: str
    version: str
    transport: str
    registry_base_url: str | None = None


@dataclass
class RegistryEntry:
    """A parsed MCP server entry from the registry."""

    name: str
    title: str
    description: str
    version: str
    packages: list[PackageRef] = field(default_factory=list)
    repository_url: str = ""
    repository_source: str = ""
    categories: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    is_latest: bool = False
    status: str = "unknown"


class RegistryClient:
    """Client for the official MCP Registry API.

    Handles cursor-based pagination, response parsing, local caching,
    rate limiting, and graceful error recovery.
    """

    BASE_URL = "https://registry.modelcontextprotocol.io/v0.1/servers"

    def __init__(self, cache_ttl: int = 86400) -> None:
        """Initialise the client.

        Args:
            cache_ttl: Cache time-to-live in seconds. Default: 24 hours.
        """
        self._cache_ttl = cache_ttl

    # -- Public API -------------------------------------------------------

    def list_servers(self, limit: int = 100, latest_only: bool = True) -> list[RegistryEntry]:
        """Fetch all servers from the registry, walking all pagination pages.

        Args:
            limit: Page size for each HTTP request.
            latest_only: When True, only return entries whose ``_meta``
                ``isLatest`` flag is true.

        Returns:
            Parsed RegistryEntry objects. On network failure, falls back
            to cached data; returns an empty list if no cache is available.
        """
        all_raw_servers: list[dict[str, Any]] = []
        cursor: str | None = None

        try:
            while True:
                page = self.fetch_page(limit=limit, cursor=cursor)
                servers = page.get("servers", [])
                all_raw_servers.extend(servers)

                metadata = page.get("metadata", {})
                cursor = metadata.get("nextCursor")
                if cursor is None:
                    break

                # Rate limiting: 1 request per second between pages
                time.sleep(1)
        except Exception:
            # Network or parse error — attempt to load from cache
            cached = self._load_cache()
            if cached is not None:
                all_raw_servers = cached.get("servers", [])
            else:
                return []

        # Persist raw data so it is available on the next failure
        with contextlib.suppress(Exception):
            self._save_cache({"servers": all_raw_servers})

        return self._parse_servers(all_raw_servers, latest_only=latest_only)

    def fetch_page(self, limit: int = 100, cursor: str | None = None) -> dict[str, Any]:
        """Fetch a single raw page from the registry API.

        Args:
            limit: Maximum number of servers per page.
            cursor: Opaque pagination cursor returned by the previous page.

        Returns:
            Parsed JSON response as a dict.

        Raises:
            httpx.HTTPError: On non-2xx responses or network failures.
        """
        params: dict[str, str] = {"limit": str(limit)}
        if cursor:
            params["cursor"] = cursor

        response = httpx.get(self.BASE_URL, params=params, timeout=30.0)
        response.raise_for_status()
        return response.json()  # type: ignore[no-any-return]

    def get_scannable_servers(self, limit: int = 100) -> list[tuple[str, str, str]]:
        """Return servers that include at least one installable package.

        Remote-only servers (those that only have ``remotes`` entries
        and no ``packages``) are excluded because they cannot be scanned
        via a package manager.

        Returns:
            List of ``(server_name, package_identifier, transport)`` tuples.
        """
        entries = self.list_servers(limit=limit, latest_only=True)
        result: list[tuple[str, str, str]] = []
        for entry in entries:
            for pkg in entry.packages:
                result.append((entry.name, pkg.identifier, pkg.transport))
        return result

    # -- Parsing ----------------------------------------------------------

    def _parse_entry(self, raw_server: dict[str, Any], raw_meta: dict[str, Any]) -> RegistryEntry:
        """Parse one server + meta dict pair into a RegistryEntry.

        Args:
            raw_server: The ``server`` object from the API response.
            raw_meta: The ``_meta`` object from the API response.

        Returns:
            A populated RegistryEntry.
        """
        # Packages
        packages: list[PackageRef] = []
        for pkg_data in raw_server.get("packages", []):
            transport_raw = pkg_data.get("transport", {})
            if isinstance(transport_raw, dict):
                transport_type = transport_raw.get("type", "")
            else:
                transport_type = str(transport_raw)

            packages.append(
                PackageRef(
                    registry_type=pkg_data.get("registryType", ""),
                    identifier=pkg_data.get("identifier", ""),
                    version=pkg_data.get("version", ""),
                    transport=transport_type,
                    registry_base_url=pkg_data.get("registryBaseUrl"),
                )
            )

        # Repository
        repo = raw_server.get("repository") or {}
        repository_url = repo.get("url", "")
        repository_source = repo.get("source", "")

        # Official meta (status, isLatest)
        official_meta = raw_meta.get("io.modelcontextprotocol.registry/official") or {}
        is_latest = bool(official_meta.get("isLatest", False))
        status = str(official_meta.get("status", "unknown"))

        # Publisher-provided meta (categories, keywords)
        publisher_meta = raw_meta.get("io.modelcontextprotocol.registry/publisher-provided") or {}
        categories: list[str] = publisher_meta.get("categories", [])
        keywords: list[str] = publisher_meta.get("keywords", [])

        return RegistryEntry(
            name=raw_server.get("name", ""),
            title=raw_server.get("title", ""),
            description=raw_server.get("description", ""),
            version=raw_server.get("version", ""),
            packages=packages,
            repository_url=repository_url,
            repository_source=repository_source,
            categories=list(categories),
            keywords=list(keywords),
            is_latest=is_latest,
            status=status,
        )

    def _parse_servers(
        self, raw_servers: list[dict[str, Any]], latest_only: bool
    ) -> list[RegistryEntry]:
        """Parse a list of raw server dicts, optionally filtering by isLatest."""
        entries: list[RegistryEntry] = []
        for raw in raw_servers:
            server_data = raw.get("server", {})
            meta_data = raw.get("_meta", {})
            entry = self._parse_entry(server_data, meta_data)
            if latest_only and not entry.is_latest:
                continue
            entries.append(entry)
        return entries

    # -- Caching ----------------------------------------------------------

    def _cache_path(self) -> Path:
        """Return the filesystem path for the registry cache file."""
        return Path(user_data_dir("mcpradar", ensure_exists=True)) / "registry_cache.json"

    def _load_cache(self) -> dict[str, Any] | None:
        """Load cached registry data if it exists and has not expired.

        Returns:
            The cached dict on success, or ``None`` if the cache is
            missing, corrupt, or expired.
        """
        path = self._cache_path()
        if not path.exists():
            return None

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None

        cached_at = data.get("_cached_at", 0)
        if time.time() - cached_at > self._cache_ttl:
            return None

        return data  # type: ignore[no-any-return]

    def _save_cache(self, data: dict[str, Any]) -> None:
        """Save registry data to the local cache file with a timestamp.

        The ``_cached_at`` key is set automatically; callers should not
        include it in *data*.
        """
        data["_cached_at"] = time.time()
        self._cache_path().write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
