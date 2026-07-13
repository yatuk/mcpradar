"""Package fetching for source-level scanning.

Resolves a package reference to a local source directory by downloading and
extracting the distribution artifact directly from the registry — no install,
so no lifecycle script (npm ``postinstall``, pip ``setup.py``) is ever executed.
"""

from __future__ import annotations

import io
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.parse
import zipfile
from pathlib import Path
from typing import Any

import httpx

_MAX_BYTES = 80 * 1024 * 1024  # 80 MB cap — a source package should be small
_TIMEOUT = 60.0


class FetchError(RuntimeError):
    """A package could not be fetched or safely extracted."""


def parse_ref(ref: str) -> tuple[str, str] | None:
    """Classify a reference, or return None if it is a local path.

    Recognized: ``npm:<pkg>``, ``pip:``/``pypi:<pkg>``, a github.com URL,
    ``gh:<owner>/<repo>``, or any ``*.git`` URL.
    """
    ref = ref.strip()
    if ref.startswith("npm:"):
        return ("npm", ref[4:])
    if ref.startswith("pip:"):
        return ("pypi", ref[4:])
    if ref.startswith("pypi:"):
        return ("pypi", ref[5:])
    if ref.startswith("gh:"):
        return ("github", "https://github.com/" + ref[3:])
    if re.match(r"https?://github\.com/[^/]+/[^/]+", ref):
        return ("github", ref)
    if ref.endswith(".git") or ref.startswith("git@"):
        return ("github", ref)
    return None


def is_ref(s: str) -> bool:
    return parse_ref(s) is not None


def resolve_source(path_or_ref: str, workdir: Path | None = None) -> Path:
    """Return a local source directory for a path or a package reference.

    A local path is returned unchanged; a reference is fetched into ``workdir``
    (a fresh temp dir when omitted — the caller owns cleanup).
    """
    parsed = parse_ref(path_or_ref)
    if parsed is None:
        return Path(path_or_ref)
    kind, identifier = parsed
    return fetch_source(kind, identifier, workdir)


def fetch_source(kind: str, identifier: str, workdir: Path | None = None) -> Path:
    dest = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="mcpradar-fetch-"))
    dest.mkdir(parents=True, exist_ok=True)
    if kind == "npm":
        return _fetch_npm(identifier, dest)
    if kind == "pypi":
        return _fetch_pypi(identifier, dest)
    if kind == "github":
        return _fetch_github(identifier, dest)
    raise FetchError(f"unknown package kind: {kind}")


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------
def _fetch_npm(pkg: str, dest: Path) -> Path:
    name, _, version = pkg.partition("@") if not pkg.startswith("@") else _split_scoped(pkg)
    quoted = urllib.parse.quote(name, safe="@")
    try:
        meta = _get_json(f"https://registry.npmjs.org/{quoted}")
    except Exception as exc:
        raise FetchError(f"npm metadata fetch failed for '{name}': {exc}") from None
    if not version:
        version = str(meta.get("dist-tags", {}).get("latest", ""))
    versions = meta.get("versions", {})
    entry = versions.get(version) or (versions.get(next(iter(versions), "")) if versions else None)
    if not isinstance(entry, dict):
        raise FetchError(f"npm version not found for '{name}@{version or 'latest'}'")
    tarball = entry.get("dist", {}).get("tarball")
    if not tarball:
        raise FetchError(f"npm tarball URL missing for '{name}'")
    data = _download(tarball)
    _safe_extract_tar(data, dest)
    # npm tarballs contain a single top-level "package/" directory.
    pkg_dir = dest / "package"
    return pkg_dir if pkg_dir.is_dir() else dest


def _split_scoped(pkg: str) -> tuple[str, str, str]:
    # "@scope/name@version" or "@scope/name"
    rest = pkg[1:]
    scope, _, tail = rest.partition("/")
    name, _, version = tail.partition("@")
    return (f"@{scope}/{name}", "@", version)


# ---------------------------------------------------------------------------
# PyPI
# ---------------------------------------------------------------------------
def _fetch_pypi(pkg: str, dest: Path) -> Path:
    name, _, version = pkg.partition("==")
    url = (
        f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json"
        if not version
        else f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/json"
    )
    try:
        meta = _get_json(url)
    except Exception as exc:
        raise FetchError(f"PyPI metadata fetch failed for '{name}': {exc}") from None
    sdist = next((u for u in meta.get("urls", []) if u.get("packagetype") == "sdist"), None)
    if not sdist:
        raise FetchError(f"no source distribution (sdist) published for '{name}'")
    data = _download(sdist["url"])
    if sdist["url"].endswith(".zip"):
        _safe_extract_zip(data, dest)
    else:
        _safe_extract_tar(data, dest)
    # sdists extract to a single "<name>-<version>/" directory.
    subdirs = [p for p in dest.iterdir() if p.is_dir()]
    return subdirs[0] if len(subdirs) == 1 else dest


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------
def _fetch_github(url: str, dest: Path) -> Path:
    if shutil.which("git") is None:
        raise FetchError("git is required to fetch a GitHub repository")
    target = dest / "repo"
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, str(target)],
            capture_output=True,
            timeout=120,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode("utf-8", "replace")[:200]
        raise FetchError(f"git clone failed: {detail}") from None
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FetchError(f"git clone failed: {exc}") from None
    return target


# ---------------------------------------------------------------------------
# HTTP + safe extraction
# ---------------------------------------------------------------------------
def _get_json(url: str) -> dict[str, Any]:
    resp = httpx.get(url, timeout=_TIMEOUT, follow_redirects=True)
    resp.raise_for_status()
    return resp.json()  # type: ignore[no-any-return]


def _download(url: str) -> bytes:
    with httpx.stream("GET", url, timeout=_TIMEOUT, follow_redirects=True) as resp:
        resp.raise_for_status()
        buf = bytearray()
        for chunk in resp.iter_bytes():
            buf += chunk
            if len(buf) > _MAX_BYTES:
                raise FetchError(f"package exceeds {_MAX_BYTES // (1024 * 1024)} MB cap")
        return bytes(buf)


def _safe_extract_tar(data: bytes, dest: Path) -> None:
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
            # filter='data' (3.12+) rejects path traversal, absolute paths,
            # and unsafe members (device/link escapes).
            tar.extractall(dest, filter="data")
    except (tarfile.TarError, OSError) as exc:
        raise FetchError(f"tar extraction failed: {exc}") from None


def _safe_extract_zip(data: bytes, dest: Path) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for member in zf.namelist():
                target = (dest / member).resolve()
                if not str(target).startswith(str(dest.resolve())):
                    raise FetchError(f"unsafe path in archive: {member}")
            zf.extractall(dest)
    except (zipfile.BadZipFile, OSError) as exc:
        raise FetchError(f"zip extraction failed: {exc}") from None
