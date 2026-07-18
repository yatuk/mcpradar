"""Package fetching for source-level scanning.

Resolves a package reference to a local source directory by downloading and
extracting the distribution artifact directly from the registry — no install,
so no lifecycle script (npm ``postinstall``, pip ``setup.py``) is ever executed.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
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

from mcpradar.network.safe_http import SafeHttpError, SafeUrlPolicy, safe_get

_MAX_BYTES = 80 * 1024 * 1024  # 80 MB cap — a source package should be small
_MAX_EXPANDED_BYTES = 512 * 1024 * 1024
_MAX_MEMBER_BYTES = 128 * 1024 * 1024
_MAX_MEMBERS = 10_000
_MAX_PATH_DEPTH = 32
_MAX_COMPRESSION_RATIO = 100
_TIMEOUT = 60.0
_COMMIT_RE = re.compile(r"[0-9a-fA-F]{40}")
_JSON_POLICY = SafeUrlPolicy(max_response_bytes=4 * 1024 * 1024)
_PACKAGE_POLICY = SafeUrlPolicy(max_response_bytes=_MAX_BYTES)


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
    dist = entry.get("dist", {})
    tarball = dist.get("tarball")
    if not tarball:
        raise FetchError(f"npm tarball URL missing for '{name}'")
    integrity = dist.get("integrity") or (
        f"sha1-{_hex_to_b64(dist['shasum'])}" if dist.get("shasum") else ""
    )
    if not integrity:
        raise FetchError(f"npm integrity metadata missing for '{name}@{version}'")
    data = _download(str(tarball), str(integrity))
    _safe_extract_tar(data, dest)
    _write_provenance(
        dest,
        kind="npm",
        identifier=f"{name}@{version}",
        source_url=str(tarball),
        digest=_digest_label(data, str(integrity)),
    )
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
    digest = sdist.get("digests", {}).get("sha256")
    if not digest:
        raise FetchError(f"PyPI SHA-256 digest missing for '{name}'")
    expected = f"sha256-{_hex_to_b64(str(digest))}"
    data = _download(sdist["url"], expected)
    if sdist["url"].endswith(".zip"):
        _safe_extract_zip(data, dest)
    else:
        _safe_extract_tar(data, dest)
    _write_provenance(
        dest,
        kind="pypi",
        identifier=f"{name}=={version or meta.get('info', {}).get('version', '')}",
        source_url=str(sdist["url"]),
        digest=f"sha256:{digest}",
    )
    # sdists extract to a single "<name>-<version>/" directory.
    subdirs = [p for p in dest.iterdir() if p.is_dir()]
    return subdirs[0] if len(subdirs) == 1 else dest


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------
def _fetch_github(url: str, dest: Path) -> Path:
    if shutil.which("git") is None:
        raise FetchError("git is required to fetch a GitHub repository")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "github.com":
        raise FetchError("git sources must use an https://github.com URL")
    commit = parsed.fragment
    if not _COMMIT_RE.fullmatch(commit):
        raise FetchError("GitHub source must be pinned with #<40-character-commit-sha>")
    clone_url = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.query, "")
    )
    target = dest / "repo"
    try:
        _run_git(["init", str(target)])
        _run_git(["-C", str(target), "remote", "add", "origin", clone_url])
        _run_git(["-C", str(target), "fetch", "--depth", "1", "origin", commit])
        _run_git(["-C", str(target), "checkout", "--detach", "FETCH_HEAD"])
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode("utf-8", "replace")[:200]
        raise FetchError(f"git clone failed: {detail}") from None
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FetchError(f"git clone failed: {exc}") from None
    _write_provenance(
        target,
        kind="github",
        identifier=parsed.path.strip("/"),
        source_url=clone_url,
        digest=f"git:{commit.lower()}",
    )
    return target


def _run_git(args: list[str]) -> None:
    subprocess.run(
        ["git", *args],
        capture_output=True,
        timeout=120,
        check=True,
    )


# ---------------------------------------------------------------------------
# HTTP + safe extraction
# ---------------------------------------------------------------------------
def _get_json(url: str) -> dict[str, Any]:
    with httpx.Client(timeout=_TIMEOUT, follow_redirects=False) as client:
        response = safe_get(client, url, _JSON_POLICY)
        response.raise_for_status()
        return response.json()  # type: ignore[no-any-return]


def _download(url: str, expected_integrity: str) -> bytes:
    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=False) as client:
            response = safe_get(client, url, _PACKAGE_POLICY)
            response.raise_for_status()
            data = response.content
    except SafeHttpError as exc:
        raise FetchError(f"package URL rejected: {exc}") from None
    except httpx.HTTPError as exc:
        raise FetchError(f"package download failed: {exc}") from None
    _verify_integrity(data, expected_integrity)
    return data


def _safe_extract_tar(data: bytes, dest: Path) -> None:
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
            members = tar.getmembers()
            _validate_archive_members(
                [(member.name, member.size, member.isdir(), member.isreg()) for member in members],
                compressed_size=len(data),
                dest=dest,
            )
            if any(member.issym() or member.islnk() or member.isdev() for member in members):
                raise FetchError("archive links and device entries are not allowed")
            tar.extractall(dest, members=members, filter="data")
    except (tarfile.TarError, OSError) as exc:
        raise FetchError(f"tar extraction failed: {exc}") from None


def _safe_extract_zip(data: bytes, dest: Path) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            _validate_archive_members(
                [
                    (info.filename, info.file_size, info.is_dir(), not info.is_dir())
                    for info in infos
                ],
                compressed_size=len(data),
                dest=dest,
            )
            for info in infos:
                unix_mode = info.external_attr >> 16
                if unix_mode & 0o170000 == 0o120000:
                    raise FetchError(f"archive symlink is not allowed: {info.filename}")
            zf.extractall(dest)
    except (zipfile.BadZipFile, OSError) as exc:
        raise FetchError(f"zip extraction failed: {exc}") from None


def _validate_archive_members(
    members: list[tuple[str, int, bool, bool]], *, compressed_size: int, dest: Path
) -> None:
    if len(members) > _MAX_MEMBERS:
        raise FetchError(f"archive contains more than {_MAX_MEMBERS} entries")
    expanded = 0
    destination = dest.resolve()
    for name, size, is_dir, is_file in members:
        normalized = name.replace("\\", "/")
        parts = [part for part in normalized.split("/") if part not in {"", "."}]
        if normalized.startswith("/") or ".." in parts:
            raise FetchError(f"unsafe path in archive: {name}")
        if len(parts) > _MAX_PATH_DEPTH:
            raise FetchError(f"archive path exceeds {_MAX_PATH_DEPTH} components: {name}")
        target = (dest / Path(*parts)).resolve()
        if not target.is_relative_to(destination):
            raise FetchError(f"unsafe path in archive: {name}")
        if not is_dir and not is_file:
            raise FetchError(f"unsupported archive member type: {name}")
        if size < 0 or size > _MAX_MEMBER_BYTES:
            raise FetchError(f"archive member exceeds size limit: {name}")
        expanded += size
        if expanded > _MAX_EXPANDED_BYTES:
            raise FetchError("archive expanded size exceeds configured limit")
    if compressed_size and expanded > compressed_size * _MAX_COMPRESSION_RATIO:
        raise FetchError("archive compression ratio exceeds configured limit")


def _verify_integrity(data: bytes, integrity: str) -> None:
    token = integrity.split()[0]
    try:
        algorithm, encoded = token.split("-", 1)
    except ValueError:
        raise FetchError("invalid artifact integrity metadata") from None
    if algorithm not in {"sha256", "sha384", "sha512", "sha1"}:
        raise FetchError(f"unsupported artifact digest: {algorithm}")
    actual = base64.b64encode(hashlib.new(algorithm, data).digest()).decode().rstrip("=")
    if actual != encoded.rstrip("="):
        raise FetchError("artifact digest does not match registry metadata")


def _hex_to_b64(value: str) -> str:
    try:
        return base64.b64encode(bytes.fromhex(value)).decode()
    except ValueError:
        raise FetchError("invalid hexadecimal digest in registry metadata") from None


def _digest_label(data: bytes, integrity: str) -> str:
    algorithm = integrity.split("-", 1)[0]
    return f"{algorithm}:{hashlib.new(algorithm, data).hexdigest()}"


def _write_provenance(
    dest: Path, *, kind: str, identifier: str, source_url: str, digest: str
) -> None:
    payload = {
        "schema_version": "1.0",
        "kind": kind,
        "identifier": identifier,
        "source_url": source_url,
        "digest": digest,
    }
    (dest / ".mcpradar-provenance.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )
