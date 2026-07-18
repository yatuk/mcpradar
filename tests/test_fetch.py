"""Tests for package fetching (mcpradar.fetch)."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest

from mcpradar.fetch import FetchError, is_ref, parse_ref, resolve_source
from mcpradar.fetch import fetcher as fx


class TestParseRef:
    def test_npm(self) -> None:
        assert parse_ref("npm:@scope/pkg") == ("npm", "@scope/pkg")

    def test_pip_variants(self) -> None:
        assert parse_ref("pip:requests") == ("pypi", "requests")
        assert parse_ref("pypi:requests") == ("pypi", "requests")

    def test_github(self) -> None:
        assert parse_ref("https://github.com/owner/repo") == (
            "github",
            "https://github.com/owner/repo",
        )
        assert parse_ref("gh:owner/repo") == ("github", "https://github.com/owner/repo")

    def test_local_path_is_none(self) -> None:
        assert parse_ref("./src") is None
        assert parse_ref("/abs/path") is None
        assert is_ref("npm:x") is True
        assert is_ref("./x") is False


class TestResolveLocal:
    def test_local_path_returned_unchanged(self, tmp_path: Path) -> None:
        assert resolve_source(str(tmp_path)) == tmp_path


def _make_npm_tarball(files: dict[str, str]) -> bytes:
    """Build an npm-style tarball (single top-level 'package/' dir)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(f"package/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _integrity(data: bytes, algorithm: str = "sha512") -> str:
    digest = base64.b64encode(hashlib.new(algorithm, data).digest()).decode()
    return f"{algorithm}-{digest}"


class TestNpmFetch:
    def test_fetch_and_extract(self, tmp_path: Path, monkeypatch) -> None:
        tarball = _make_npm_tarball(
            {"package.json": json.dumps({"name": "demo", "version": "1.0.0"})}
        )
        monkeypatch.setattr(
            fx,
            "_get_json",
            lambda url: {
                "dist-tags": {"latest": "1.0.0"},
                "versions": {
                    "1.0.0": {
                        "dist": {
                            "tarball": "https://x/demo.tgz",
                            "integrity": _integrity(tarball),
                        }
                    }
                },
            },
        )
        monkeypatch.setattr(fx, "_download", lambda url, integrity: tarball)
        src = resolve_source("npm:demo", workdir=tmp_path)
        assert (src / "package.json").exists()
        assert src.name == "package"
        assert (tmp_path / ".mcpradar-provenance.json").exists()

    def test_missing_version_errors(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(
            fx, "_get_json", lambda url: {"dist-tags": {"latest": "9.9.9"}, "versions": {}}
        )
        with pytest.raises(FetchError):
            resolve_source("npm:demo", workdir=tmp_path)


class TestPypiFetch:
    def test_fetch_sdist(self, tmp_path: Path, monkeypatch) -> None:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            data = b"print('hi')"
            info = tarfile.TarInfo("demo-1.0.0/server.py")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        monkeypatch.setattr(
            fx,
            "_get_json",
            lambda url: {
                "info": {"version": "1.0.0"},
                "urls": [
                    {
                        "packagetype": "sdist",
                        "url": "https://x/demo.tar.gz",
                        "digests": {"sha256": hashlib.sha256(buf.getvalue()).hexdigest()},
                    }
                ],
            },
        )
        monkeypatch.setattr(fx, "_download", lambda url, integrity: buf.getvalue())
        src = resolve_source("pip:demo", workdir=tmp_path)
        assert (src / "server.py").exists()

    def test_no_sdist_errors(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(fx, "_get_json", lambda url: {"urls": [{"packagetype": "bdist_wheel"}]})
        with pytest.raises(FetchError, match="sdist"):
            resolve_source("pip:demo", workdir=tmp_path)


class TestSafeExtract:
    def test_path_traversal_rejected(self, tmp_path: Path) -> None:
        # a tarball with a '../escape' member must not write outside dest
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            data = b"pwned"
            info = tarfile.TarInfo("../escape.txt")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        with pytest.raises(FetchError):
            fx._safe_extract_tar(buf.getvalue(), tmp_path)
        assert not (tmp_path.parent / "escape.txt").exists()

    def test_zip_path_traversal_rejected(self, tmp_path: Path) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as archive:
            archive.writestr("../sibling/escape.txt", "pwned")
        with pytest.raises(FetchError, match="unsafe path"):
            fx._safe_extract_zip(buf.getvalue(), tmp_path)

    def test_integrity_mismatch_rejected(self) -> None:
        with pytest.raises(FetchError, match="digest"):
            fx._verify_integrity(b"actual", _integrity(b"different"))

    def test_package_download_rejects_private_network_url(self) -> None:
        with pytest.raises(FetchError, match="non-public"):
            fx._download("https://127.0.0.1/archive.tgz", _integrity(b"unused"))

    def test_unpinned_github_ref_rejected(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(fx.shutil, "which", lambda _name: "git")
        with pytest.raises(FetchError, match="pinned"):
            fx._fetch_github("https://github.com/owner/repo.git", tmp_path)
