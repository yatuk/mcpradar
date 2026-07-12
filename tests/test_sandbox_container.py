"""Tests for the disposable container sandbox (mcpradar.sandbox.container)."""

from __future__ import annotations

import shlex

import pytest

from mcpradar.sandbox import container
from mcpradar.sandbox.container import (
    ContainerPolicy,
    SandboxUnavailableError,
    detect_runtime,
    network_warning,
    pick_image,
    wrap_stdio_command,
)

# ---------------------------------------------------------------------------
# pick_image
# ---------------------------------------------------------------------------


class TestPickImage:
    @pytest.mark.parametrize(
        "command,expected",
        [
            ("python demo/malicious_server.py", container.DEFAULT_PYTHON_IMAGE),
            ("python3 server.py --port 0", container.DEFAULT_PYTHON_IMAGE),
            ("uvx some-mcp-server", container.DEFAULT_PYTHON_IMAGE),
            ("node index.js", container.DEFAULT_NODE_IMAGE),
            ("npx -y @modelcontextprotocol/server-memory", container.DEFAULT_NODE_IMAGE),
            ("/usr/bin/python3 server.py", container.DEFAULT_PYTHON_IMAGE),
        ],
    )
    def test_auto_pick(self, command: str, expected: str) -> None:
        assert pick_image(command) == expected

    def test_windows_exe_suffix(self) -> None:
        assert pick_image("python.exe server.py") == container.DEFAULT_PYTHON_IMAGE

    def test_unknown_launcher_raises(self) -> None:
        with pytest.raises(SandboxUnavailableError, match="sandbox-image"):
            pick_image("./custom-binary --stdio")


# ---------------------------------------------------------------------------
# detect_runtime
# ---------------------------------------------------------------------------


class TestDetectRuntime:
    def test_no_runtime_installed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(container.shutil, "which", lambda _: None)
        assert detect_runtime() is None

    def test_prefers_docker(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(container.shutil, "which", lambda name: f"/bin/{name}")
        assert detect_runtime(check_daemon=False) == "docker"

    def test_daemon_down_falls_through(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            container.shutil,
            "which",
            lambda name: "/bin/docker" if name == "docker" else None,
        )

        class FakeProc:
            returncode = 1

        monkeypatch.setattr(container.subprocess, "run", lambda *a, **k: FakeProc())
        assert detect_runtime() is None


# ---------------------------------------------------------------------------
# wrap_stdio_command
# ---------------------------------------------------------------------------


class TestWrapStdioCommand:
    @pytest.fixture()
    def docker_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(container, "detect_runtime", lambda check_daemon=True: "docker")

    def test_isolation_flags_present(self, docker_available: None) -> None:
        wrapped = shlex.split(wrap_stdio_command("python server.py"))
        assert wrapped[:3] == ["docker", "run", "--rm"]
        assert "-i" in wrapped
        for flag, value in [
            ("--network", "none"),
            ("--cap-drop", "ALL"),
            ("--security-opt", "no-new-privileges"),
            ("--pids-limit", "256"),
            ("--memory", "512m"),
            ("--cpus", "1.0"),
        ]:
            assert value == wrapped[wrapped.index(flag) + 1], flag

    def test_original_command_preserved_after_image(self, docker_available: None) -> None:
        wrapped = shlex.split(wrap_stdio_command("python server.py --port 0"))
        image_idx = wrapped.index(container.DEFAULT_PYTHON_IMAGE)
        assert wrapped[image_idx + 1 :] == ["python", "server.py", "--port", "0"]

    def test_cwd_mounted_read_only(self, docker_available: None) -> None:
        wrapped = shlex.split(wrap_stdio_command("python server.py"))
        mount = wrapped[wrapped.index("-v") + 1]
        assert mount.endswith(":/workspace:ro")
        assert wrapped[wrapped.index("-w") + 1] == "/workspace"

    def test_mount_can_be_disabled(self, docker_available: None) -> None:
        policy = ContainerPolicy(mount_cwd=False)
        wrapped = shlex.split(wrap_stdio_command("npx -y foo", policy))
        assert "-v" not in wrapped

    def test_policy_overrides(self, docker_available: None) -> None:
        policy = ContainerPolicy(image="custom:latest", network="bridge", memory="1g")
        wrapped = shlex.split(wrap_stdio_command("./custom-binary", policy))
        assert "custom:latest" in wrapped
        assert wrapped[wrapped.index("--network") + 1] == "bridge"
        assert wrapped[wrapped.index("--memory") + 1] == "1g"

    def test_no_runtime_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(container, "detect_runtime", lambda check_daemon=True: None)
        with pytest.raises(SandboxUnavailableError, match="Docker or\nPodman|Docker or Podman"):
            wrap_stdio_command("python server.py")

    def test_explicit_runtime_skips_detection(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def boom(check_daemon: bool = True) -> str | None:
            raise AssertionError("detect_runtime should not be called")

        monkeypatch.setattr(container, "detect_runtime", boom)
        wrapped = shlex.split(wrap_stdio_command("node x.js", ContainerPolicy(runtime="podman")))
        assert wrapped[0] == "podman"


# ---------------------------------------------------------------------------
# network_warning
# ---------------------------------------------------------------------------


class TestNetworkWarning:
    def test_npx_with_egress_lock_warns(self) -> None:
        warning = network_warning("npx -y @scope/server", ContainerPolicy())
        assert warning is not None
        assert "bridge" in warning

    def test_npx_with_bridge_no_warning(self) -> None:
        assert network_warning("npx -y @scope/server", ContainerPolicy(network="bridge")) is None

    def test_local_script_no_warning(self) -> None:
        assert network_warning("python server.py", ContainerPolicy()) is None
