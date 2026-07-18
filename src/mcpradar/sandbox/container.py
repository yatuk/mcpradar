"""Disposable container isolation for stdio MCP server scanning.

Scanning a stdio server means executing its code. For untrusted servers the
scan itself is an attack surface, so ``--sandbox`` wraps the launch command in
a disposable Docker/Podman container:

- egress locked (``--network none`` by default)
- ephemeral filesystem (``--rm`` + tmpfs, nothing survives the scan)
- no capabilities, no privilege escalation, bounded pids/memory/cpu
- optional source directory mounted read-only at ``/workspace``
- executable package caches isolated in an ephemeral ``/sandbox`` tmpfs

The MCP stdio session flows through the container runtime's ``-i`` stdin/stdout
pipe, so the scanner needs no protocol changes.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

# Commands whose interpreter decides the default image.
_PYTHON_LAUNCHERS = {"python", "python3", "uvx", "uv", "pip", "pipx"}
_NODE_LAUNCHERS = {"node", "npx", "npm", "yarn", "pnpm", "bun"}

DEFAULT_PYTHON_IMAGE = "python:3.12-slim"
DEFAULT_NODE_IMAGE = "node:22-slim"

# Launchers that download the package at startup and therefore cannot work
# with the default egress lock.
_NETWORK_DEPENDENT_LAUNCHERS = {"npx", "uvx", "pipx"}


class SandboxUnavailableError(RuntimeError):
    """No usable container runtime, or the command cannot be containerized."""


@dataclass
class ContainerPolicy:
    """Isolation parameters for a sandboxed stdio scan."""

    image: str | None = None  # auto-picked from the launcher when None
    network: str = "none"  # "none" (egress lock) or "bridge"
    memory: str = "512m"
    cpus: str = "1.0"
    pids_limit: int = 256
    mount_cwd: bool = False
    mount_path: Path | None = None
    user: str = "65532:65532"
    read_only: bool = True
    runtime: str | None = None  # "docker" | "podman"; auto-detected when None


def detect_runtime(check_daemon: bool = True) -> str | None:
    """Return the first usable container runtime, or None.

    Docker is preferred over Podman. With ``check_daemon`` the runtime must
    also respond to ``info`` (a Docker CLI without a running daemon is not
    usable).
    """
    for runtime in ("docker", "podman"):
        if shutil.which(runtime) is None:
            continue
        if not check_daemon:
            return runtime
        try:
            proc = subprocess.run(
                [runtime, "info"],
                capture_output=True,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0:
            return runtime
    return None


def pick_image(command: str) -> str:
    """Choose a base image from the command's launcher."""
    launcher = Path(shlex.split(command)[0]).name.lower()
    launcher = launcher.removesuffix(".exe")
    if launcher in _PYTHON_LAUNCHERS:
        return DEFAULT_PYTHON_IMAGE
    if launcher in _NODE_LAUNCHERS:
        return DEFAULT_NODE_IMAGE
    raise SandboxUnavailableError(
        f"Cannot auto-pick a container image for launcher '{launcher}'. "
        "Pass --sandbox-image explicitly."
    )


def network_warning(command: str, policy: ContainerPolicy) -> str | None:
    """Warn when the launch command needs network but egress is locked."""
    launcher = Path(shlex.split(command)[0]).name.lower().removesuffix(".exe")
    if policy.network == "none" and launcher in _NETWORK_DEPENDENT_LAUNCHERS:
        return (
            f"'{launcher}' downloads the server package at startup, but the sandbox "
            "egress lock (--sandbox-network none) blocks all network access. "
            "If the scan fails to connect, retry with --sandbox-network bridge."
        )
    return None


def resolve_image_digest(runtime: str, image: str) -> str:
    """Resolve a local image tag to an immutable repository digest."""
    if "@sha256:" in image:
        digest = image.rsplit("@sha256:", 1)[1]
        if len(digest) == 64 and all(char in "0123456789abcdefABCDEF" for char in digest):
            return image
        raise SandboxUnavailableError("Invalid sha256 image digest")
    try:
        result = subprocess.run(
            [runtime, "image", "inspect", "--format", "{{index .RepoDigests 0}}", image],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SandboxUnavailableError(f"Could not inspect sandbox image: {exc}") from None
    resolved = result.stdout.strip() if result.returncode == 0 else ""
    if "@sha256:" not in resolved:
        raise SandboxUnavailableError(
            f"Sandbox image '{image}' is not available with a repository digest. "
            f"Pull it explicitly with '{runtime} pull {image}', then retry."
        )
    return resolved


def wrap_stdio_command(command: str, policy: ContainerPolicy | None = None) -> str:
    """Wrap a stdio launch command in a disposable container invocation.

    Returns the ``docker run ...`` (or ``podman run ...``) command string that
    the stdio transport can launch in place of the original command.

    Raises:
        SandboxUnavailableError: no container runtime found, or no image
            could be determined for the command.
    """
    policy = policy or ContainerPolicy()

    runtime = policy.runtime or detect_runtime()
    if runtime is None:
        raise SandboxUnavailableError(
            "No usable container runtime found. --sandbox requires Docker or "
            "Podman with a running daemon. Install one, or drop --sandbox to "
            "run the server directly on the host (not recommended for "
            "untrusted servers)."
        )

    image = resolve_image_digest(runtime, policy.image or pick_image(command))

    args: list[str] = [
        runtime,
        "run",
        "--rm",  # ephemeral: container and its filesystem vanish after the scan
        "-i",  # MCP stdio session flows through stdin/stdout
        "--init",
        "--user",
        policy.user,
        "--network",
        policy.network,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        str(policy.pids_limit),
        "--memory",
        policy.memory,
        "--cpus",
        policy.cpus,
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=256m",
        "--tmpfs",
        "/sandbox:rw,exec,nosuid,nodev,size=384m,uid=65532,gid=65532,mode=0700",
        "-e",
        "HOME=/sandbox",
        "-e",
        "XDG_CACHE_HOME=/sandbox/.cache",
        "-e",
        "NPM_CONFIG_CACHE=/sandbox/.npm",
        "-e",
        "UV_CACHE_DIR=/sandbox/.cache/uv",
    ]

    if policy.read_only:
        args.append("--read-only")

    mount_path = policy.mount_path
    if mount_path is None and policy.mount_cwd:
        mount_path = Path.cwd()
    if mount_path is not None:
        resolved_mount = mount_path.resolve()
        args += ["-v", f"{resolved_mount.as_posix()}:/workspace:ro", "-w", "/workspace"]
    else:
        args += ["-w", "/sandbox"]

    args.append(image)
    args += shlex.split(command)

    return shlex.join(args)
