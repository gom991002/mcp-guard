"""OS isolation for a guarded local MCP server (separate track: "OS 격리", 2026-11-04).

The checks see a server's MCP traffic only; what its process does to files and
the network is outside them (Docs/Core_mds/architecture.md, out of scope for the
core). As a portfolio-scale answer the L2 wrapper can start the server inside
a Docker container instead of on the host:

* no network unless the manifest asks for it (``network: none`` by default);
* a read-only root file system, a private /tmp, every Linux capability
  dropped, no privilege gain, process, memory and CPU limits;
* only the folders the manifest lists are mounted, read-only unless marked
  ``rw``; the stage 1 checks still verify the host files that are mounted.

Manifest, per server::

    "sandbox": {"image": "node:22-slim@sha256:<digest>",
                "command": ["node", "/srv/server/index.js"],
                "mounts": [{"source": "C:/mcp/servers/files", "target": "/srv/server"},
                           {"source": "C:/work/shared", "target": "/work", "mode": "rw"}],
                "network": "none", "memory": "512m", "cpus": "1"}

This is a container, not a VM: it shares the host kernel, and Docker itself
must be trusted. It is not a hardened multi-tenant sandbox.
"""

from __future__ import annotations

import re
import shutil
from typing import Any

NETWORKS = ("none", "bridge")
_SIZE = re.compile(r"\d{1,6}[kmg]")
_CPUS = re.compile(r"\d{1,2}(\.\d{1,2})?")
_TARGET = re.compile(r"/[A-Za-z0-9._/-]*")


def validate(spec: Any) -> dict[str, Any]:
    """The sandbox block with defaults, or ValueError."""
    if not isinstance(spec, dict):
        raise ValueError("sandbox must be an object")
    image, command = spec.get("image"), spec.get("command")
    if not isinstance(image, str) or not image or image.startswith("-"):
        raise ValueError("sandbox needs an image")
    if not isinstance(command, list) or not command or not all(isinstance(c, str) and c for c in command):
        raise ValueError("sandbox needs a command list to run inside the container")
    network = spec.get("network", "none")
    if network not in NETWORKS:
        raise ValueError(f"sandbox network must be one of {', '.join(NETWORKS)}")
    memory, cpus = str(spec.get("memory", "512m")).lower(), str(spec.get("cpus", "1"))
    if not _SIZE.fullmatch(memory) or not _CPUS.fullmatch(cpus):
        raise ValueError("sandbox memory (e.g. 512m) or cpus (e.g. 1) is invalid")
    mounts = []
    for mount in spec.get("mounts", []):
        if not isinstance(mount, dict) or not isinstance(mount.get("source"), str) or not mount["source"]:
            raise ValueError("each sandbox mount needs a source folder")
        target, mode = mount.get("target"), mount.get("mode", "ro")
        if not isinstance(target, str) or not _TARGET.fullmatch(target) or ".." in target.split("/"):
            raise ValueError("each sandbox mount needs an absolute container target")
        if mode not in ("ro", "rw"):
            raise ValueError("sandbox mount mode must be ro or rw")
        if "," in mount["source"] or "," in target:
            raise ValueError("sandbox mount paths cannot contain commas")
        mounts.append({"source": mount["source"], "target": target, "mode": mode})
    return {"image": image, "command": list(command), "network": network, "memory": memory, "cpus": cpus,
            "mounts": mounts, "pinned": "@sha256:" in image}


def docker_command(spec: dict[str, Any], docker: str | None = None) -> list[str]:
    """The ``docker run`` line that starts the server with stdio attached and nothing else."""
    sandbox = validate(spec)
    argv = [docker or shutil.which("docker") or "docker", "run", "--rm", "-i",
            "--network", sandbox["network"], "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", "128", "--memory", sandbox["memory"], "--cpus", sandbox["cpus"],
            "--user", "65534:65534", "--env", "PYTHONDONTWRITEBYTECODE=1"]
    for mount in sandbox["mounts"]:
        option = f"type=bind,source={mount['source']},target={mount['target']}"
        argv += ["--mount", option + (",readonly" if mount["mode"] == "ro" else "")]
    return argv + [sandbox["image"], *sandbox["command"]]


def describe(spec: dict[str, Any]) -> dict[str, Any]:
    """What the audit record keeps about the isolation."""
    sandbox = validate(spec)
    return {"engine": "docker", "image": sandbox["image"], "image_pinned": sandbox["pinned"],
            "network": sandbox["network"], "mounts": [f"{m['target']}:{m['mode']}" for m in sandbox["mounts"]]}
