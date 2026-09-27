"""Authenticated, bounded SSH transport to a separate sandbox host.

The control plane owns model credentials and policy state.  The sandbox host
accepts only a forced SSH command and returns scanned worker results.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any


_CID = re.compile(r"[a-f0-9]{64}\Z")
_EPISODE = re.compile(r"ep_[a-f0-9]{12}\Z")
_SCENARIO_FILES = {"scenario.json", "README.md", "reference.txt", "service.env"}
_RUNTIMES = {"runc", "runsc-oci", "kata-qemu"}


class RemoteError(RuntimeError):
    """A credential-free transport or gateway failure."""


@dataclass(frozen=True)
class RemoteConfig:
    target: str
    identity: Path
    known_hosts: Path

    @classmethod
    def from_env(cls) -> "RemoteConfig":
        target = os.getenv("CRUCIBLE_REMOTE_TARGET", "")
        identity = Path(os.getenv("CRUCIBLE_REMOTE_IDENTITY", ""))
        known_hosts = Path(os.getenv("CRUCIBLE_REMOTE_KNOWN_HOSTS", ""))
        match = re.fullmatch(r"root@([0-9.]+)", target)
        if not match:
            raise RemoteError("remote target must be root@<private IPv4 address>")
        try:
            address = ipaddress.IPv4Address(match.group(1))
        except ipaddress.AddressValueError:
            raise RemoteError("remote target must be a private IPv4 address") from None
        private_ranges = tuple(ipaddress.IPv4Network(value) for value in
                               ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
        if not any(address in network for network in private_ranges):
            raise RemoteError("remote target must be in an RFC 1918 network")
        for path, label in ((identity, "identity"), (known_hosts, "known-hosts")):
            if not path.is_absolute() or path.is_symlink() or not path.is_file():
                raise RemoteError(f"remote {label} must be an existing regular absolute path")
            if path.stat().st_uid != os.geteuid():
                raise RemoteError(f"remote {label} must be owned by the current user")
        if identity.stat().st_mode & 0o077:
            raise RemoteError("remote identity must be owner-only (chmod 600)")
        if known_hosts.stat().st_mode & 0o022:
            raise RemoteError("remote known-hosts must not be group or world writable")
        if known_hosts.stat().st_size == 0:
            raise RemoteError("remote known-hosts file is empty")
        return cls(target, identity, known_hosts)


class RemoteWorkerClient:
    def __init__(self, config: RemoteConfig):
        self.config = config
        self._runtime_by_cid: dict[str, str] = {}

    def _call(self, request: dict[str, Any], *, timeout: int) -> dict[str, Any]:
        payload = json.dumps(request, ensure_ascii=True, separators=(",", ":"))
        if len(payload) > 256 * 1024:
            raise RemoteError("remote request exceeds size limit")
        command = ["ssh", "-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                   "-o", "StrictHostKeyChecking=yes", "-o", "ClearAllForwardings=yes",
                   "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ProxyCommand=none",
                   "-o", "UpdateHostKeys=no", "-o", "ForwardAgent=no", "-o", "ConnectionAttempts=1",
                   "-o", "ConnectTimeout=8", "-o", f"UserKnownHostsFile={self.config.known_hosts}",
                   "-i", str(self.config.identity), self.config.target, "crucible-remote-v1"]
        env = {"PATH": os.getenv("PATH", "/usr/bin:/bin"), "HOME": os.getenv("HOME", "/")}
        try:
            process = subprocess.run(command, input=payload, text=True, errors="replace",
                                     capture_output=True, check=False, timeout=timeout, env=env)
        except (OSError, subprocess.TimeoutExpired):
            raise RemoteError("remote gateway unavailable or timed out") from None
        if process.returncode != 0 or len(process.stdout) > 256 * 1024:
            raise RemoteError("remote gateway failed or returned oversized output")
        try:
            response = json.loads(process.stdout)
        except ValueError:
            raise RemoteError("remote gateway returned invalid JSON") from None
        if not isinstance(response, dict) or response.get("ok") is not True:
            raise RemoteError("remote gateway rejected the request")
        return response

    def create(self, scenario_dir: Path, episode_id: str) -> str:
        if not _EPISODE.fullmatch(episode_id):
            raise ValueError("invalid episode ID")
        files: dict[str, str] = {}
        for child in scenario_dir.iterdir():
            if child.name not in _SCENARIO_FILES or child.is_symlink() or not child.is_file():
                raise RemoteError("scenario contains an unsupported entry")
            if child.stat().st_size > 32 * 1024:
                raise RemoteError("scenario file exceeds remote size limit")
            files[child.name] = base64.b64encode(child.read_bytes()).decode("ascii")
        if not {"scenario.json", "README.md", "reference.txt"}.issubset(files):
            raise RemoteError("scenario is missing a required file")
        try:
            response = self._call({"op": "create", "episode_id": episode_id, "files": files}, timeout=155)
            cid = response.get("container_id")
            if not isinstance(cid, str) or not _CID.fullmatch(cid):
                raise RemoteError("remote gateway returned an invalid container ID")
            runtime = response.get("runtime")
            if not isinstance(runtime, str) or runtime not in _RUNTIMES:
                raise RemoteError("remote gateway did not attest a known worker runtime")
        except RemoteError:
            # The gateway may have created a worker before its response was lost
            # or malformed. Remove all containers bearing this episode label.
            self.cleanup(episode_id)
            raise
        self._runtime_by_cid[cid] = runtime
        return cid

    def runtime_for(self, cid: str) -> str | None:
        """Return the gateway-attested runtime for a created session."""
        return self._runtime_by_cid.get(cid)

    def execute(self, cid: str, episode_id: str, action: dict[str, Any]) -> dict[str, Any]:
        if not _CID.fullmatch(cid) or not _EPISODE.fullmatch(episode_id):
            raise ValueError("invalid remote session ID")
        response = self._call({"op": "exec", "container_id": cid,
                               "episode_id": episode_id, "action": action}, timeout=95)
        result = response.get("result")
        if not isinstance(result, dict):
            raise RemoteError("remote gateway returned an invalid worker result")
        return result

    def destroy(self, cid: str, episode_id: str) -> bool:
        if not _CID.fullmatch(cid) or not _EPISODE.fullmatch(episode_id):
            return False
        try:
            return self._call({"op": "destroy", "container_id": cid,
                               "episode_id": episode_id}, timeout=75).get("destroyed") is True
        except RemoteError:
            return False

    def cleanup(self, episode_id: str) -> bool:
        if not _EPISODE.fullmatch(episode_id):
            return False
        try:
            return self._call({"op": "cleanup", "episode_id": episode_id}, timeout=45).get("destroyed") is True
        except RemoteError:
            return False
