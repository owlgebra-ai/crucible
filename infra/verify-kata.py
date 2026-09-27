#!/usr/bin/env python3
"""Attest the pinned Kata QEMU runtime and each CRUCIBLE task microVM.

The daemon configuration is checked as well as Docker's effective runtime.
For a running task, the guest kernel, guest seccomp state, and its particular
QEMU process's KVM file descriptor are checked before any scenario is staged.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

try:
    import tomllib
except ImportError:  # Local tests may run on Python 3.10.
    import tomli as tomllib


VERSION = "4.2.0"
RUNTIME = "kata-qemu"
SHIM = Path("/opt/kata/runtime-rs/bin/containerd-shim-kata-v2")
CONFIG = Path("/etc/crucible/kata-qemu.toml")
MANIFEST = Path("/etc/crucible/kata-install.json")
DAEMON = Path("/etc/docker/daemon.json")
PINNED_ARCHIVES = {
    "amd64": "b828904fa3f1e49ddd7dc799c72cb1503cd1e772d354c3987c8d4189b2a623a8",
    "arm64": "5dd4e9f2d5ea9e6bdfa2f476b3315335b58252366fcda2775a3094fc8fec376b",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_root_owned(path: Path, *, executable: bool = False) -> None:
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            raise ValueError(f"symlink is not an attested runtime path: {candidate}")
        details = candidate.stat()
        if details.st_uid != 0 or details.st_mode & 0o022:
            raise ValueError(f"runtime path is not root-owned and protected: {candidate}")
    details = path.stat()
    if not stat.S_ISREG(details.st_mode):
        raise ValueError(f"runtime path is not a regular file: {path}")
    if executable and not details.st_mode & stat.S_IXUSR:
        raise ValueError(f"runtime path is not executable: {path}")


def validate_docker_config(data: object) -> None:
    if not isinstance(data, dict):
        raise ValueError("Docker daemon configuration is not an object")
    runtime = data.get("runtimes", {}).get(RUNTIME)
    if runtime != {
        "runtimeType": str(SHIM),
        "options": {"ConfigPath": str(CONFIG)},
    }:
        raise ValueError("kata-qemu Docker alias does not select the pinned shim and config")
    if data.get("default-runtime") == RUNTIME:
        raise ValueError("Kata must not become Docker's global default runtime")


def validate_live_runtime(runtimes: object) -> None:
    """Check the daemon's loaded alias, not only its on-disk configuration."""
    if not isinstance(runtimes, dict):
        raise ValueError("Docker did not report runtime configuration")
    entry = runtimes.get(RUNTIME)
    if not isinstance(entry, dict):
        raise ValueError("Docker has not loaded the kata-qemu runtime alias")
    if (entry.get("runtimeType") != str(SHIM) or
            entry.get("options") != {"ConfigPath": str(CONFIG)} or
            entry.get("path") or entry.get("runtimeArgs")):
        raise ValueError("Docker's effective kata-qemu alias differs from the pinned shim and config")


def validate_kata_config(data: object) -> dict[str, Path]:
    if not isinstance(data, dict):
        raise ValueError("Kata configuration is not an object")
    runtime = data.get("runtime", {})
    hypervisor = data.get("hypervisor", {}).get("qemu", {})
    if runtime.get("hypervisor_name") != "qemu":
        raise ValueError("Kata config must select QEMU")
    if runtime.get("disable_guest_seccomp") is not False:
        raise ValueError("Kata guest seccomp must be enabled")
    # Kata normally appends accel=kvm itself; machine_accelerators is for
    # optional machine features (and is empty in upstream's QEMU default).
    # Actual KVM use is attested against the task QEMU process below.
    seccomp_sandbox = hypervisor.get("seccomp_sandbox", "")
    if not isinstance(seccomp_sandbox, str) or seccomp_sandbox.split(",")[0] != "on":
        raise ValueError("QEMU's host-side seccomp sandbox must be on")
    paths = {
        "qemu_sha256": Path(hypervisor.get("path", "")),
        "virtiofsd_sha256": Path(hypervisor.get("virtio_fs_daemon", "")),
        "guest_kernel_sha256": Path(hypervisor.get("kernel", "")),
        "guest_image_sha256": Path(hypervisor.get("image", "")),
    }
    if any(not path.is_absolute() or not str(path).startswith("/opt/kata/") for path in paths.values()):
        raise ValueError("QEMU, virtiofsd, and guest assets must come from the pinned Kata release")
    return paths


def validate_container(
    info: object,
    expected_network: str | None = None,
    expected_seccomp: object | None = None,
) -> None:
    if not isinstance(info, dict) or not re.fullmatch(r"[a-f0-9]{64}", str(info.get("Id", ""))):
        raise ValueError("Docker did not report a full container ID")
    host = info.get("HostConfig", {})
    config = info.get("Config", {})
    if host.get("Runtime") != RUNTIME:
        raise ValueError("task did not use the kata-qemu runtime")
    if config.get("Labels", {}).get("crucible.managed") != "true":
        raise ValueError("task is not CRUCIBLE-managed")
    if info.get("State", {}).get("Running") is not True:
        raise ValueError("task VM is not running")
    if host.get("ReadonlyRootfs") is not True or host.get("Binds"):
        raise ValueError("task must have a read-only root and no host binds")
    if (host.get("Memory") != 512 * 1024 * 1024 or
            host.get("MemorySwap") != 512 * 1024 * 1024 or
            host.get("NanoCpus") != 1_000_000_000 or
            host.get("PidsLimit") != 64):
        raise ValueError("task Docker resource limits differ from the required profile")
    if config.get("User") != "10001:10001":
        raise ValueError("task must run as the unprivileged worker user")
    if expected_network is not None:
        networks = info.get("NetworkSettings", {}).get("Networks", {})
        if list(networks) != [expected_network]:
            raise ValueError("task is not attached only to its policy network")
    security = host.get("SecurityOpt") or []
    profiles = [item.partition("=")[2] for item in security if item.startswith("seccomp=")]
    if len(profiles) != 1:
        raise ValueError("Docker did not send an OCI seccomp profile")
    if expected_seccomp is not None:
        try:
            applied_seccomp = json.loads(profiles[0])
        except ValueError as exc:
            raise ValueError("Docker reported an invalid OCI seccomp profile") from exc
        if applied_seccomp != expected_seccomp:
            raise ValueError("Docker's effective OCI seccomp profile changed")
    if not any(item.startswith("no-new-privileges") for item in security):
        raise ValueError("task lacks no-new-privileges")


def qemu_processes(cid: str, qemu_binary: Path, proc_root: Path = Path("/proc")) -> list[tuple[int, list[str]]]:
    """Return this container's QEMU processes by their Kata sandbox name."""
    matches: list[tuple[int, list[str]]] = []
    for directory in proc_root.iterdir():
        if not directory.name.isdigit():
            continue
        try:
            argv = (directory / "cmdline").read_bytes().rstrip(b"\0").split(b"\0")
            args = [arg.decode("utf-8", "replace") for arg in argv]
            if not args or Path(args[0]) != qemu_binary:
                continue
            if "-name" not in args:
                continue
            name = args[args.index("-name") + 1]
            if not name.startswith("sandbox-"):
                continue
            suffix = name.removeprefix("sandbox-").split(",", 1)[0]
            if len(suffix) < 12 or not cid.startswith(suffix):
                continue
            matches.append((int(directory.name), args))
        except (OSError, IndexError, ValueError):
            continue
    return matches


def qemu_kvm_pid(cid: str, qemu_binary: Path, proc_root: Path = Path("/proc")) -> int:
    """Require this task's QEMU to have KVM and QEMU seccomp enabled."""
    matches = []
    for pid, args in qemu_processes(cid, qemu_binary, proc_root):
        try:
            if "-machine" not in args or "accel=kvm" not in args[args.index("-machine") + 1].split(","):
                continue
            if "-sandbox" not in args or args[args.index("-sandbox") + 1].split(",")[0] != "on":
                continue
            fds = (proc_root / str(pid) / "fd").iterdir()
            if any(os.readlink(fd) == "/dev/kvm" for fd in fds):
                matches.append(pid)
        except (OSError, IndexError):
            continue
    if len(matches) != 1:
        raise ValueError(f"expected exactly one task QEMU process using KVM; found {len(matches)}")
    return matches[0]


def verify_install() -> tuple[Path, str]:
    if os.environ.get("DOCKER_HOST") not in (None, "", "unix:///var/run/docker.sock"):
        raise ValueError("Docker must use the local rootful socket")
    contexts = json.loads(subprocess.check_output(["docker", "context", "inspect"], text=True))
    if contexts[0]["Endpoints"]["docker"]["Host"] != "unix:///var/run/docker.sock":
        raise ValueError("Docker context must use the local rootful socket")
    with open("/dev/kvm", "rb+"):
        pass
    cpu = Path("/proc/cpuinfo").read_text()
    if not re.search(r"\b(vmx|svm)\b", cpu):
        raise ValueError("hardware virtualization flag is absent")
    for path in (SHIM, CONFIG, MANIFEST, DAEMON):
        require_root_owned(path, executable=path == SHIM)
    manifest = json.loads(MANIFEST.read_text())
    if manifest.get("version") != VERSION:
        raise ValueError("Kata install manifest version is not pinned")
    arch = manifest.get("arch")
    if manifest.get("archive_sha256") != PINNED_ARCHIVES.get(arch):
        raise ValueError("Kata archive digest differs from the pinned release")
    if sha256(SHIM) != manifest.get("shim_sha256"):
        raise ValueError("Kata shim differs from the verified release")
    if sha256(CONFIG) != manifest.get("config_sha256"):
        raise ValueError("Kata config changed after installation")
    config_data = tomllib.loads(CONFIG.read_text())
    assets = validate_kata_config(config_data)
    for name, path in assets.items():
        require_root_owned(path, executable=name in ("qemu_sha256", "virtiofsd_sha256"))
        if sha256(path) != manifest.get(name):
            raise ValueError(f"Kata {name} differs from the verified release")
    validate_docker_config(json.loads(DAEMON.read_text()))
    runtimes = json.loads(subprocess.check_output(
        ["docker", "info", "--format", "{{json .Runtimes}}"], text=True
    ))
    validate_live_runtime(runtimes)
    default = subprocess.check_output(
        ["docker", "info", "--format", "{{.DefaultRuntime}}"], text=True
    ).strip()
    if default == RUNTIME:
        raise ValueError("Kata unexpectedly became Docker's default runtime")
    return assets["qemu_sha256"], manifest["archive_sha256"]


def verify_session(cid: str, network: str | None = None) -> dict:
    if not re.fullmatch(r"[a-f0-9]{64}", cid):
        raise ValueError("invalid full container ID")
    qemu, archive_digest = verify_install()
    info = json.loads(subprocess.check_output(["docker", "inspect", cid], text=True))[0]
    seccomp_path = Path(__file__).with_name("crucible-seccomp.json")
    validate_container(
        info, expected_network=network,
        expected_seccomp=json.loads(seccomp_path.read_text()),
    )
    probe = subprocess.check_output([
        "docker", "exec", cid, "python", "-c",
        "import json,os,pathlib,re; "
        "r=lambda p: pathlib.Path(p).read_text().strip(); "
        "s=r('/proc/self/status'); p=r('/proc/1/status'); "
        "get=lambda t: int(re.search(r'^Seccomp:\\s*(\\d+)$', t, re.M).group(1)); "
        "print(json.dumps({'kernel':os.uname().release,'self_seccomp':get(s),"
        "'pid1_seccomp':get(p),'cpu_max':r('/sys/fs/cgroup/cpu.max'),"
        "'memory_max':r('/sys/fs/cgroup/memory.max')}))",
    ], text=True, timeout=30)
    guest = json.loads(probe)
    host_kernel = os.uname().release
    if not guest.get("kernel") or guest["kernel"] == host_kernel:
        raise ValueError("task does not have a separate guest kernel")
    # The Kata guest agent may be PID 1. The workload process launched through
    # the exec seam is the subject of the OCI profile, so attest that process.
    if guest.get("self_seccomp") != 2:
        raise ValueError("task workload must have guest seccomp-filter mode")
    cpu_max = str(guest.get("cpu_max", "")).split()
    if len(cpu_max) != 2 or not all(item.isdecimal() for item in cpu_max):
        raise ValueError("task guest has no numeric CPU cgroup quota")
    if int(cpu_max[1]) <= 0 or int(cpu_max[0]) > int(cpu_max[1]):
        raise ValueError("task guest CPU quota exceeds one CPU")
    memory_max = str(guest.get("memory_max", ""))
    if not memory_max.isdecimal() or int(memory_max) > 512 * 1024 * 1024:
        raise ValueError("task guest memory cgroup exceeds 512 MiB")
    pid = qemu_kvm_pid(cid, qemu)
    return {
        "runtime": RUNTIME,
        "guest_kernel": guest["kernel"],
        "host_kernel": host_kernel,
        "guest_seccomp": True,
        "guest_cpu_max": guest["cpu_max"],
        "guest_memory_max": int(memory_max),
        "qemu_kvm_pid": pid,
        "release": VERSION,
        "archive_sha256": archive_digest,
    }


def main() -> int:
    if sys.argv[1:] in ([], ["--quiet"]):
        session = None
        destroyed = None
    elif len(sys.argv) == 3 and sys.argv[1] == "--destroyed" and re.fullmatch(r"[a-f0-9]{64}", sys.argv[2]):
        session = None
        destroyed = sys.argv[2]
    elif len(sys.argv) in (2, 3) and re.fullmatch(r"[a-f0-9]{64}", sys.argv[1]):
        session = sys.argv[1:]
        destroyed = None
    else:
        print("usage: verify-kata.py [--quiet | <full-container-id> [network] | --destroyed <full-container-id>]", file=sys.stderr)
        return 2
    try:
        if destroyed is not None:
            qemu, _ = verify_install()
            if qemu_processes(destroyed, qemu):
                raise ValueError("task QEMU remains after container teardown")
            print("kata-qemu microVM teardown: OK")
        elif session is None:
            qemu, _ = verify_install()
            if sys.argv[1:] != ["--quiet"]:
                print(f"kata-qemu install: verified ({VERSION}; {qemu})")
        else:
            print(json.dumps(verify_session(session[0], session[1] if len(session) > 1 else None), sort_keys=True))
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, IndexError, TypeError) as exc:
        print(f"UNVERIFIED: kata-qemu: {exc}", file=sys.stderr)
        return 77
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
