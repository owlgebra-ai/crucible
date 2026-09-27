#!/usr/bin/env python3
"""Build a deployment archive from committed, explicitly allowed application files.

The working tree is never read. In particular, local credentials and generated
episode data cannot enter the archive even if someone accidentally tracks them.
"""

from __future__ import annotations

import argparse
import io
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile


REQUIRED = {
    "crucible/__init__.py",
    "crucible/dashboard.py",
    "crucible/worker.py",
    "infra/Dockerfile",
    "infra/build-worker.sh",
    "infra/prove-wall.sh",
    "infra/run-worker.sh",
    "infra/setup-net.sh",
    "deploy/bootstrap-vm.sh",
    "deploy/check-sandbox-idle.py",
}
INFRA_NAMES = {
    "Dockerfile",
    "Dockerfile.dockerignore",
    "build-worker.sh",
    "create-worker.sh",
    "crucible-seccomp.json",
    "destroy-worker.sh",
    "exec-worker.sh",
    "extract-scenario.py",
    "install-gvisor.sh",
    "install-kata.sh",
    "prove-wall.sh",
    "run-worker.sh",
    "setup-net.sh",
    "stage-scenario.py",
    "wall-probe.py",
    "verify-runtime.py",
    "verify-kata.py",
}


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.PIPE)


def allowed(name: str) -> bool:
    if not re.fullmatch(r"[A-Za-z0-9_./-]+", name):
        return False
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or len(path.parts) < 2:
        return False
    if any(part.startswith(".") or part == "__pycache__" for part in path.parts):
        return False
    if path.parts[0] == "crucible":
        return path.suffix == ".py" or name == "crucible/registry.json"
    if path.parts[0] == "infra":
        return len(path.parts) == 2 and path.name in INFRA_NAMES
    if path.parts[0] == "dsh":
        return len(path.parts) == 2 and path.name in {
            "policy_plugin.mjs", "smoke.patch.yml", "worker.patch.yml"
        }
    return name in {"deploy/bootstrap-vm.sh", "deploy/bootstrap-control-vm.sh",
                    "deploy/bootstrap-sandbox-vm.sh", "deploy/activate-worker-runtime.sh",
                    "deploy/check-sandbox-idle.py",
                    "deploy/remote-worker-gateway.py", "deploy/authorize-control-key.sh"}


def package(root: Path, output: Path) -> str:
    toplevel = Path(git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    if root.resolve() != toplevel:
        raise ValueError(f"run from repository root: {toplevel}")
    revision = git(root, "rev-parse", "HEAD").decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", revision):
        raise ValueError("HEAD is not a committed Git revision")
    records = git(root, "ls-tree", "--full-tree", "-r", "-z", "HEAD").split(b"\0")
    selected: list[tuple[str, str, str]] = []
    for record in records:
        if not record:
            continue
        metadata, raw_name = record.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split(" ")
        name = raw_name.decode("utf-8", "strict")
        if not allowed(name):
            continue
        if kind != "blob" or mode not in {"100644", "100755"}:
            raise ValueError(f"unsupported Git entry in deployment: {name}")
        selected.append((name, mode, oid))
    missing = REQUIRED - {name for name, _, _ in selected}
    if missing:
        raise ValueError(f"required committed files missing: {', '.join(sorted(missing))}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        for name, mode, oid in sorted(selected):
            payload = git(root, "cat-file", "blob", oid)
            info = tarfile.TarInfo(name)
            info.mode = 0o755 if mode == "100755" else 0o644
            info.size = len(payload)
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(payload))
    return revision


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    try:
        revision = package(root, args.output)
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        parser.exit(2, f"deployment packaging failed: {exc}\n")
    print(revision)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
