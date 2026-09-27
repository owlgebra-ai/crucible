#!/usr/bin/env python3
"""Fail closed before changing a sandbox host that still owns task guests."""

from __future__ import annotations

import re
import subprocess


_CID = re.compile(r"[a-f0-9]{64}\Z")


def main() -> int:
    try:
        result = subprocess.run(
            ["docker", "ps", "-aq", "--no-trunc", "--filter", "label=crucible.managed=true"],
            capture_output=True, text=True, timeout=20, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        print("cannot inspect managed sandbox containers", flush=True)
        return 77
    ids = result.stdout.splitlines()
    if result.returncode != 0 or any(not _CID.fullmatch(cid) for cid in ids):
        print("cannot verify managed sandbox container state", flush=True)
        return 77
    if ids:
        print("sandbox deployment refused while a managed container exists", flush=True)
        return 75
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
