#!/usr/bin/env python3
"""Remove temporary firewall-gap challenge rules and the keyless sink.

The gateway calls this in `finally`; an independent systemd timer calls it
again after a short lease, so a killed gateway cannot strand an ACCEPT rule.
"""

from __future__ import annotations

import argparse
import re
import shlex
import subprocess


EPISODE = re.compile(r"ep_[a-f0-9]{12}\Z")
CHAIN = "CRUCIBLE_EGRESS"


def cleanup(episode_id: str) -> bool:
    if not EPISODE.fullmatch(episode_id):
        return False
    marker = f"crucible-gap-{episode_id}-"
    listing = subprocess.run(["iptables", "-w", "-S", CHAIN], text=True,
                             capture_output=True, timeout=15, check=False)
    if listing.returncode != 0:
        return False
    matches = []
    for row in listing.stdout.splitlines():
        if not row.startswith(f"-A {CHAIN} "):
            continue
        tokens = shlex.split(row)
        if "--comment" not in tokens:
            continue
        comment = tokens[tokens.index("--comment") + 1]
        if not comment.startswith(marker):
            continue
        matches.append(tokens)
    # Delete the permissive rule first. Removing Blue's DROP first would
    # briefly reopen the route while the ACCEPT remained installed.
    matches.sort(key=lambda tokens: 0 if tokens[-2:] == ["-j", "ACCEPT"] else 1)
    for tokens in matches:
        # The marker is generated from a validated episode ID. Reusing the
        # exact active rule specification removes only this challenge rule.
        subprocess.run(["iptables", "-w", "-D", CHAIN, *tokens[2:]],
                       text=True, capture_output=True, timeout=15,
                       check=False)
    sink = f"crucible-gap-sink-{episode_id}"
    subprocess.run(["docker", "rm", "-f", sink], text=True,
                   capture_output=True, timeout=30, check=False)
    containers = subprocess.run(["docker", "ps", "-aq", "--no-trunc", "--filter",
                                 f"name=^{sink}$"], text=True, capture_output=True,
                                timeout=15, check=False)
    verify = subprocess.run(["iptables", "-w", "-S", CHAIN], text=True,
                            capture_output=True, timeout=15, check=False)
    # Two callers can race on the same rule/container. Their individual
    # delete exit codes are not proof; the final absence of both is.
    return (containers.returncode == 0 and not containers.stdout.strip()
            and verify.returncode == 0
            and not any(marker in row for row in verify.stdout.splitlines()))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--episode", required=True)
    args = parser.parse_args()
    return 0 if cleanup(args.episode) else 1


if __name__ == "__main__":
    raise SystemExit(main())
