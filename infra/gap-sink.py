#!/usr/bin/env python3
"""Keyless TCP receipt sink for the isolated firewall-gap challenge.

The listener never reads or writes application bytes.  Its only output is a
bounded in-container receipt log of peer IPv4 and local port.  It has no host
mount, no inference key, and no application credentials.
"""

from __future__ import annotations

import json
from pathlib import Path
import selectors
import socket
import sys
import time


PORTS = (18443, 18444)
STATE = Path("/run/crucible-sink")
RECEIPTS = STATE / "receipts.jsonl"
READY = STATE / "ready"
MAX_RECEIPTS = 1024
MAX_LIFETIME_SECONDS = 300


def count(peer: str, port: int) -> int:
    if port not in PORTS or not RECEIPTS.is_file():
        return 0
    seen = 0
    for line in RECEIPTS.read_text().splitlines()[:MAX_RECEIPTS]:
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if (peer == "*" or item.get("peer") == peer) and item.get("port") == port:
            seen += 1
    return seen


def serve() -> None:
    STATE.mkdir(parents=True, exist_ok=True)
    # If the gateway dies before it arms the firewall watchdog, no ACCEPT
    # exists. The keyless sink still removes itself after a bounded lifetime.
    deadline = time.monotonic() + MAX_LIFETIME_SECONDS
    selector = selectors.DefaultSelector()
    listeners = []
    for port in PORTS:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", port))
        server.listen(16)
        server.setblocking(False)
        selector.register(server, selectors.EVENT_READ, port)
        listeners.append(server)
    READY.write_text("ready\n")
    receipts = 0
    try:
        while time.monotonic() < deadline:
            for key, _ in selector.select(timeout=max(0, min(1, deadline - time.monotonic()))):
                connection, address = key.fileobj.accept()
                with connection:
                    # Never read or send data. A completed TCP handshake is
                    # sufficient to prove this controlled sink was reached.
                    if receipts < MAX_RECEIPTS:
                        with RECEIPTS.open("a") as output:
                            output.write(json.dumps({"peer": address[0],
                                                     "port": key.data}) + "\n")
                        receipts += 1
    finally:
        for listener in listeners:
            listener.close()


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--ready":
        print("ready" if READY.is_file() else "pending")
        return 0 if READY.is_file() else 1
    if len(sys.argv) == 4 and sys.argv[1] == "--count":
        try:
            port = int(sys.argv[3])
            if sys.argv[2] != "*":
                socket.inet_aton(sys.argv[2])
        except (ValueError, OSError):
            return 2
        print(count(sys.argv[2], port))
        return 0
    if len(sys.argv) != 1:
        return 2
    serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
