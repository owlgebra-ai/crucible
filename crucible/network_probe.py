"""Fixed, data-free destinations for the isolated egress-wall challenge.

The addresses are TEST-NET-3 documentation space.  A failed firewall may
complete a TCP handshake, but this probe never sends application bytes.
"""

from __future__ import annotations

from urllib.parse import urlsplit


CHALLENGE_ID = "egress_probe_v1"
PROBE_HOSTS = frozenset({"203.0.113.10", "203.0.113.11"})
PROBE_URLS = frozenset(f"https://{host}:443/fixture-check" for host in PROBE_HOSTS)


def probe_host(url: object) -> str | None:
    """Accept exactly one of two HTTPS URLs, with no DNS or user input in it."""
    if type(url) is not str or url not in PROBE_URLS:
        return None
    parsed = urlsplit(url)
    return parsed.hostname if parsed.hostname in PROBE_HOSTS else None
