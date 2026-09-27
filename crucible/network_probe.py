"""Fixed, data-free destinations for the isolated egress-wall challenge.

The addresses are TEST-NET-3 documentation space.  A failed firewall may
complete a TCP handshake, but this probe never sends application bytes.
"""

from __future__ import annotations

from urllib.parse import urlsplit


CHALLENGE_ID = "egress_probe_v1"
PROBE_HOSTS = frozenset({"203.0.113.10", "203.0.113.11"})
PROBE_URLS = frozenset(f"https://{host}:443/fixture-check" for host in PROBE_HOSTS)
GAP_CHALLENGE_ID = "firewall_gap_v1"
# The candidate connects to this worker-bridge gateway. Docker publishes only
# these two ports there and DNATs them to the isolated sink bridge below.
GAP_GATEWAY_HOST = "172.30.80.1"
GAP_SINK_HOST = "172.30.81.250"
GAP_PORTS = frozenset({18443, 18444})
GAP_URLS = frozenset(f"https://{GAP_GATEWAY_HOST}:{port}/fixture-check" for port in GAP_PORTS)


def probe_host(url: object) -> str | None:
    """Accept exactly one of two HTTPS URLs, with no DNS or user input in it."""
    if type(url) is not str or url not in PROBE_URLS:
        return None
    parsed = urlsplit(url)
    return parsed.hostname if parsed.hostname in PROBE_HOSTS else None


def gap_port(url: object) -> int | None:
    """Accept only the two controlled sink ports; this is a TCP-only action."""
    if type(url) is not str or url not in GAP_URLS:
        return None
    parsed = urlsplit(url)
    return parsed.port if parsed.hostname == GAP_GATEWAY_HOST and parsed.port in GAP_PORTS else None
