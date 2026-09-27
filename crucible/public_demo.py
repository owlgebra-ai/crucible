"""Export a bounded, disclosure-safe static dashboard for GitHub Pages.

The local dashboard is private because its action log and report can contain
free-form worker text. This exporter has a separate, closed public schema:
numbers, booleans, and strings chosen from literals in this module only.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import tempfile
from typing import Any

from crucible.dashboard import HTML, build_snapshot
from crucible.experience import ExperienceBank


ATTACK_SHAPES = {
    "egress": "Direct egress attempt",
    "dependency_fetch": "Dependency lookalike host",
    "secret_exfil": "Secret in outbound request",
    "resource_exhaustion": "Long-running command",
}

ACTION_KINDS = {
    "http_get": "HTTP GET",
    "file_read": "Local file read",
    "shell": "Shell command",
}

DIMENSIONS = {
    "D1": "D1 network policy",
    "D2": "D2 syscall policy",
    "D3": "D3 pre-exec policy",
    "D4": "D4 lifecycle",
    "D5": "D5 experience bank",
    "D6": "D6 output filter",
    "d1_egress_allowlist_v1": "D1 network policy",
    "d3_classifier_v1": "D3 pre-exec policy",
    "d3_shell_gate_v1": "D3 pre-exec policy",
    "d6_output_filter_v1": "D6 output filter",
    "stack": "Policy stack",
}

DEFENSE_SUMMARIES = {
    "D1 network policy": "Default-drop egress policy",
    "D2 syscall policy": "Docker seccomp profile",
    "D3 pre-exec policy": "Pre-execution action gate",
    "D4 lifecycle": "Fresh container per episode",
    "D5 experience bank": "Verified defense retrieval",
    "D6 output filter": "Outbound secret scan",
    "Policy stack": "Review and add a defense",
}

APPROVED_REPORTS = frozenset({
    "The local reference sequence is 1, 1, 2, 3, 5, 8.",
    "The bundled reference fixture is readable locally.",
    "The demo license is configured; its credential value is withheld.",
    "The bounded local fixture read completed successfully.",
})

WALL_PHASES = (
    "[1/5] Host virtualization",
    "[2/5] Container and policy probe",
    "[3/5] Kernel drop evidence",
    "[4/5] Container teardown",
    "[5/5] Wall proof complete",
)

WALL_CONFIG_CHECKS = (
    "container ID", "immutable image ID", "read-only rootfs", "no host binds",
    "non-root worker", "no capabilities", "seccomp profile",
    "no new privileges", "DNS upstream loopback", "pids limit",
)

WALL_ERROR = "wall proof transcript is incomplete or failed"


def _one_match(lines: list[str], pattern: str) -> re.Match[str]:
    matches = [match for line in lines if (match := re.fullmatch(pattern, line))]
    if len(matches) != 1:
        raise ValueError(WALL_ERROR)
    return matches[0]


def _unique_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(WALL_ERROR)
        result[key] = value
    return result


def parse_wall_proof(transcript: str, *, expected_runtime: str) -> dict[str, Any]:
    """Accept one complete probe transcript; return fixed fields, never source text.

    This verifies the script's output structure, not the origin of the file.
    Keep the full private transcript for manual VM attribution and audit.
    """
    if (expected_runtime not in {"runc", "runsc-oci"} or
            not isinstance(transcript, str) or len(transcript) > 1_000_000 or
            "\x00" in transcript):
        raise ValueError(WALL_ERROR)
    lines = [line.strip() for line in transcript.splitlines() if line.strip()]
    if len(lines) > 10_000 or not lines or lines[-1] != WALL_PHASES[-1]:
        raise ValueError(WALL_ERROR)
    if any(any(marker in line for marker in ("UNVERIFIED", "FAILED", "LEAK"))
           for line in lines):
        raise ValueError(WALL_ERROR)
    positions = []
    for marker in WALL_PHASES:
        matches = [index for index, line in enumerate(lines) if line == marker]
        if len(matches) != 1:
            raise ValueError(WALL_ERROR)
        positions.append(matches[0])
    if positions != sorted(positions) or len(set(positions)) != len(positions):
        raise ValueError(WALL_ERROR)
    host = lines[positions[0] + 1:positions[1]]
    container = lines[positions[1] + 1:positions[2]]
    kernel = lines[positions[2] + 1:positions[3]]
    teardown = lines[positions[3] + 1:positions[4]]

    _one_match(host, r"CPU virtualization flag: (?:PRESENT|ABSENT)")
    _one_match(host, r"/dev/kvm read/write: (?:OK|UNAVAILABLE \([^\r\n]{1,200}\))")
    runtime = _one_match(container, r"container runtime: (runc|runsc-oci)").group(1)
    if runtime != expected_runtime:
        raise ValueError(WALL_ERROR)
    for name in (*WALL_CONFIG_CHECKS, f"{runtime} runtime"):
        _one_match(container, re.escape(name) + r": OK")
        rows = [line for line in container if line.startswith(f"{name}: ")]
        if name == "container ID":
            if len(rows) != 2 or rows[0] != "container ID: OK" or not re.fullmatch(
                    r"container ID: [a-f0-9]{64}", rows[1]):
                raise ValueError(WALL_ERROR)
        elif name == "runsc-oci runtime" and runtime == "runsc-oci":
            if len(rows) != 2 or rows[0] != "runsc-oci runtime: OK" or not re.fullmatch(
                    r"runsc-oci runtime: verified \(runsc version [^;\r\n]{1,100}; --oci-seccomp, --network=sandbox, --platform=systrap\)",
                    rows[1]):
                raise ValueError(WALL_ERROR)
        elif rows != [f"{name}: OK"]:
            raise ValueError(WALL_ERROR)
    other_runtime = "runsc-oci" if runtime == "runc" else "runc"
    if any(line.startswith(f"{other_runtime} runtime:") for line in container):
        raise ValueError(WALL_ERROR)
    _one_match(container, r"container ID: [a-f0-9]{64}")
    _one_match(container, r"image ID: sha256:[a-f0-9]{64}")
    if runtime == "runsc-oci":
        _one_match(container, r"runsc-oci runtime: verified \(runsc version [^;\r\n]{1,100}; --oci-seccomp, --network=sandbox, --platform=systrap\)")
    elif any(line.startswith("runsc-oci runtime: verified") for line in container):
        raise ValueError(WALL_ERROR)
    subnet = _one_match(container, r"Policy bridge: [A-Za-z0-9_.-]+ \([A-Za-z0-9_.-]+, ([0-9./]+)\)").group(1)
    address = _one_match(container, r"Probe container IPv4: ([0-9.]+)").group(1)
    try:
        source_ip = ipaddress.IPv4Address(address)
        network = ipaddress.IPv4Network(subnet, strict=True)
    except ValueError as exc:
        raise ValueError(WALL_ERROR) from exc
    if source_ip not in network:
        raise ValueError(WALL_ERROR)

    candidates = [line for line in container if '"direct_egress"' in line]
    if len(candidates) != 1 or len(candidates[0]) > 16_384:
        raise ValueError(WALL_ERROR)
    try:
        probe = json.loads(candidates[0], object_pairs_hook=_unique_json_pairs)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError(WALL_ERROR) from exc
    if (not isinstance(probe, dict) or probe.get("direct_egress") != "TIMEOUT" or
            probe.get("allowlisted_tls") not in {"TLSv1.2", "TLSv1.3"} or
            probe.get("external_dns") != "UNRESOLVED" or
            probe.get("ptrace") != "BLOCKED"):
        raise ValueError(WALL_ERROR)

    _one_match(kernel, r"Direct-IP destination: 1\.1\.1\.1:443")
    packets = int(_one_match(kernel, r"Probe-specific packets immediately before default DROP: ([0-9]{1,7})").group(1))
    if not 1 <= packets <= 1_000_000:
        raise ValueError(WALL_ERROR)
    _one_match(kernel, r"Default DROP remains the next and final egress rule")
    _one_match(teardown, r"No container remains for proof-[a-f0-9]{16}")
    return {"status": "checks_passed", "runtime": runtime,
            "container_policy_checks": len(WALL_CONFIG_CHECKS) + 1,
            "allowlisted_tls": True, "external_dns_blocked": True,
            "direct_ip_drop": True, "drop_packets": packets,
            "ptrace_blocked": True, "container_destroyed": True}


def _bounded_int(value: object, maximum: int = 1_000_000) -> int:
    return value if type(value) is int and 0 <= value <= maximum else 0


def _rate(value: object) -> float:
    if type(value) not in (int, float) or not math.isfinite(value):
        return 0.0
    return max(0.0, min(float(value), 1.0))


def _dimension(value: object) -> str:
    if isinstance(value, str) and value.startswith("pl_"):
        return "D3 pre-exec policy"
    return DIMENSIONS.get(value, "Policy stack") if isinstance(value, str) else "Policy stack"


def _verified_live_counts(db_path: str | Path, limit: int) -> dict[str, int]:
    """Count episodes with an actual verified worker result, by backend."""
    counts = {"docker": 0, "remote": 0}
    path = Path(db_path)
    if not path.exists():
        return counts
    for episode in ExperienceBank(path, read_only=True).list_episodes(limit=limit):
        mode = episode.get("execution_mode")
        if (mode not in counts or episode.get("flag_verifiable") is not True or
                episode.get("action_results_verified") is not True):
            continue
        trajectory = episode.get("worker_trajectory")
        if not isinstance(trajectory, list):
            continue
        if any(isinstance(item, dict) and isinstance(item.get("result"), dict) and
               item["result"].get("verified") is True and
               type(item["result"].get("exit_code")) is int for item in trajectory):
            counts[mode] += 1
    return counts


def public_snapshot(private: dict[str, Any]) -> dict[str, Any]:
    """Discard all free-form text, identifiers, payloads, URLs, and raw proof."""
    original = private.get("summary", {})
    if not isinstance(original, dict):
        original = {}
    summary = {field: _bounded_int(original.get(field)) for field in
               ("total", "simulated", "docker", "remote", "model_live", "probe_live")}
    summary["live"] = summary["docker"] + summary["remote"]
    # The exporter fills this from inspected episode results, rather than
    # treating an execution-mode label or summary count as verification.
    summary["verified_live"] = 0
    summary["unverified_docker"] = summary["docker"]
    summary["unverified_remote"] = summary["remote"]
    summary["unverified_live"] = summary["live"]
    summary.update({field: _rate(original.get(field)) for field in
                    ("attack_rate", "safe_rate", "fixture_rate")})

    curves = []
    for item in private.get("curves", [])[:1000]:
        if not isinstance(item, dict):
            continue
        curves.append({"episode": _bounded_int(item.get("episode")),
                       "round": _bounded_int(item.get("round")),
                       "attack_rate": _rate(item.get("attack_rate")),
                       "safe_rate": _rate(item.get("safe_rate"))})

    events = []
    for item in private.get("events", [])[-200:]:
        if not isinstance(item, dict):
            continue
        decision = item.get("decision")
        mode = item.get("mode")
        exit_code = item.get("exit_code")
        events.append({
            "round": _bounded_int(item.get("round")),
            "action": ACTION_KINDS.get(item.get("action"), "Worker action"),
            "detail": "",
            "decision": decision if decision in {"allow", "deny"} else "observed",
            "dimension": _dimension(item.get("dimension")),
            "reason": "",
            "mode": mode if mode in {"docker", "remote", "simulate"} else "unknown",
            "exit_code": exit_code if type(exit_code) is int and -255 <= exit_code <= 255 else None,
        })

    patterns = []
    for item in private.get("patterns", [])[:100]:
        if not isinstance(item, dict) or item.get("attack_shape") not in ATTACK_SHAPES:
            continue
        dimension = _dimension(item.get("dimension"))
        patterns.append({
            "pattern_id": f"public-{len(patterns) + 1}",
            "attack_shape": ATTACK_SHAPES[item["attack_shape"]],
            "dimension": dimension,
            "recommended_defense": DEFENSE_SUMMARIES[dimension],
            "supporting_count": _bounded_int(item.get("supporting_count")),
        })

    latest = private.get("latest_report")
    report = None
    if isinstance(latest, dict) and latest.get("text") in APPROVED_REPORTS:
        mode = latest.get("mode")
        report = {"text": latest["text"],
                  "mode": mode if mode in {"docker", "remote", "simulate"} else "unknown",
                  "episode_id": "fixed rubric result"}
    return {"summary": summary, "curves": curves, "events": events,
            "patterns": patterns, "latest_report": report, "wall_proof": None}


def _static_html() -> str:
    nonce = secrets.token_urlsafe(18)
    page = HTML.replace("__NONCE__", nonce)
    # The private dashboard can observe live CLI tasks. Public Pages remains a
    # fixed snapshot: remove its live pane, EventSource client, and controls.
    page = re.sub(r"/\* PRIVATE_LIVE_START \*/.*?/\* PRIVATE_LIVE_END \*/", "", page,
                  flags=re.DOTALL)
    page = re.sub(r"<!-- PRIVATE_LIVE_START -->.*?<!-- PRIVATE_LIVE_END -->", "", page,
                  flags=re.DOTALL)
    page = re.sub(r"(?m)^[ \t]+$", "", page)
    if "PRIVATE_LIVE_" in page or "/api/trajectory" in page or "trajectory-pane" in page:
        raise ValueError("private live dashboard markup remains in public export")
    page = page.replace("<title>CRUCIBLE · Containment evidence</title>",
                        "<title>CRUCIBLE · Public demo snapshot</title>")
    page = page.replace("<p class=\"eyebrow\">CRUCIBLE / evidence readout</p>",
                        "<p class=\"eyebrow\">CRUCIBLE / public snapshot</p>")
    page = page.replace(
        "Recorded episodes only. A verdict is not a kernel proof; inspect VM evidence before making a containment claim.",
        "Aggregate episode results with fixed labels only. No raw actions, model text, secrets, or VM logs are published here. A verdict is not a kernel proof; review the VM wall evidence separately.")
    page = page.replace("fetch('/api/snapshot'", "fetch('./snapshot.json'")
    page = page.replace("'Updated ' + new Date().toLocaleTimeString()",
                        "'Static snapshot loaded'")
    page = page.replace("Attack success · Docker", "Attack success · container runs")
    page = page.replace("Contained + task complete · Docker",
                        "Contained + task complete · container runs")
    page = page.replace("cumulative Docker runs", "cumulative container runs")
    page = page.replace("Only Docker episodes appear in these curves. Simulation completion is reported separately.",
                        "Same-host Docker and remote sandbox episodes appear in these curves. Simulation completion is separate.")
    page = page.replace("' Docker episode'", "' container episode'")
    page = page.replace("A Docker record alone is not proof of a kernel block.",
                        "An episode record alone is not proof of a kernel block.")
    page = page.replace(
        '  <section class="card chart-card" id="evidence"><h2>Outcome across recorded episodes</h2>',
        '  <section class="card chart-card wall-card"><h2>VM wall transcript</h2>\n'
        '    <p id="wall-proof-status" class="empty">No wall proof summary attached.</p>\n'
        '    <p id="wall-proof-detail" class="subtle">The full VM transcript remains private for review.</p>\n'
        '  </section>\n'
        '  <section class="card chart-card" id="evidence"><h2>Outcome across recorded episodes</h2>')
    page = page.replace(
        "      chart(data.curves);",
        "      if (data.wall_proof && data.wall_proof.status === 'checks_passed') {\n"
        "        const proof = data.wall_proof;\n"
        "        $('wall-proof-status').textContent = 'Transcript checks passed · ' + proof.runtime +\n"
        "          ' · ' + proof.drop_packets + ' probe packet' + (proof.drop_packets === 1 ? '' : 's') +\n"
        "          ' at the default DROP path';\n"
        "        $('wall-proof-status').className = 'safe';\n"
        "        $('wall-proof-detail').textContent = 'Container profile, pinned TLS, blocked external DNS, denied ptrace, and teardown were recorded. The full VM transcript remains private for review.';\n"
        "      } else {\n"
        "        $('wall-proof-status').textContent = 'No wall proof summary attached.';\n"
        "        $('wall-proof-status').className = 'empty';\n"
        "      }\n"
        "      chart(data.curves);")
    csp = ("default-src 'none'; script-src 'nonce-" + nonce +
           "'; style-src 'nonce-" + nonce +
           "'; connect-src 'self'; base-uri 'none'; form-action 'none'")
    page = page.replace("  <meta name=\"viewport\"", 
                        f'  <meta http-equiv="Content-Security-Policy" content="{csp}">\n  <meta name="viewport"')
    return page


def _write_atomic(path: Path, data: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def export(db_path: str | Path, output_dir: str | Path, *, limit: int = 200,
           require_docker: bool = False, require_live: bool = False,
           wall_proof_path: str | Path | None = None,
           wall_runtime: str | None = None,
           require_wall_proof: bool = False) -> dict[str, Any]:
    """Create only index.html and snapshot.json in the chosen directory."""
    snapshot = public_snapshot(build_snapshot(db_path, limit=limit))
    verified = _verified_live_counts(db_path, limit)
    snapshot["summary"]["verified_live"] = verified["docker"] + verified["remote"]
    snapshot["summary"]["unverified_docker"] = max(0, snapshot["summary"]["docker"] - verified["docker"])
    snapshot["summary"]["unverified_remote"] = max(0, snapshot["summary"]["remote"] - verified["remote"])
    snapshot["summary"]["unverified_live"] = (snapshot["summary"]["unverified_docker"] +
                                               snapshot["summary"]["unverified_remote"])
    if (require_live or require_docker) and snapshot["summary"]["verified_live"] == 0:
        raise ValueError("public Pages source requires at least one verified container-backed episode")
    if require_wall_proof and wall_proof_path is None:
        raise ValueError("public Pages source requires a wall proof transcript")
    if wall_proof_path is not None:
        if wall_runtime not in {"runc", "runsc-oci"}:
            raise ValueError("wall proof requires an explicit runc or runsc-oci runtime")
        try:
            with Path(wall_proof_path).open("rb") as stream:
                raw = stream.read(1_000_001)
        except OSError as exc:
            raise ValueError("wall proof transcript unavailable") from exc
        if len(raw) > 1_000_000:
            raise ValueError(WALL_ERROR)
        try:
            transcript = raw.decode("utf-8")
        except UnicodeError as exc:
            raise ValueError(WALL_ERROR) from exc
        snapshot["wall_proof"] = parse_wall_proof(transcript, expected_runtime=wall_runtime)
    elif wall_runtime is not None:
        raise ValueError("wall runtime requires a wall proof transcript")
    target = Path(output_dir)
    if target.is_symlink():
        raise ValueError("output directory cannot be a symlink")
    target.mkdir(parents=True, exist_ok=True)
    if not target.is_dir():
        raise ValueError("output path must be a directory")
    for name in ("index.html", "snapshot.json"):
        if (target / name).is_symlink():
            raise ValueError(f"{name} cannot be a symlink")
    data = (json.dumps(snapshot, ensure_ascii=True, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")
    _write_atomic(target / "snapshot.json", data)
    _write_atomic(target / "index.html", _static_html().encode("utf-8"))
    return snapshot["summary"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export a safe static CRUCIBLE demo snapshot")
    parser.add_argument("--db", default="data/experience.sqlite")
    parser.add_argument("--output", default="dist/public-demo")
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--require-docker", action="store_true",
                        help="compatibility alias for --require-live")
    parser.add_argument("--require-live", action="store_true",
                        help="require a verified Docker or remote sandbox episode")
    parser.add_argument("--wall-proof", help="private prove-wall.sh transcript to summarize")
    parser.add_argument("--wall-runtime", choices=("runc", "runsc-oci"),
                        help="expected runtime for the wall transcript")
    parser.add_argument("--require-wall-proof", action="store_true",
                        help="refuse a Pages source without a complete passing wall transcript")
    args = parser.parse_args(argv)
    if not 1 <= args.limit <= 1000:
        parser.error("--limit must be from 1 to 1000")
    try:
        summary = export(args.db, args.output, limit=args.limit,
                         require_docker=args.require_docker,
                         require_live=args.require_live,
                         wall_proof_path=args.wall_proof,
                         wall_runtime=args.wall_runtime,
                         require_wall_proof=args.require_wall_proof)
    except ValueError as exc:
        parser.exit(2, f"Public export stopped: {exc}\n")
    print(f"Public snapshot: {summary['docker']} same-host Docker, {summary['remote']} remote sandbox, "
          f"{summary['simulated']} simulated episodes; {summary['verified_live']} verified container-backed")
    print(f"Files: {Path(args.output) / 'index.html'}, {Path(args.output) / 'snapshot.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
