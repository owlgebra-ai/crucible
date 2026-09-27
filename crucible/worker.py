"""Execute one approved action inside a disposable container.

The host owns model access and policy decisions. This module receives no cloud key.
Every result is scanned before it leaves the worker; the host scans it again
because container output is untrusted.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import socket
import subprocess
import sys
import urllib.request
from urllib.error import HTTPError

from crucible.network_policy import SAFE_FETCH_URLS
from crucible.network_probe import GAP_GATEWAY_HOST, gap_port, probe_host
from crucible.safe_commands import parse_safe_command
from crucible.secret_scan import DEMO_CANARY, SecretScanner

MAX_OUTPUT = 32_768
SCAN_OVERLAP = 4_096
MAX_ACTION = 64 * 1024
WORK = Path("/work")
OUTPUT_SCANNER = SecretScanner((DEMO_CANARY,))


class PolicyDenied(ValueError):
    def __init__(self, dimension: str, reason: str) -> None:
        self.dimension = dimension
        super().__init__(reason)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise HTTPError(request.full_url, code, "redirect blocked", headers, fp)


def _inside(path: str, root: Path) -> Path:
    root = root.resolve(strict=False)
    target = Path(path)
    if not target.is_absolute():
        target = root / target
    resolved = target.resolve(strict=False)
    if resolved != root and root not in resolved.parents:
        raise ValueError("path outside permitted work directory")
    return resolved


def execute(action: dict) -> dict:
    kind = action.get("kind")
    payload = action.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    if kind == "shell":
        command = payload.get("cmd")
        try:
            argv = parse_safe_command(command)
        except ValueError:
            raise PolicyDenied("D3", "command outside diagnostic grammar") from None
        result = subprocess.run(
            argv, cwd="/work", capture_output=True,
            text=True, errors="replace", timeout=15, check=False, env={
                "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/work", "TMPDIR": "/work"
            },
        )
        return {"exit_code": result.returncode,
                "stdout": result.stdout[:MAX_OUTPUT + SCAN_OVERLAP],
                "stderr": result.stderr[:MAX_OUTPUT + SCAN_OVERLAP],
                "truncated": (len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT)}
    if kind == "file_read":
        path = _inside(str(payload.get("path", "")), WORK)
        with path.open("rb") as handle:
            body = handle.read(MAX_OUTPUT + SCAN_OVERLAP + 1)
        return {"exit_code": 0, "stdout": body.decode("utf-8", "replace"),
                "stderr": "", "truncated": len(body) > MAX_OUTPUT}
    if kind == "file_write":
        path = _inside(str(payload.get("path", "")), WORK / "output")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(payload.get("content", "")))
        return {"exit_code": 0, "stdout": str(path), "stderr": ""}
    if kind == "http_get":
        url = str(payload.get("url", ""))
        if not url.startswith("https://"):
            raise ValueError("http_get requires HTTPS")
        if url not in SAFE_FETCH_URLS:
            raise PolicyDenied("D1", "network URL is outside exact fetch policy")
        request = urllib.request.Request(url, method="GET", headers={"User-Agent": "crucible-worker/0.1"})
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(request, timeout=10) as response:
                body = response.read(MAX_OUTPUT + SCAN_OVERLAP + 1)
                return {"exit_code": 0, "stdout": body.decode("utf-8", "replace"),
                        "stderr": "", "http_status": response.status,
                        "network_request_attempted": True, "network_response_received": True,
                        "truncated": len(body) > MAX_OUTPUT}
        except HTTPError as exc:
            exc.close()
            return {"exit_code": 1, "stdout": "", "stderr": f"HTTP status {exc.code}",
                    "http_status": exc.code, "network_request_attempted": True,
                    "network_response_received": True}
        except Exception as exc:
            return {"exit_code": 1, "stdout": "", "stderr": f"network error: {type(exc).__name__}",
                    "network_request_attempted": True, "network_response_received": False}
    if kind == "net_connect":
        # A dedicated, fixed challenge can exercise the VM2 kernel wall.  A
        # direct IPv4 socket avoids DNS and sends no application data, even if
        # the firewall is unexpectedly open.  The gateway separately requires
        # a trusted challenge ID and proves a per-container DROP hit.
        url = payload.get("url") if set(payload) == {"url"} else None
        host = probe_host(url)
        port = 443 if host is not None else gap_port(url)
        if port is not None and host is None:
            host = GAP_GATEWAY_HOST
        if host is None or port is None:
            raise PolicyDenied("D1", "destination is outside fixed network probe")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                connection.settimeout(3)
                connection.connect((host, port))
        except OSError:
            return {"exit_code": 1, "stdout": "", "stderr": "network connection blocked",
                    "network_request_attempted": True, "network_response_received": False}
        return {"exit_code": 0, "stdout": "", "stderr": "network connection established",
                "network_request_attempted": True, "network_response_received": True}
    raise ValueError(f"unsupported action kind: {kind}")


def sanitize_result(result: dict) -> dict:
    """Construct the only JSON record allowed to cross the worker boundary."""
    safe = {"exit_code": result["exit_code"] if type(result.get("exit_code")) is int else 1}
    redactions = 0
    truncated = result.get("truncated") is True
    for field in ("stdout", "stderr"):
        value = result.get(field, "")
        if not isinstance(value, str):
            value = ""
        clean, count = OUTPUT_SCANNER.redact(value)
        truncated |= len(clean) > MAX_OUTPUT
        safe[field] = clean[:MAX_OUTPUT]
        redactions += count
    safe["redactions"] = min(redactions, MAX_OUTPUT)
    safe["output_blocked"] = redactions > 0
    safe["truncated"] = truncated
    for field in ("network_request_attempted", "network_response_received"):
        if field in result:
            safe[field] = result[field] is True
    if result.get("policy_denial") in {"D1", "D2", "D3", "D4", "D5", "D6"}:
        safe["policy_denial"] = result["policy_denial"]
    status = result.get("http_status")
    if type(status) is int and 100 <= status <= 599:
        safe["http_status"] = status
    return safe


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--action-file", default="/work/scenario/action.json")
    args = parser.parse_args()
    try:
        if args.action_file == "-":
            raw = sys.stdin.buffer.read(MAX_ACTION + 1)
            if len(raw) > MAX_ACTION:
                raise ValueError("action input too large")
            action = json.loads(raw)
        else:
            action = json.loads(Path(args.action_file).read_text())
        if not isinstance(action, dict):
            raise ValueError("action must be a JSON object")
        result = execute(action)
    except subprocess.TimeoutExpired:
        result = {"exit_code": 124, "stdout": "", "stderr": "action timed out"}
    except PolicyDenied as exc:
        result = {"exit_code": 77, "stdout": "", "stderr": "worker policy denied",
                  "policy_denial": exc.dimension}
    except Exception:
        # Exception text may contain an action path, URL, or credential.
        result = {"exit_code": 1, "stdout": "", "stderr": "worker action failed"}
    try:
        record = sanitize_result(result)
    except Exception:
        record = {"exit_code": 1, "stdout": "", "stderr": "worker result unavailable",
                  "redactions": 0, "output_blocked": False, "truncated": False}
    print(json.dumps(record, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
