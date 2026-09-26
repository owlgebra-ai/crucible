#!/usr/bin/env python3
"""Guarded VPC 2.0 attachment for two already provisioned Vultr VMs.

Dry-run is the default. The Vultr management key stays on this local machine.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from deploy.provision_vm import (KEY_FILE, ROOT, ProvisionError, VultrManagement,
                                 load_management_key)


ID = re.compile(r"[a-zA-Z0-9-]{8,80}\Z")
DEFAULT_STATE = ROOT / "secrets" / "vpc_pair.json"


def _private_state(path: Path) -> Path:
    resolved = path.resolve()
    if ROOT / "secrets" not in resolved.parents:
        raise ProvisionError("All state files must be under the ignored secrets directory")
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise ProvisionError("VM state must be a regular owner-only file")
    return resolved


def _vm(path: Path) -> tuple[str, str]:
    try:
        state = json.loads(_private_state(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        raise ProvisionError("Cannot read VM recovery state") from None
    instance_id, region = state.get("instance_id"), state.get("region")
    if not isinstance(instance_id, str) or not ID.fullmatch(instance_id) or \
            not isinstance(region, str) or not re.fullmatch(r"[a-z0-9]{2,12}", region):
        raise ProvisionError("VM recovery state lacks a valid instance ID and region")
    return instance_id, region


def _node_ids(response: dict[str, Any]) -> set[str]:
    nodes = response.get("nodes")
    if not isinstance(nodes, list):
        raise ProvisionError("VPC node listing had an unexpected shape")
    found: set[str] = set()
    for node in nodes:
        if isinstance(node, str) and ID.fullmatch(node):
            found.add(node)
        elif isinstance(node, dict):
            for key in ("id", "instance_id", "node_id"):
                value = node.get(key)
                if isinstance(value, str) and ID.fullmatch(value):
                    found.add(value)
    return found


def _save(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise ProvisionError("VPC recovery state cannot be a symlink")
    data = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if path.exists():
        if path.stat().st_mode & 0o077:
            raise ProvisionError("VPC recovery state must be owner-only")
        path.write_bytes(data)
    else:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)


def _legacy_attached(api: VultrManagement, instance_id: str, vpc_id: str) -> bool:
    response = api.request("GET", f"/instances/{instance_id}/vpcs")
    networks = response.get("vpcs")
    if not isinstance(networks, list):
        raise ProvisionError("Instance VPC listing had an unexpected shape")
    return any((item == vpc_id if isinstance(item, str) else
                isinstance(item, dict) and item.get("id", item.get("vpc_id")) == vpc_id)
               for item in networks)


def attach(api: VultrManagement, *, control_state: Path, sandbox_state: Path,
           state_file: Path = DEFAULT_STATE, vpc_id: str = "", apply: bool = False,
           kind: str = "vpc2") -> dict[str, Any]:
    if kind not in {"vpc2", "vpc"}:
        raise ProvisionError("Network kind must be vpc2 or vpc")
    control_id, control_region = _vm(control_state)
    sandbox_id, sandbox_region = _vm(sandbox_state)
    if control_id == sandbox_id or control_region != sandbox_region:
        raise ProvisionError("Control and sandbox must be distinct VMs in one region")
    for instance_id in (control_id, sandbox_id):
        response = api.request("GET", f"/instances/{instance_id}").get("instance")
        if not isinstance(response, dict) or response.get("id") != instance_id or \
                response.get("region") != control_region:
            raise ProvisionError("VM account identity or region could not be verified")
    state_file = state_file.resolve()
    if ROOT / "secrets" not in state_file.parents:
        raise ProvisionError("VPC recovery state must be under the ignored secrets directory")
    if state_file.exists():
        saved = json.loads(_private_state(state_file).read_text(encoding="utf-8"))
        if (saved.get("control_id"), saved.get("sandbox_id"), saved.get("region"),
            saved.get("kind", "vpc2")) != (control_id, sandbox_id, control_region, kind):
            raise ProvisionError("Existing VPC recovery state belongs to another VM pair")
        vpc_id = saved.get("vpc_id", "")
    if vpc_id and not ID.fullmatch(vpc_id):
        raise ProvisionError("Invalid VPC ID")
    if vpc_id:
        vpc = api.request("GET", f"/{'vpc2' if kind == 'vpc2' else 'vpcs'}/{vpc_id}").get(
            "vpc2" if kind == "vpc2" else "vpc")
        if not isinstance(vpc, dict) or vpc.get("id") != vpc_id or vpc.get("region") != control_region:
            raise ProvisionError("VPC identity or region could not be verified")
    print(f"Control VM: {control_id}; sandbox VM: {sandbox_id}; region: {control_region}")
    print(f"{'VPC 2.0' if kind == 'vpc2' else 'VPC'}: {vpc_id or 'create new private network'}")
    if not apply:
        print("Dry run: no VPC was created and no VM was attached.")
        return {"dry_run": True, "control_id": control_id, "sandbox_id": sandbox_id,
                "region": control_region, "vpc_id": vpc_id, "kind": kind}
    if not vpc_id:
        response = api.request("POST", "/vpc2" if kind == "vpc2" else "/vpcs", {"region": control_region,
            "description": "crucible-control-sandbox-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")})
        vpc = response.get("vpc2" if kind == "vpc2" else "vpc")
        vpc_id = vpc.get("id", "") if isinstance(vpc, dict) else ""
        if not isinstance(vpc_id, str) or not ID.fullmatch(vpc_id):
            raise ProvisionError("VPC may have been created, but its ID was not returned; inspect account before retrying")
    record = {"vpc_id": vpc_id, "control_id": control_id, "sandbox_id": sandbox_id,
              "region": control_region, "kind": kind, "attached_verified": False}
    _save(state_file, record)
    if kind == "vpc2":
        current = _node_ids(api.request("GET", f"/vpc2/{vpc_id}/nodes"))
        missing = [instance_id for instance_id in (control_id, sandbox_id) if instance_id not in current]
        if missing:
            api.request("POST", f"/vpc2/{vpc_id}/nodes/attach", {"nodes": missing})
        final = _node_ids(api.request("GET", f"/vpc2/{vpc_id}/nodes"))
        verified = {control_id, sandbox_id}.issubset(final)
    else:
        for instance_id in (control_id, sandbox_id):
            if not _legacy_attached(api, instance_id, vpc_id):
                api.request("POST", f"/instances/{instance_id}/vpcs/attach", {"vpc_id": vpc_id})
        verified = all(_legacy_attached(api, instance_id, vpc_id)
                       for instance_id in (control_id, sandbox_id))
    if not verified:
        raise ProvisionError("VPC attach request returned, but both VM attachments are not verified")
    record["attached_verified"] = True
    _save(state_file, record)
    print(f"Verified both VM IDs on {kind} {vpc_id}; recovery record: {state_file}")
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control-state", required=True, type=Path)
    parser.add_argument("--sandbox-state", required=True, type=Path)
    parser.add_argument("--state-file", default=DEFAULT_STATE, type=Path)
    parser.add_argument("--vpc-id", default="", help="Attach to an existing same-region VPC 2.0")
    parser.add_argument("--kind", choices=["vpc2", "vpc"], default="vpc2",
                        help="VPC 2.0 or legacy VPC API; choose vpc where /vpc2 is unavailable")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        api = VultrManagement(load_management_key(KEY_FILE))
        attach(api, control_state=args.control_state, sandbox_state=args.sandbox_state,
               state_file=args.state_file, vpc_id=args.vpc_id, apply=args.apply, kind=args.kind)
    except ProvisionError as exc:
        print(f"VPC pairing stopped: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
