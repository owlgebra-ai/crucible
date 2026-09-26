#!/usr/bin/env python3
"""Narrow VM2 SSH ingress after the private control-to-sandbox path is proven.

Dry-run is the default. The public admin rule is removed only with an explicit
private-path verification flag, after the private /32 rule has been verified.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import re
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from deploy.provision_vm import (ProvisionError, VultrManagement, _admin_ipv4,  # noqa: E402
                                 load_management_key)
from deploy.vpc_pair import _private_state  # noqa: E402


def _private_ip(value: str) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        raise ProvisionError("Control private IP must be RFC 1918 IPv4") from None
    if not any(address in ipaddress.IPv4Network(item) for item in
               ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")):
        raise ProvisionError("Control private IP must be RFC 1918 IPv4")
    return str(address)


def _rule_matches(rule: dict[str, Any], ip: str) -> bool:
    return (rule.get("ip_type") == "v4" and rule.get("protocol") == "tcp" and
            str(rule.get("port")) == "22" and rule.get("subnet") == ip and
            str(rule.get("subnet_size")) == "32" and
            rule.get("source", "") in {"", f"{ip}/32"})


def _rules(api: VultrManagement, group_id: str) -> list[dict[str, Any]]:
    data = api.request("GET", f"/firewalls/{group_id}/rules").get("firewall_rules")
    if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
        raise ProvisionError("Sandbox firewall rule listing is malformed")
    return data


def limit(api: VultrManagement, *, sandbox_state: Path, admin_source: str,
          control_private_ip: str, apply: bool = False, close_public_admin: bool = False,
          private_path_verified: bool = False) -> dict[str, Any]:
    try:
        state = json.loads(_private_state(sandbox_state).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        raise ProvisionError("Cannot read sandbox VM recovery state") from None
    instance_id = state.get("instance_id") if isinstance(state, dict) else None
    group_id = state.get("firewall_group_id") if isinstance(state, dict) else None
    if not isinstance(instance_id, str) or not re.fullmatch(r"[A-Za-z0-9-]{4,100}", instance_id) or \
            not isinstance(group_id, str) or not re.fullmatch(r"[A-Za-z0-9-]{4,100}", group_id):
        raise ProvisionError("Sandbox recovery state lacks valid instance and firewall IDs")
    admin_ip = _admin_ipv4(admin_source)
    private_ip = _private_ip(control_private_ip)
    instance = api.request("GET", f"/instances/{instance_id}").get("instance")
    if not isinstance(instance, dict) or instance.get("id") != instance_id or \
            instance.get("firewall_group_id") != group_id:
        raise ProvisionError("Sandbox VM firewall attachment could not be verified")
    current = _rules(api, group_id)
    admin = [rule for rule in current if _rule_matches(rule, admin_ip)]
    private = [rule for rule in current if _rule_matches(rule, private_ip)]
    if len(admin) > 1 or len(private) > 1 or len(current) != len(admin) + len(private):
        raise ProvisionError("Sandbox firewall has unexpected rules; inspect it manually")
    if close_public_admin and apply and not private_path_verified:
        raise ProvisionError("Prove SSH from control over the VPC before closing public admin access")
    print(f"Sandbox VM: {instance_id}; firewall group: {group_id}")
    print(f"Allow control private SSH: {private_ip}/32")
    print(f"Public admin SSH: {'remove after private-path proof' if close_public_admin else 'keep during bootstrap'}")
    if not apply:
        print("Dry run: no firewall rule changed.")
        return {"dry_run": True, "private_rule": bool(private), "public_admin_rule": bool(admin)}
    if not private:
        api.request("POST", f"/firewalls/{group_id}/rules", {
            "ip_type": "v4", "protocol": "tcp", "port": "22", "subnet": private_ip,
            "subnet_size": 32, "source": "", "notes": "CRUCIBLE control VPC SSH only",
        })
        current = _rules(api, group_id)
        private = [rule for rule in current if _rule_matches(rule, private_ip)]
        if len(private) != 1:
            raise ProvisionError("Private SSH rule was not verified; public admin remains open")
    if close_public_admin and admin:
        rule_id = admin[0].get("id")
        if not isinstance(rule_id, (str, int)) or not re.fullmatch(r"[A-Za-z0-9-]{1,100}", str(rule_id)):
            raise ProvisionError("Public admin rule ID was invalid; no rule deleted")
        api.request("DELETE", f"/firewalls/{group_id}/rules/{rule_id}")
    final = _rules(api, group_id)
    if len([rule for rule in final if _rule_matches(rule, private_ip)]) != 1 or \
            (close_public_admin and any(_rule_matches(rule, admin_ip) for rule in final)):
        raise ProvisionError("Sandbox firewall post-change verification failed")
    print("Verified sandbox firewall: private control /32 allowed" +
          ("; public admin rule removed" if close_public_admin else "; public admin rule retained"))
    return {"dry_run": False, "private_rule": True,
            "public_admin_rule": any(_rule_matches(rule, admin_ip) for rule in final)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sandbox-state", required=True, type=Path)
    parser.add_argument("--admin-ip", required=True, help="Existing public admin IPv4 /32")
    parser.add_argument("--control-private-ip", required=True)
    parser.add_argument("--close-public-admin", action="store_true")
    parser.add_argument("--private-path-verified", action="store_true")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        api = VultrManagement(load_management_key())
        limit(api, sandbox_state=args.sandbox_state, admin_source=args.admin_ip,
              control_private_ip=args.control_private_ip, apply=args.apply,
              close_public_admin=args.close_public_admin,
              private_path_verified=args.private_path_verified)
    except ProvisionError as exc:
        print(f"Sandbox firewall change stopped: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
