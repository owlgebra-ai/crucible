"""Guarded, opt-in provisioning of one Vultr VM for CRUCIBLE.

``provision`` is read-only unless both ``--apply`` and
``--confirm-hourly-billing`` are given. The management API key stays on the
controller; it is never sent to the VM or included in a deployment archive.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_CEILING, ROUND_FLOOR
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)


API_BASE = "https://api.vultr.com/v2"
ROOT = Path(__file__).resolve().parent.parent
_key_file_setting = os.getenv("CRUCIBLE_MANAGEMENT_KEY_FILE", "secrets/vultr_key.json")
KEY_FILE = Path(_key_file_setting)
if not KEY_FILE.is_absolute():
    KEY_FILE = ROOT / KEY_FILE
STATE_FILE = ROOT / "secrets" / "provisioned_vm.json"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_PLANNED_HOURS = 168
UBUNTU_NAME = "Ubuntu 24.04 LTS x64"
PUBLIC_KEY_TYPES = {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}


class ProvisionError(Exception):
    """A credential-free failure message suitable for display."""


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, request: Request, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        return None


def _tls_context() -> ssl.SSLContext:
    if ssl.get_default_verify_paths().cafile:
        return ssl.create_default_context()
    try:
        import certifi
    except ImportError:
        return ssl.create_default_context()
    return ssl.create_default_context(cafile=certifi.where())


def load_management_key(path: Path = KEY_FILE) -> str:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
            raise ProvisionError("Management key file must be accessible only to its owner (chmod 600)")
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        raise ProvisionError("Cannot read the local Vultr management key file") from None
    key = payload.get("api_key") if isinstance(payload, dict) else None
    if not isinstance(key, str) or not key or any(c in key for c in "\r\n"):
        raise ProvisionError("Management key file must contain one valid api_key string")
    return key


class VultrManagement:
    def __init__(self, key: str):
        self._key = key
        # No environment proxy and no redirects: neither can receive a bearer
        # credential intended only for api.vultr.com.
        self._opener = build_opener(ProxyHandler({}), _RejectRedirects(),
                                    HTTPSHandler(context=_tls_context()))

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        if method not in {"GET", "POST", "DELETE"} or not path.startswith("/") or "//" in path:
            raise ValueError("Invalid management request")
        data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = {"Accept": "application/json", "Authorization": f"Bearer {self._key}"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = Request(API_BASE + path, data=data, headers=headers, method=method)
        try:
            with self._opener.open(req, timeout=20) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            raise ProvisionError(f"Vultr management {method} {path.split('?')[0]} returned HTTP {exc.code}") from None
        except (TimeoutError, socket.timeout):
            raise ProvisionError(f"Vultr management {method} timed out; check resources before retrying") from None
        except URLError:
            raise ProvisionError(f"Vultr management {method} connection failed; check resources before retrying") from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ProvisionError("Vultr management response exceeded size limit")
        if not raw:
            return {}
        try:
            result = json.loads(raw)
        except (UnicodeError, ValueError):
            raise ProvisionError("Vultr management returned invalid JSON") from None
        if not isinstance(result, dict):
            raise ProvisionError("Vultr management returned an unexpected response")
        return result

    def list_all(self, path: str, field: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        cursor = ""
        seen: set[str] = set()
        for _ in range(20):
            suffix = f"?per_page=500&cursor={quote(cursor, safe='')}" if cursor else "?per_page=500"
            response = self.request("GET", path + suffix)
            page = response.get(field)
            if not isinstance(page, list) or any(not isinstance(item, dict) for item in page):
                raise ProvisionError(f"Vultr management {path} returned an unexpected catalog")
            items.extend(page)
            meta = response.get("meta", {})
            links = meta.get("links", {}) if isinstance(meta, dict) else {}
            next_cursor = links.get("next", "") if isinstance(links, dict) else ""
            if not next_cursor:
                return items
            if not isinstance(next_cursor, str) or next_cursor in seen:
                break
            seen.add(next_cursor)
            cursor = next_cursor
        raise ProvisionError(f"Vultr management {path} pagination did not finish")


def _public_key(path: Path) -> tuple[str, str, str]:
    try:
        if path.suffix != ".pub" or path.is_symlink() or path.stat().st_size > 8192:
            raise ProvisionError("Select one regular .pub SSH public-key file")
        line = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        raise ProvisionError("Cannot read the selected SSH public-key file") from None
    parts = line.split()
    if len(parts) < 2 or parts[0] not in PUBLIC_KEY_TYPES or "\n" in line or "\r" in line:
        raise ProvisionError("SSH public-key file must contain one supported OpenSSH public key")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except binascii.Error:
        raise ProvisionError("SSH public-key file contains invalid base64") from None
    if len(blob) < 32:
        raise ProvisionError("SSH public-key file is too short")
    canonical = parts[0] + " " + parts[1]
    fingerprint = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return line, canonical, "SHA256:" + fingerprint


def _admin_ipv4(value: str) -> str:
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        raise ProvisionError("Admin source must be an explicit public IPv4 /32 CIDR") from None
    if network.version != 4 or network.prefixlen != 32 or not network.network_address.is_global:
        raise ProvisionError("Admin source must be an explicit public IPv4 /32 CIDR")
    return str(network.network_address)


def _money(value: Any, label: str) -> Decimal:
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise ProvisionError(f"Invalid {label}") from None
    if not amount.is_finite() or amount <= 0:
        raise ProvisionError(f"Invalid {label}")
    return amount


@dataclass(frozen=True)
class Plan:
    region: str
    region_name: str
    plan_id: str
    hourly: Decimal
    monthly: Decimal
    vcpus: int
    ram_mb: int
    disk_gb: int
    os_id: int
    admin_ip: str
    public_key: str
    canonical_key: str
    fingerprint: str
    key_path: Path
    hours: int
    estimated: Decimal
    max_total: Decimal | None


def make_plan(api: VultrManagement, *, region: str, plan_id: str, admin_source: str,
              key_path: Path, max_hours: int | None, max_total_spend: str | None) -> Plan:
    if not re.fullmatch(r"[a-z0-9]{2,12}", region) or not re.fullmatch(r"[a-z0-9-]{4,80}", plan_id):
        raise ProvisionError("Invalid region or plan ID")
    admin_ip = _admin_ipv4(admin_source)
    public_key, canonical, fingerprint = _public_key(key_path)
    if max_hours is None and max_total_spend is None:
        raise ProvisionError("Provide --max-hours or --max-total-spend")
    if max_hours is not None and not 1 <= max_hours <= MAX_PLANNED_HOURS:
        raise ProvisionError(f"--max-hours must be between 1 and {MAX_PLANNED_HOURS}")
    max_total = _money(max_total_spend, "maximum total spend") if max_total_spend is not None else None

    regions = api.list_all("/regions", "regions")
    selected_region = next((item for item in regions if item.get("id") == region), None)
    if selected_region is None:
        raise ProvisionError("Selected region is absent from the live Vultr catalog")
    plans = api.list_all("/plans", "plans")
    selected_plan = next((item for item in plans if item.get("id") == plan_id), None)
    if selected_plan is None:
        raise ProvisionError("Selected plan is absent from the live Vultr catalog")
    availability = api.request("GET", f"/regions/{region}/availability").get("available_plans")
    if not isinstance(availability, list) or plan_id not in availability:
        raise ProvisionError("Selected plan is not currently available in that region")
    systems = api.list_all("/os", "os")
    ubuntu = next((item for item in systems if item.get("name") == UBUNTU_NAME), None)
    if ubuntu is None or not isinstance(ubuntu.get("id"), int):
        raise ProvisionError("Ubuntu 24.04 LTS x64 is absent from the live Vultr catalog")

    hourly = _money(selected_plan.get("hourly_cost"), "live hourly price")
    monthly = _money(selected_plan.get("monthly_cost"), "live monthly price")
    # The API rounds its displayed hourly rate. Use the larger of that rate
    # and the monthly price spread across Vultr's 672-hour non-GPU cap when
    # sizing a spend guard, then round the total estimate upward to cents.
    budget_hourly = max(hourly, monthly / Decimal(672))
    if max_hours is None:
        assert max_total is not None
        max_hours = min(MAX_PLANNED_HOURS, int((max_total / budget_hourly).to_integral_value(rounding=ROUND_FLOOR)))
    if max_hours < 1:
        raise ProvisionError("Spend cap is below the first billable hour")
    estimated = (budget_hourly * max_hours).quantize(Decimal("0.01"), rounding=ROUND_CEILING)
    if max_total is not None and estimated > max_total:
        raise ProvisionError("Planned hours exceed the explicit maximum total spend")
    try:
        vcpus = int(selected_plan["vcpu_count"])
        ram = int(selected_plan["ram"])
        disk = int(selected_plan["disk"])
    except (KeyError, TypeError, ValueError):
        raise ProvisionError("Live plan specifications are incomplete") from None
    if min(vcpus, ram, disk) < 1:
        raise ProvisionError("Live plan specifications are invalid")
    return Plan(region, f"{selected_region.get('city', region)}, {selected_region.get('country', '')}",
                plan_id, hourly, monthly, vcpus, ram, disk, ubuntu["id"], admin_ip,
                public_key, canonical, fingerprint, key_path, max_hours, estimated, max_total)


def _same_key(left: str, right: str) -> bool:
    pieces = left.split()
    return len(pieces) >= 2 and pieces[0] + " " + pieces[1] == right


def _existing_key(api: VultrManagement, plan: Plan) -> str | None:
    for item in api.list_all("/ssh-keys", "ssh_keys"):
        if isinstance(item.get("ssh_key"), str) and _same_key(item["ssh_key"], plan.canonical_key):
            key_id = item.get("id")
            if isinstance(key_id, str) and key_id:
                return key_id
    return None


def print_plan(plan: Plan, existing_key_id: str | None) -> None:
    print(f"Region: {plan.region} ({plan.region_name})")
    print(f"Plan: {plan.plan_id} — {plan.vcpus} vCPU, {plan.ram_mb} MB RAM, {plan.disk_gb} GB disk")
    print(f"OS: {UBUNTU_NAME} (ID {plan.os_id})")
    print(f"Price: ${plan.hourly}/hour, ${plan.monthly}/month catalog")
    print(f"Planning horizon: {plan.hours} hours; conservative compute estimate ${plan.estimated}")
    if plan.max_total is not None:
        print(f"User-specified maximum estimate: ${plan.max_total}")
    print(f"SSH public key: {plan.key_path} ({plan.fingerprint}); " +
          ("already registered" if existing_key_id else "will register"))
    print(f"Inbound firewall: TCP 22 from {plan.admin_ip}/32 only; IPv6 disabled")
    print("Backups and DDoS add-ons: disabled")
    print("The planning horizon does not auto-destroy the VM; destroy it to stop billing.")


def _required_id(response: dict[str, Any], field: str) -> str:
    item = response.get(field)
    value = item.get("id") if isinstance(item, dict) else None
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9-]{4,100}", value):
        raise ProvisionError(f"Vultr returned no valid {field} ID; inspect account resources before retrying")
    return value


def _verify_firewall(api: VultrManagement, group_id: str, admin_ip: str) -> None:
    response = api.request("GET", f"/firewalls/{group_id}/rules")
    rules = response.get("firewall_rules")
    if not isinstance(rules, list) or len(rules) != 1:
        raise ProvisionError("New firewall group does not contain exactly one SSH rule")
    rule = rules[0]
    if not isinstance(rule, dict) or not (
        rule.get("ip_type") == "v4" and rule.get("protocol") == "tcp" and
        str(rule.get("port")) == "22" and rule.get("subnet") == admin_ip and
        str(rule.get("subnet_size")) == "32" and
        rule.get("source", "") in {"", f"{admin_ip}/32"}
    ):
        raise ProvisionError("New firewall group has an unexpected rule; VM was not created")


def _verify_reusable_firewall(api: VultrManagement, group_id: str, admin_ip: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9-]{4,100}", group_id):
        raise ProvisionError("Invalid existing firewall group ID")
    group = api.request("GET", f"/firewalls/{group_id}").get("firewall_group")
    if not isinstance(group, dict) or group.get("id") != group_id or \
            group.get("description") != f"crucible SSH {admin_ip}/32":
        raise ProvisionError("Existing firewall group has unexpected identity or description")
    _verify_firewall(api, group_id, admin_ip)
    instances = api.list_all("/instances", "instances")
    if any(item.get("firewall_group_id") == group_id for item in instances):
        raise ProvisionError("Existing firewall group is already attached to an instance")


def _write_state(state: dict[str, Any], path: Path = STATE_FILE) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                     prefix=".provision-", delete=False) as file:
        temp_path = Path(file.name)
        os.chmod(temp_path, 0o600)
        json.dump(state, file, indent=2)
        file.write("\n")
    os.replace(temp_path, path)


def guard_pair_estimate(plan: Plan, peer_state: Path, aggregate_cap: str) -> Decimal:
    """Require the recorded peer plus this VM to fit one compute estimate cap."""
    if peer_state.is_symlink() or not peer_state.is_file() or peer_state.stat().st_mode & 0o077:
        raise ProvisionError("Peer VM state must be a regular owner-only file")
    if ROOT / "secrets" not in peer_state.resolve().parents:
        raise ProvisionError("Peer VM state must be under the ignored secrets directory")
    try:
        peer = json.loads(peer_state.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        raise ProvisionError("Cannot read peer VM recovery state") from None
    if not isinstance(peer, dict) or peer.get("region") != plan.region or not peer.get("instance_id"):
        raise ProvisionError("Peer VM must be a provisioned instance in the same region")
    peer_estimate = _money(peer.get("estimated_compute_usd"), "peer compute estimate")
    total = plan.estimated + peer_estimate
    cap = _money(aggregate_cap, "aggregate compute cap")
    if total > cap:
        raise ProvisionError(f"Two-VM estimated compute ${total} exceeds aggregate cap ${cap}")
    print(f"Two-VM estimated compute: ${peer_estimate} peer + ${plan.estimated} planned = ${total} \
against aggregate cap ${cap}")
    return total


def _valid_public_ip(value: Any) -> bool:
    try:
        return isinstance(value, str) and ipaddress.ip_address(value).version == 4 and ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def apply_plan(api: VultrManagement, plan: Plan, existing_key_id: str | None,
               *, state_path: Path = STATE_FILE, poll_seconds: int = 600,
               existing_firewall_group_id: str | None = None) -> dict[str, Any]:
    state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_path = state_path.with_suffix(".lock")
    try:
        with lock_path.open("a+", encoding="utf-8") as lock:
            os.chmod(lock_path, 0o600)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ProvisionError("Another VM provisioning attempt is already running") from None
            return _apply_plan_locked(api, plan, existing_key_id,
                                      state_path=state_path, poll_seconds=poll_seconds,
                                      existing_firewall_group_id=existing_firewall_group_id)
    except OSError:
        raise ProvisionError("Cannot create the local provisioning lock") from None


def _apply_plan_locked(api: VultrManagement, plan: Plan, existing_key_id: str | None,
                       *, state_path: Path, poll_seconds: int,
                       existing_firewall_group_id: str | None = None) -> dict[str, Any]:
    if state_path.exists():
        raise ProvisionError(f"Local provision state already exists at {state_path}; inspect or destroy that VM first")
    if existing_firewall_group_id is not None:
        _verify_reusable_firewall(api, existing_firewall_group_id, plan.admin_ip)
    key_id = existing_key_id
    if key_id is None:
        response = api.request("POST", "/ssh-keys", {
            "name": "crucible-" + plan.fingerprint[7:19].replace("/", "-").replace("+", "-"),
            "ssh_key": plan.public_key,
        })
        key_id = _required_id(response, "ssh_key")
        print(f"Registered SSH key ID: {key_id}")
    if existing_firewall_group_id is not None:
        group_id = existing_firewall_group_id
        print(f"Reusing verified firewall group ID: {group_id}")
    else:
        response = api.request("POST", "/firewalls", {"description": f"crucible SSH {plan.admin_ip}/32"})
        group_id = _required_id(response, "firewall_group")
        print(f"Created firewall group ID: {group_id}")
        api.request("POST", f"/firewalls/{group_id}/rules", {
            "ip_type": "v4", "protocol": "tcp", "port": "22", "subnet": plan.admin_ip,
            "subnet_size": 32, "source": "", "notes": "CRUCIBLE admin SSH only",
        })
    _verify_firewall(api, group_id, plan.admin_ip)
    label = "crucible-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + os.urandom(3).hex()
    response = api.request("POST", "/instances", {
        "region": plan.region, "plan": plan.plan_id, "os_id": plan.os_id,
        "label": label, "hostname": label, "sshkey_id": [key_id],
        "firewall_group_id": group_id, "enable_ipv6": False,
        "backups": "disabled", "ddos_protection": False, "activation_email": False,
    })
    instance_id = _required_id(response, "instance")
    created_at = datetime.now(timezone.utc)
    destroy_by = created_at + timedelta(hours=plan.hours)
    print(f"Created VM ID: {instance_id}; destroy by {destroy_by.isoformat()} UTC")
    state = {
        "instance_id": instance_id, "firewall_group_id": group_id, "ssh_key_id": key_id,
        "region": plan.region, "plan": plan.plan_id, "hourly_usd": str(plan.hourly),
        "planned_hours": plan.hours, "estimated_compute_usd": str(plan.estimated),
        "created_at_utc": created_at.isoformat(), "destroy_by_utc": destroy_by.isoformat(),
    }
    try:
        _write_state(state, state_path)
    except OSError:
        raise ProvisionError(f"VM {instance_id} exists, but its local recovery record could not be saved") from None
    print(f"Local recovery record: {state_path}")

    deadline = time.monotonic() + poll_seconds
    while True:
        instance = api.request("GET", f"/instances/{instance_id}").get("instance")
        if not isinstance(instance, dict):
            raise ProvisionError(f"VM {instance_id} exists, but its status response is malformed")
        attached_group = instance.get("firewall_group_id")
        if attached_group not in {None, "", group_id}:
            raise ProvisionError(f"VM {instance_id} exists, but its firewall attachment is unverified")
        status = str(instance.get("status", "unknown"))
        server = str(instance.get("server_status", "unknown"))
        power = str(instance.get("power_status", "unknown"))
        ip = instance.get("main_ip")
        if (attached_group == group_id and status == "active" and server == "ok" and
                power == "running" and _valid_public_ip(ip)):
            print(f"VM ready: ID {instance_id}, IPv4 {ip}, status {status}/{server}/{power}")
            print(f"Catalog price: ${plan.hourly}/hour; conservative estimate ${plan.estimated} over {plan.hours} hours")
            return {"id": instance_id, "ip": ip, "firewall_group_id": group_id, "ssh_key_id": key_id}
        if time.monotonic() >= deadline:
            raise ProvisionError(f"VM {instance_id} was created but readiness or firewall attachment is unverified; inspect it before retrying")
        time.sleep(10)


def list_options(api: VultrManagement, region: str | None) -> None:
    regions = api.list_all("/regions", "regions")
    print("Regions:")
    for item in regions:
        print(f"  {item.get('id')}: {item.get('city')}, {item.get('country')}")
    available: set[str] | None = None
    if region is not None:
        if not re.fullmatch(r"[a-z0-9]{2,12}", region):
            raise ProvisionError("Invalid region ID")
        if region not in {item.get("id") for item in regions}:
            raise ProvisionError("Selected region is absent from the live Vultr catalog")
        values = api.request("GET", f"/regions/{region}/availability").get("available_plans")
        if not isinstance(values, list):
            raise ProvisionError("Vultr returned no regional plan availability")
        available = set(values)
    all_plans = api.list_all("/plans", "plans")
    print("Small Cloud Compute plans (live catalog prices):")
    for item in all_plans:
        plan_id = item.get("id", "")
        if plan_id in {"vc2-1c-2gb", "vc2-2c-2gb", "vc2-2c-4gb", "vhp-2c-4gb-amd"}:
            suffix = " available" if available is not None and plan_id in available else " unavailable" if available is not None else ""
            print(f"  {plan_id}: {item.get('vcpu_count')} vCPU, {item.get('ram')} MB, "
                  f"${item.get('hourly_cost')}/hour, ${item.get('monthly_cost')}/month{suffix}")
    vx1: list[tuple[Decimal, dict[str, Any]]] = []
    for item in all_plans:
        if not str(item.get("id", "")).startswith("vx1-") or (
                available is not None and item.get("id") not in available):
            continue
        try:
            price = _money(item.get("hourly_cost"), "live VX1 hourly price")
        except ProvisionError:
            continue
        vx1.append((price, item))
    vx1.sort(key=lambda pair: pair[0])
    print("VX1 plans with nested virtualization (first eight by hourly price):")
    if not vx1:
        print("  none available in this region")
    for _, item in vx1[:8]:
        print(f"  {item.get('id')}: {item.get('vcpu_count')} vCPU, {item.get('ram')} MB, "
              f"${item.get('hourly_cost')}/hour, ${item.get('monthly_cost')}/month")
    systems = api.list_all("/os", "os")
    ubuntu = next((item for item in systems if item.get("name") == UBUNTU_NAME), None)
    print(f"OS: {UBUNTU_NAME} (ID {ubuntu.get('id') if ubuntu else 'unavailable'})")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Guarded Vultr VM provisioning for CRUCIBLE")
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("list", help="Read-only live regions and prices")
    listing.add_argument("--region", help="Include plan availability in a region")
    provision = commands.add_parser("provision", help="Preview by default; --apply creates one VM")
    provision.add_argument("--region", required=True)
    provision.add_argument("--plan", required=True)
    provision.add_argument("--admin-ip", required=True, help="Explicit public IPv4 /32 CIDR for SSH")
    provision.add_argument("--ssh-public-key", required=True, type=Path)
    provision.add_argument("--max-hours", type=int)
    provision.add_argument("--max-total-spend", help="Maximum estimated compute cost in USD")
    provision.add_argument("--state-file", type=Path, default=STATE_FILE,
                           help="Private local recovery record; use separate paths for control and sandbox VMs")
    provision.add_argument("--peer-state", type=Path,
                           help="Existing first-VM state; enforce --max-total-spend against combined compute estimate")
    provision.add_argument("--existing-firewall-group-id",
                           help="Reuse a previously created /32-only group after a partial provisioning attempt")
    mode = provision.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Preview only (the default)")
    mode.add_argument("--apply", action="store_true", help="Create SSH key, firewall, and VM")
    provision.add_argument("--confirm-hourly-billing", action="store_true",
                           help="Required with --apply; VM billing continues until destruction")
    args = parser.parse_args(argv)
    try:
        if args.command == "provision" and args.apply and not args.confirm_hourly_billing:
            raise ProvisionError("--apply also requires --confirm-hourly-billing")
        api = VultrManagement(load_management_key())
        if args.command == "list":
            list_options(api, args.region)
            return 0
        plan = make_plan(api, region=args.region, plan_id=args.plan,
                         admin_source=args.admin_ip, key_path=args.ssh_public_key,
                         max_hours=args.max_hours, max_total_spend=args.max_total_spend)
        if args.peer_state:
            if not args.max_total_spend:
                raise ProvisionError("--peer-state requires --max-total-spend as the aggregate cap")
            guard_pair_estimate(plan, args.peer_state, args.max_total_spend)
        existing = _existing_key(api, plan)
        if args.existing_firewall_group_id:
            _verify_reusable_firewall(api, args.existing_firewall_group_id, plan.admin_ip)
        print_plan(plan, existing)
        if not args.apply:
            print("Dry run: no Vultr resources were created.")
            return 0
        state_path = args.state_file.resolve()
        if ROOT / "secrets" not in state_path.parents:
            raise ProvisionError("Provision state file must be under the ignored secrets directory")
        apply_plan(api, plan, existing, state_path=state_path,
                   existing_firewall_group_id=args.existing_firewall_group_id)
        return 0
    except ProvisionError as exc:
        print(f"Provisioning stopped: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
