"""Read-only, disclosure-safe attestation of the current Vultr deployment.

The management credential is used only for GET requests.  Successful output
contains bounded status fields; neither API responses nor credentials are
printed.  This checks account ownership of the local inference credential,
not whether a model was trained by this project or whether a VM is reachable.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hmac
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

from deploy.provision_vm import KEY_FILE, ROOT, VultrManagement, load_management_key


_INSTANCE_ID = re.compile(r"[a-zA-Z0-9-]{8,80}\Z")
_REGION = re.compile(r"[a-z0-9]{2,12}\Z")
_INFERENCE_NAMES = {"VULTR_INFERENCE_API_KEY", "VULTR_SERVERLESS_INFERENCE_API_KEY"}


class AttestationError(RuntimeError):
    """A private verification step failed; no untrusted detail is displayed."""


def _read_private_json(path: Path) -> dict[str, Any]:
    if (path.is_symlink() or not path.is_file() or path.stat().st_uid != os.geteuid()
            or path.stat().st_mode & 0o077 or not 0 < path.stat().st_size <= 16_384):
        raise AttestationError
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise AttestationError from None
    if not isinstance(value, dict):
        raise AttestationError
    return value


def _read_inference_key(path: Path) -> str:
    if (path.is_symlink() or not path.is_file() or path.stat().st_uid != os.geteuid()
            or path.stat().st_mode & 0o077 or not 0 < path.stat().st_size <= 16_384):
        raise AttestationError
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        raise AttestationError from None
    values: list[str] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise AttestationError
        name, value = line.split("=", 1)
        if name.strip() not in _INFERENCE_NAMES:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if not value or any(char in value for char in "\r\n\x00"):
            raise AttestationError
        values.append(value)
    if not values or any(not hmac.compare_digest(values[0], value) for value in values[1:]):
        raise AttestationError
    return values[0]


def _instance_state(path: Path) -> tuple[str, str]:
    state = _read_private_json(path)
    instance_id, region = state.get("instance_id"), state.get("region")
    if (not isinstance(instance_id, str) or not _INSTANCE_ID.fullmatch(instance_id)
            or not isinstance(region, str) or not _REGION.fullmatch(region)):
        raise AttestationError
    return instance_id, region


def _verified_instance(api: VultrManagement, instance_id: str, region: str,
                       vpc_id: str) -> dict[str, str]:
    response = api.request("GET", f"/instances/{instance_id}")
    instance = response.get("instance")
    if not isinstance(instance, dict) or instance.get("id") != instance_id or instance.get("region") != region:
        raise AttestationError
    vpcs = instance.get("vpcs")
    if (not isinstance(vpcs, list) or not any(
            isinstance(vpc, dict) and vpc.get("id") == vpc_id for vpc in vpcs)):
        raise AttestationError
    statuses = {name: instance.get(name) for name in ("status", "server_status", "power_status")}
    if statuses != {"status": "active", "server_status": "ok", "power_status": "running"}:
        raise AttestationError
    return statuses


def attest(api: VultrManagement, *, root: Path = ROOT,
           checked_at: datetime | None = None) -> dict[str, Any]:
    """Verify live account resources and return only the public proof schema."""
    root = root.resolve()
    secrets = root / "secrets"
    if secrets.is_symlink() or not secrets.is_dir():
        raise AttestationError
    control_id, control_region = _instance_state(secrets / "elicitation_control_vm.json")
    sandbox_id, sandbox_region = _instance_state(secrets / "elicitation_sandbox_vm.json")
    if control_id == sandbox_id or control_region != "sjc" or sandbox_region != "sjc":
        raise AttestationError
    network = _read_private_json(secrets / "elicitation_vpc_pair.json")
    vpc_id = network.get("vpc_id")
    kind = network.get("kind")
    if (network.get("control_id") != control_id or network.get("sandbox_id") != sandbox_id
            or network.get("region") != "sjc" or kind not in {"vpc", "vpc2"}
            or network.get("attached_verified") is not True
            or not isinstance(vpc_id, str) or not _INSTANCE_ID.fullmatch(vpc_id)):
        raise AttestationError
    control = _verified_instance(api, control_id, "sjc", vpc_id)
    sandbox = _verified_instance(api, sandbox_id, "sjc", vpc_id)
    path, field = ("vpc2", "vpc2") if kind == "vpc2" else ("vpcs", "vpc")
    vpc = api.request("GET", f"/{path}/{vpc_id}").get(field)
    if not isinstance(vpc, dict) or vpc.get("id") != vpc_id or vpc.get("region") != "sjc":
        raise AttestationError

    local_key = _read_inference_key(root / ".env.local")
    subscriptions = api.list_all("/inference", "subscriptions")
    active = [item for item in subscriptions if item.get("status") == "active"]
    matches = [item for item in active if isinstance(item.get("api_key"), str)
               and hmac.compare_digest(local_key, item["api_key"])]
    if len(matches) != 1:
        raise AttestationError
    timestamp = checked_at or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        raise AttestationError
    return {
        "schema_version": 1,
        "checked_at_utc": timestamp.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "attested": True,
        "control_vm": control,
        "sandbox_vm": sandbox,
        "region": "sjc",
        "shared_vpc": True,
        "active_inference_subscriptions": len(active),
        "inference_key_matches_account_subscription": True,
    }


def main() -> int:
    try:
        result = attest(VultrManagement(load_management_key(KEY_FILE)))
    except Exception:
        # API errors can include account metadata.  One fixed error shape
        # keeps all failure paths from disclosing credentials or instance IDs.
        result = {"schema_version": 1,
                  "checked_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
                  "attested": False, "reason": "verification_failed"}
        print(json.dumps(result, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
