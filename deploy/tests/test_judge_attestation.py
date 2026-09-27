"""The judge attestation must be live, read-only, and disclosure-safe."""

from __future__ import annotations

from contextlib import redirect_stdout
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from deploy import judge_attestation as judge


CONTROL = "11111111-1111-4111-8111-111111111111"
SANDBOX = "22222222-2222-4222-8222-222222222222"
VPC = "33333333-3333-4333-8333-333333333333"
KEY = "inference-key-must-never-be-printed"


class FakeAPI:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.instances = {
            CONTROL: {"id": CONTROL, "region": "sjc", "status": "active",
                      "server_status": "ok", "power_status": "running",
                      "vpcs": [{"id": VPC, "subnet": "10.0.0.0/24"}],
                      "main_ip": "203.0.113.10"},
            SANDBOX: {"id": SANDBOX, "region": "sjc", "status": "active",
                      "server_status": "ok", "power_status": "running",
                      "vpcs": [{"id": VPC, "subnet": "10.0.0.0/24"}],
                      "main_ip": "203.0.113.11"},
        }
        self.subscriptions = [{"id": "subscription-id", "status": "active",
                               "api_key": KEY, "label": "private-label"}]

    def request(self, method: str, path: str) -> dict:
        self.calls.append((method, path))
        if method != "GET":
            raise AssertionError("attestation tried to mutate the account")
        if path.startswith("/instances/"):
            return {"instance": self.instances[path.rsplit("/", 1)[1]]}
        if path == f"/vpc2/{VPC}":
            return {"vpc2": {"id": VPC, "region": "sjc"}}
        if path == f"/vpcs/{VPC}":
            return {"vpc": {"id": VPC, "region": "sjc"}}
        raise AssertionError(path)

    def list_all(self, path: str, field: str) -> list[dict]:
        self.calls.append(("GET", path))
        if (path, field) != ("/inference", "subscriptions"):
            raise AssertionError((path, field))
        return self.subscriptions


class JudgeAttestationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        secrets = self.root / "secrets"
        secrets.mkdir()
        for name, instance_id in (("elicitation_control_vm.json", CONTROL),
                                  ("elicitation_sandbox_vm.json", SANDBOX)):
            path = secrets / name
            path.write_text(json.dumps({"instance_id": instance_id, "region": "sjc"}))
            path.chmod(0o600)
        pair = secrets / "elicitation_vpc_pair.json"
        pair.write_text(json.dumps({"control_id": CONTROL, "sandbox_id": SANDBOX,
                                    "region": "sjc", "kind": "vpc2", "vpc_id": VPC,
                                    "attached_verified": True}))
        pair.chmod(0o600)
        self.env = self.root / ".env.local"
        self.env.write_text(f"VULTR_INFERENCE_API_KEY={KEY}\n")
        self.env.chmod(0o600)
        self.api = FakeAPI()

    def attest(self) -> dict:
        return judge.attest(self.api, root=self.root,
                            checked_at=datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc))

    def test_success_is_closed_schema_and_read_only(self) -> None:
        result = self.attest()
        self.assertEqual(result, {
            "schema_version": 1, "checked_at_utc": "2026-09-27T12:00:00Z",
            "attested": True,
            "control_vm": {"status": "active", "server_status": "ok", "power_status": "running"},
            "sandbox_vm": {"status": "active", "server_status": "ok", "power_status": "running"},
            "region": "sjc", "shared_vpc": True, "active_inference_subscriptions": 1,
            "inference_key_matches_account_subscription": True,
        })
        self.assertTrue(all(method == "GET" for method, _ in self.api.calls))
        rendered = json.dumps(result)
        for secret in (KEY, CONTROL, SANDBOX, VPC, "203.0.113", "private-label", "subscription-id"):
            self.assertNotIn(secret, rendered)

    def test_key_or_subscription_mismatch_fails_closed(self) -> None:
        self.env.write_text("VULTR_INFERENCE_API_KEY=another-private-key\n")
        with self.assertRaises(judge.AttestationError):
            self.attest()
        self.env.write_text(f"VULTR_INFERENCE_API_KEY={KEY}\n")
        self.api.subscriptions[0]["status"] = "pending"
        with self.assertRaises(judge.AttestationError):
            self.attest()

    def test_inactive_vm_or_missing_vpc_fails_closed(self) -> None:
        self.api.instances[SANDBOX]["power_status"] = "stopped"
        with self.assertRaises(judge.AttestationError):
            self.attest()
        self.api.instances[SANDBOX]["power_status"] = "running"
        self.api.instances[SANDBOX]["vpcs"] = []
        with self.assertRaises(judge.AttestationError):
            self.attest()

    def test_legacy_vpc_is_verified_from_live_instances(self) -> None:
        pair = self.root / "secrets" / "elicitation_vpc_pair.json"
        record = json.loads(pair.read_text())
        record["kind"] = "vpc"
        pair.write_text(json.dumps(record))
        self.assertTrue(self.attest()["shared_vpc"])
        self.assertIn(("GET", f"/vpcs/{VPC}"), self.api.calls)

    def test_unsafe_credential_file_is_rejected(self) -> None:
        self.env.chmod(0o644)
        with self.assertRaises(judge.AttestationError):
            self.attest()

    def test_main_error_never_discloses_exception_text(self) -> None:
        output = io.StringIO()
        with mock.patch.object(judge, "load_management_key", return_value="redacted"), \
             mock.patch.object(judge, "VultrManagement", return_value=self.api), \
             mock.patch.object(judge, "attest", side_effect=RuntimeError(f"failure {KEY}")), \
             redirect_stdout(output):
            self.assertEqual(judge.main(), 2)
        result = json.loads(output.getvalue())
        self.assertEqual(result["reason"], "verification_failed")
        self.assertNotIn(KEY, output.getvalue())


if __name__ == "__main__":
    unittest.main()
