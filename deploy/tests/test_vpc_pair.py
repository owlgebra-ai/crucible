"""Guarded VPC pairing uses the selected VM states and verifies both nodes."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from deploy import vpc_pair
from deploy.provision_vm import ProvisionError


CONTROL = "11111111-1111-4111-8111-111111111111"
SANDBOX = "22222222-2222-4222-8222-222222222222"
VPC = "33333333-3333-4333-8333-333333333333"


class FakeApi:
    def __init__(self):
        self.calls = []
        self.nodes = []

    def request(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        if path.startswith("/instances/") and method == "GET":
            return {"instance": {"id": path.rsplit("/", 1)[1], "region": "lax"}}
        if method == "POST" and path == "/vpc2":
            return {"vpc2": {"id": VPC}}
        if method == "GET" and path == f"/vpc2/{VPC}/nodes":
            return {"nodes": [{"id": item} for item in self.nodes]}
        if method == "POST" and path == f"/vpc2/{VPC}/nodes/attach":
            self.nodes.extend(payload["nodes"])
            return {}
        if method == "GET" and path == f"/vpc2/{VPC}":
            return {"vpc2": {"id": VPC, "region": "lax"}}
        raise AssertionError((method, path, payload))


class FakeLegacyApi(FakeApi):
    def request(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        if path.startswith("/instances/") and path.endswith("/vpcs") and method == "GET":
            instance_id = path.split("/")[2]
            return {"vpcs": [{"id": VPC}] if instance_id in self.nodes else []}
        if path.startswith("/instances/") and path.endswith("/vpcs/attach") and method == "POST":
            self.nodes.append(path.split("/")[2])
            return {}
        if method == "POST" and path == "/vpcs":
            return {"vpc": {"id": VPC}}
        if method == "GET" and path == f"/vpcs/{VPC}":
            return {"vpc": {"id": VPC, "region": "lax"}}
        self.calls.pop()
        return super().request(method, path, payload)


class VpcPairTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.secrets = self.root / "secrets"
        self.secrets.mkdir(mode=0o700)
        self.control = self.secrets / "control.json"
        self.sandbox = self.secrets / "sandbox.json"
        self.state = self.secrets / "vpc.json"
        for path, instance_id in ((self.control, CONTROL), (self.sandbox, SANDBOX)):
            path.write_text(json.dumps({"instance_id": instance_id, "region": "lax"}))
            path.chmod(0o600)
        self.patch = mock.patch.object(vpc_pair, "ROOT", self.root)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.temp.cleanup()

    def test_default_dry_run_only_reads(self):
        api = FakeApi()
        result = vpc_pair.attach(api, control_state=self.control, sandbox_state=self.sandbox,
                                 state_file=self.state)
        self.assertTrue(result["dry_run"])
        self.assertFalse(self.state.exists())
        self.assertTrue(all(method == "GET" for method, _, _ in api.calls))

    def test_apply_creates_and_verifies_private_network(self):
        api = FakeApi()
        result = vpc_pair.attach(api, control_state=self.control, sandbox_state=self.sandbox,
                                 state_file=self.state, apply=True)
        self.assertTrue(result["attached_verified"])
        self.assertEqual(set(api.nodes), {CONTROL, SANDBOX})
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(self.state.read_text())["vpc_id"], VPC)

    def test_cross_region_pair_is_rejected_before_writes(self):
        self.sandbox.write_text(json.dumps({"instance_id": SANDBOX, "region": "sjc"}))
        api = FakeApi()
        with self.assertRaisesRegex(ProvisionError, "one region"):
            vpc_pair.attach(api, control_state=self.control, sandbox_state=self.sandbox,
                            state_file=self.state, apply=True)
        self.assertEqual(api.calls, [])

    def test_legacy_vpc_create_and_per_instance_attach(self):
        api = FakeLegacyApi()
        result = vpc_pair.attach(api, control_state=self.control, sandbox_state=self.sandbox,
                                 state_file=self.state, apply=True, kind="vpc")
        self.assertTrue(result["attached_verified"])
        self.assertEqual(result["kind"], "vpc")
        self.assertEqual(set(api.nodes), {CONTROL, SANDBOX})
        posts = [path for method, path, _ in api.calls if method == "POST"]
        self.assertEqual(posts, ["/vpcs", f"/instances/{CONTROL}/vpcs/attach",
                                 f"/instances/{SANDBOX}/vpcs/attach"])


if __name__ == "__main__":
    unittest.main()
