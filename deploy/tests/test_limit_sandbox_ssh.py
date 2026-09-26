"""VM2 public admin SSH is closed only after private-path proof."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from deploy import limit_sandbox_ssh, vpc_pair
from deploy.provision_vm import ProvisionError


ADMIN = "8.8.8.8"
PRIVATE = "10.22.0.7"
INSTANCE = "22222222-2222-4222-8222-222222222222"
GROUP = "44444444-4444-4444-8444-444444444444"


def rule(ip, rule_id):
    return {"id": rule_id, "ip_type": "v4", "protocol": "tcp", "port": "22",
            "subnet": ip, "subnet_size": 32, "source": ip + "/32"}


class FakeApi:
    def __init__(self):
        self.calls = []
        self.rules = [rule(ADMIN, 1)]

    def request(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        if method == "GET" and path == f"/instances/{INSTANCE}":
            return {"instance": {"id": INSTANCE, "firewall_group_id": GROUP}}
        if method == "GET" and path == f"/firewalls/{GROUP}/rules":
            return {"firewall_rules": list(self.rules)}
        if method == "POST" and path == f"/firewalls/{GROUP}/rules":
            self.rules.append(rule(payload["subnet"], 2))
            return {"firewall_rule": {"id": 2}}
        if method == "DELETE" and path == f"/firewalls/{GROUP}/rules/1":
            self.rules = [item for item in self.rules if item["id"] != 1]
            return {}
        raise AssertionError((method, path, payload))


class LimitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name).resolve()
        secrets = root / "secrets"
        secrets.mkdir(mode=0o700)
        self.state = secrets / "sandbox.json"
        self.state.write_text(json.dumps({"instance_id": INSTANCE, "firewall_group_id": GROUP}))
        self.state.chmod(0o600)
        self.patch = mock.patch.object(vpc_pair, "ROOT", root)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.temp.cleanup()

    def test_dry_run_is_read_only(self):
        api = FakeApi()
        result = limit_sandbox_ssh.limit(api, sandbox_state=self.state,
            admin_source=ADMIN + "/32", control_private_ip=PRIVATE)
        self.assertTrue(result["dry_run"])
        self.assertTrue(all(method == "GET" for method, _, _ in api.calls))

    def test_public_rule_removed_only_after_verified_private_path(self):
        api = FakeApi()
        with self.assertRaisesRegex(ProvisionError, "Prove SSH"):
            limit_sandbox_ssh.limit(api, sandbox_state=self.state,
                admin_source=ADMIN + "/32", control_private_ip=PRIVATE,
                apply=True, close_public_admin=True)
        self.assertTrue(all(method == "GET" for method, _, _ in api.calls))
        result = limit_sandbox_ssh.limit(api, sandbox_state=self.state,
            admin_source=ADMIN + "/32", control_private_ip=PRIVATE,
            apply=True, close_public_admin=True, private_path_verified=True)
        self.assertFalse(result["public_admin_rule"])
        self.assertEqual(api.rules, [rule(PRIVATE, 2)])


if __name__ == "__main__":
    unittest.main()
