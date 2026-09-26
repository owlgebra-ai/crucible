from __future__ import annotations

import base64
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from deploy import provision_vm as vm


class FakeAPI:
    def __init__(self, *, hourly: float = 0.027, firewall_correct: bool = True):
        self.hourly = hourly
        self.firewall_correct = firewall_correct
        self.calls: list[tuple[str, str, dict | None]] = []

    def list_all(self, path: str, field: str):
        self.calls.append(("GET", path, None))
        return {
            "/regions": [{"id": "lax", "city": "Los Angeles", "country": "US"}],
            "/plans": [{"id": "vc2-2c-4gb", "vcpu_count": 2, "ram": 4096, "disk": 80,
                        "hourly_cost": self.hourly, "monthly_cost": 20}],
            "/os": [{"id": 2284, "name": vm.UBUNTU_NAME}],
            "/ssh-keys": [],
            "/instances": [],
        }[path]

    def request(self, method: str, path: str, payload: dict | None = None):
        self.calls.append((method, path, payload))
        if method == "GET" and path == "/regions/lax/availability":
            return {"available_plans": ["vc2-2c-4gb"]}
        if method == "POST" and path == "/ssh-keys":
            return {"ssh_key": {"id": "key-1234"}}
        if method == "POST" and path == "/firewalls":
            return {"firewall_group": {"id": "group-1234"}}
        if method == "POST" and path == "/firewalls/group-1234/rules":
            return {"firewall_rule": {"id": 1}}
        if method == "GET" and path == "/firewalls/group-1234/rules":
            return {"firewall_rules": [{
                "ip_type": "v4", "protocol": "tcp", "port": "22",
                "subnet": "8.8.8.8" if self.firewall_correct else "0.0.0.0",
                "subnet_size": 32 if self.firewall_correct else 0, "source": "",
            }]}
        if method == "GET" and path == "/firewalls/group-1234":
            return {"firewall_group": {"id": "group-1234",
                    "description": "crucible SSH 8.8.8.8/32"}}
        if method == "POST" and path == "/instances":
            return {"instance": {"id": "instance-1234"}}
        if method == "GET" and path == "/instances/instance-1234":
            return {"instance": {
                "id": "instance-1234", "status": "active", "server_status": "ok",
                "power_status": "running", "main_ip": "8.8.4.4",
                "firewall_group_id": "group-1234",
            }}
        raise AssertionError((method, path))


class ProvisionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "admin.pub"
        public_blob = base64.b64encode(b"test-ed25519-public-key-material" * 2).decode("ascii")
        self.path.write_text("ssh-ed25519 " + public_blob + " test@example\n", encoding="ascii")

    def plan(self, api: FakeAPI, **overrides):
        args = dict(region="lax", plan_id="vc2-2c-4gb", admin_source="8.8.8.8/32",
                    key_path=self.path, max_hours=24, max_total_spend="1.00")
        args.update(overrides)
        return vm.make_plan(api, **args)

    def test_dry_run_planning_only_reads_catalog(self):
        api = FakeAPI()
        plan = self.plan(api)
        existing = vm._existing_key(api, plan)
        self.assertIsNone(existing)
        self.assertEqual(plan.os_id, 2284)
        self.assertEqual(str(plan.estimated), "0.72")
        self.assertTrue(all(method == "GET" for method, _, _ in api.calls))

    def test_rejects_broad_or_private_admin_source(self):
        for source in ("8.8.8.0/24", "10.0.0.1/32", "::1/128", "0.0.0.0/0"):
            with self.subTest(source=source), self.assertRaises(vm.ProvisionError):
                self.plan(FakeAPI(), admin_source=source)

    def test_budget_guard_requires_first_hour_and_enforces_total(self):
        with self.assertRaises(vm.ProvisionError):
            self.plan(FakeAPI(), max_hours=None, max_total_spend="0.01")
        with self.assertRaises(vm.ProvisionError):
            self.plan(FakeAPI(), max_hours=48, max_total_spend="1.00")
        plan = self.plan(FakeAPI(), max_hours=None, max_total_spend="0.10")
        self.assertEqual(plan.hours, 3)

    def test_two_vm_aggregate_estimate_is_checked_before_apply(self):
        root = Path(self.temp.name).resolve()
        secrets = root / "secrets"
        secrets.mkdir(mode=0o700)
        peer = secrets / "control.json"
        peer.write_text(json.dumps({"instance_id": "instance-control", "region": "lax",
                                    "estimated_compute_usd": "0.72"}))
        peer.chmod(0o600)
        plan = self.plan(FakeAPI())
        with patch.object(vm, "ROOT", root):
            self.assertEqual(str(vm.guard_pair_estimate(plan, peer, "1.44")), "1.44")
            with self.assertRaisesRegex(vm.ProvisionError, "aggregate cap"):
                vm.guard_pair_estimate(plan, peer, "1.43")

    def test_management_client_supports_narrow_delete_request(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *_args): return False
            def read(self, *_args): return b""
        class Opener:
            def __init__(self): self.method = None
            def open(self, request, timeout):
                self.method = request.get_method()
                return Response()
        client = vm.VultrManagement("test-key")
        opener = Opener()
        client._opener = opener
        self.assertEqual(client.request("DELETE", "/firewalls/group-1234/rules/1"), {})
        self.assertEqual(opener.method, "DELETE")

    def test_apply_attaches_verified_firewall_and_key_before_vm_create(self):
        api = FakeAPI()
        plan = self.plan(api)
        state_path = Path(self.temp.name) / "state.json"
        result = vm.apply_plan(api, plan, None, state_path=state_path, poll_seconds=1)
        self.assertEqual(result["ip"], "8.8.4.4")
        posts = [(path, body) for method, path, body in api.calls if method == "POST"]
        self.assertEqual([path for path, _ in posts],
                         ["/ssh-keys", "/firewalls", "/firewalls/group-1234/rules", "/instances"])
        self.assertEqual(posts[2][1]["subnet_size"], 32)
        self.assertEqual(posts[2][1]["subnet"], "8.8.8.8")
        instance = posts[3][1]
        self.assertEqual(instance["sshkey_id"], ["key-1234"])
        self.assertEqual(instance["firewall_group_id"], "group-1234")
        self.assertFalse(instance["enable_ipv6"])
        self.assertEqual(instance["backups"], "disabled")
        state = json.loads(state_path.read_text())
        self.assertEqual(state["instance_id"], "instance-1234")
        self.assertNotIn("api_key", state)

    def test_bad_firewall_rule_stops_before_instance_create(self):
        api = FakeAPI(firewall_correct=False)
        with self.assertRaises(vm.ProvisionError):
            vm.apply_plan(api, self.plan(api), None,
                          state_path=Path(self.temp.name) / "state.json", poll_seconds=1)
        self.assertNotIn(("POST", "/instances"), [(method, path) for method, path, _ in api.calls])

    def test_vultr_normalized_source_cidr_is_verified(self):
        class ObservedRuleApi:
            def request(self, method, path):
                return {"firewall_rules": [{"id": 1, "type": "v4", "ip_type": "v4",
                    "action": "accept", "protocol": "tcp", "port": "22",
                    "subnet": "12.94.170.82", "subnet_size": 32,
                    "source": "12.94.170.82/32", "direction": "in"}]}
        vm._verify_firewall(ObservedRuleApi(), "group-1234", "12.94.170.82")

    def test_reuse_requires_unattached_matching_group_and_skips_group_creation(self):
        api = FakeAPI()
        state = Path(self.temp.name) / "reuse.json"
        vm.apply_plan(api, self.plan(api), "key-1234", state_path=state, poll_seconds=1,
                      existing_firewall_group_id="group-1234")
        posts = [path for method, path, _ in api.calls if method == "POST"]
        self.assertEqual(posts, ["/instances"])
        class AttachedApi(FakeAPI):
            def list_all(self, path, field):
                if path == "/instances":
                    return [{"id": "another-vm", "firewall_group_id": "group-1234"}]
                return super().list_all(path, field)
        attached = AttachedApi()
        with self.assertRaisesRegex(vm.ProvisionError, "already attached"):
            vm.apply_plan(attached, self.plan(attached), "key-1234",
                          state_path=Path(self.temp.name) / "other.json", poll_seconds=1,
                          existing_firewall_group_id="group-1234")
        self.assertTrue(all(method == "GET" for method, _, _ in attached.calls))

    def test_existing_state_stops_before_any_mutation(self):
        api = FakeAPI()
        state_path = Path(self.temp.name) / "state.json"
        state_path.write_text("{}")
        with self.assertRaises(vm.ProvisionError):
            vm.apply_plan(api, self.plan(api), None, state_path=state_path)
        self.assertTrue(all(method == "GET" for method, _, _ in api.calls))

    def test_management_api_rejects_cross_origin_redirect_with_bearer(self):
        received: list[str | None] = []

        class Sink(BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *_args):
                pass

        with ThreadingHTTPServer(("127.0.0.1", 0), Sink) as sink:
            sink_thread = threading.Thread(target=sink.serve_forever, daemon=True)
            sink_thread.start()
            destination = f"http://127.0.0.1:{sink.server_port}/sink"

            class Source(BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(302)
                    self.send_header("Location", destination)
                    self.end_headers()

                def log_message(self, *_args):
                    pass

            with ThreadingHTTPServer(("127.0.0.1", 0), Source) as source:
                source_thread = threading.Thread(target=source.serve_forever, daemon=True)
                source_thread.start()
                with patch.object(vm, "API_BASE", f"http://127.0.0.1:{source.server_port}"):
                    with self.assertRaises(vm.ProvisionError) as caught:
                        vm.VultrManagement("test-secret").request("GET", "/regions")
                self.assertNotIn("test-secret", str(caught.exception))
                source.shutdown()
                source_thread.join(timeout=2)
            sink.shutdown()
            sink_thread.join(timeout=2)
        self.assertEqual(received, [])


if __name__ == "__main__":
    unittest.main()
