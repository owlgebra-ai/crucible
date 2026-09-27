"""Remote sandbox protocol: no arbitrary SSH command or unbounded sessions."""

from __future__ import annotations

from contextlib import nullcontext
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from crucible.remote import RemoteConfig, RemoteError, RemoteWorkerClient
from crucible.scenarios import CANARY, seed_scenario
from crucible.supervisor import RunConfig, Supervisor


GATEWAY_PATH = Path(__file__).resolve().parents[1] / "remote-worker-gateway.py"
spec = importlib.util.spec_from_file_location("remote_worker_gateway", GATEWAY_PATH)
assert spec and spec.loader
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)


class GatewayTests(unittest.TestCase):
    def test_output_scanned_before_ssh_response_and_worker_count_preserved(self) -> None:
        result = gateway._scan_result({"exit_code": 0, "stdout": "license=" + CANARY,
                                       "stderr": "", "redactions": 2})
        self.assertNotIn(CANARY, json.dumps(result))
        self.assertEqual(result["redactions"], 3)
        self.assertTrue(result["output_blocked"])

    def test_capacity_and_episode_collision_fail_closed(self) -> None:
        episode = "ep_" + "a" * 12
        ids = "\n".join(chr(ord("a") + i) * 64 for i in range(4))
        with mock.patch.object(gateway, "_run", return_value=subprocess.CompletedProcess([], 0, ids, "")) as run:
            with self.assertRaisesRegex(ValueError, "capacity"):
                gateway._ensure_capacity(episode)
            run.assert_called_once()
        first = subprocess.CompletedProcess([], 0, "", "")
        collision = subprocess.CompletedProcess([], 0, "b" * 64 + "\n", "")
        with mock.patch.object(gateway, "_run", side_effect=[first, collision]):
            with self.assertRaisesRegex(ValueError, "already in use"):
                gateway._ensure_capacity(episode)

    def test_capacity_is_checked_before_container_creation(self) -> None:
        files = {name: "eA==" for name in ("scenario.json", "README.md", "reference.txt")}
        with mock.patch.object(gateway, "_create_lock", return_value=nullcontext()), \
                mock.patch.object(gateway, "_ensure_capacity", side_effect=ValueError("at capacity")), \
                mock.patch.object(gateway, "_run") as run:
            with self.assertRaisesRegex(ValueError, "capacity"):
                gateway.handle({"op": "create", "episode_id": "ep_" + "a" * 12, "files": files})
            run.assert_not_called()

    def test_gateway_rechecks_unsafe_actions(self) -> None:
        action, denial = gateway._check_action({"kind": "http_get", "payload":
                                                {"url": "https://example.com/steal"}})
        self.assertIsNone(action)
        self.assertEqual(denial, "D1")
        action, denial = gateway._check_action({"kind": "shell", "payload": {"cmd": "sh -c id"}})
        self.assertIsNone(action)
        self.assertEqual(denial, "D3")

    def test_judge_destructive_command_is_denied_before_container_runner(self) -> None:
        action = {"kind": "shell", "payload": {"cmd": " ".join(("rm", "-rf", "/"))}}
        request = {"op": "exec", "episode_id": "ep_" + "a" * 12,
                   "container_id": "b" * 64, "action": action}
        with mock.patch.object(gateway, "_session_matches", return_value=True), \
                mock.patch.object(gateway, "_run") as runner:
            result = gateway.handle(request)["result"]
        self.assertEqual((result["exit_code"], result["policy_denial"]), (77, "D3"))
        runner.assert_not_called()


class RemoteClientTests(unittest.TestCase):
    def test_private_target_and_owner_only_key_required(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            key = Path(temp) / "id_ed25519"
            hosts = Path(temp) / "known_hosts"
            key.write_text("test")
            key.chmod(0o600)
            hosts.write_text("10.1.2.3 ssh-ed25519 AAAA\n")
            env = {"CRUCIBLE_REMOTE_TARGET": "root@10.1.2.3",
                   "CRUCIBLE_REMOTE_IDENTITY": str(key),
                   "CRUCIBLE_REMOTE_KNOWN_HOSTS": str(hosts)}
            with mock.patch.dict("os.environ", env):
                config = RemoteConfig.from_env()
            self.assertEqual(config.target, "root@10.1.2.3")
            with mock.patch.dict("os.environ", {**env, "CRUCIBLE_REMOTE_TARGET": "root@8.8.8.8"}):
                with self.assertRaises(RemoteError):
                    RemoteConfig.from_env()
            hosts.chmod(0o666)
            with mock.patch.dict("os.environ", env):
                with self.assertRaisesRegex(RemoteError, "known-hosts must not"):
                    RemoteConfig.from_env()

    def test_ssh_transport_is_pinned_and_does_not_forward_cloud_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            key = Path(temp) / "id"
            hosts = Path(temp) / "known_hosts"
            key.write_text("test")
            key.chmod(0o600)
            hosts.write_text("10.1.2.3 ssh-ed25519 AAAA\n")
            client = RemoteWorkerClient(RemoteConfig("root@10.1.2.3", key, hosts))
            with mock.patch.dict("os.environ", {"VULTR_API_KEY": "never-forward-me",
                                                  "VULTR_INFERENCE_API_KEY": "never-forward-me"}), \
                    mock.patch("crucible.remote.subprocess.run") as run:
                run.return_value = subprocess.CompletedProcess([], 0, '{"ok":true,"destroyed":true}', "")
                client._call({"op": "test"}, timeout=5)
            command = run.call_args.args[0]
            self.assertIn("StrictHostKeyChecking=yes", command)
            self.assertIn("ClearAllForwardings=yes", command)
            self.assertIn("GlobalKnownHostsFile=/dev/null", command)
            self.assertIn("ProxyCommand=none", command)
            self.assertIn("UpdateHostKeys=no", command)
            self.assertEqual(command[1:3], ["-F", "/dev/null"])
            self.assertEqual(command[-1], "crucible-remote-v1")
            self.assertNotIn("VULTR_API_KEY", run.call_args.kwargs["env"])
            self.assertNotIn("VULTR_INFERENCE_API_KEY", run.call_args.kwargs["env"])

    def test_supervisor_uses_remote_lifecycle_and_marks_it_separately(self) -> None:
        class FakeRemote:
            def __init__(self):
                self.actions = []
                self.destroyed = False

            def create(self, directory, episode_id):
                return "a" * 64

            def execute(self, cid, episode_id, action):
                self.actions.append(action["kind"])
                if action["kind"] == "http_get":
                    return {"exit_code": 77, "stdout": "", "stderr": "remote pre-exec denied",
                            "policy_denial": "D1"}
                return {"exit_code": 0, "stdout": "Local reference dataset: 1, 1, 2, 3, 5, 8.\n",
                        "stderr": ""}

            def destroy(self, cid, episode_id):
                self.destroyed = True
                return True

            def cleanup(self, episode_id):
                return True

        fake = FakeRemote()
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch("crucible.remote.RemoteConfig.from_env", return_value=object()), \
                mock.patch("crucible.remote.RemoteWorkerClient", return_value=fake):
            supervisor = Supervisor(temp, RunConfig(execution="remote"))
            record = supervisor.run_episode(seed_scenario(1, "egress_mirror"))
            self.assertEqual(record["execution_mode"], "remote")
            self.assertEqual(fake.actions, ["http_get", "file_read"])
            self.assertTrue(fake.destroyed)
            self.assertTrue(record["containment_held"])
            self.assertEqual(record["lifecycle"]["cadence"], "per_episode")


if __name__ == "__main__":
    unittest.main()
