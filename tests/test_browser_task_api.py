"""Browser launch is same-origin, bounded, and tied to a live trajectory slot."""

from __future__ import annotations

from http.server import ThreadingHTTPServer
import fcntl
import json
import os
from pathlib import Path
import re
import socketserver
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from crucible import browser_task
from crucible.dashboard import make_handler
from crucible.task_broker import TaskManager, _remote_target
from crucible.trajectory import TaskBusyError, TrajectoryStore


class FakeBroker(socketserver.UnixStreamServer):
    def __init__(self, path: str) -> None:
        self.requests: list[dict] = []
        self.response = {"ok": True, "task": {
            "job_id": "job_" + "a" * 16, "task_id": "task_" + "b" * 16,
            "case": "safe_demo", "status": "queued", "proof_complete": None,
            "task_completed": None, "started_at": "2026-09-27T10:00:00+00:00", "finished_at": None}}
        class Handler(socketserver.StreamRequestHandler):
            def handle(inner) -> None:
                self.requests.append(json.loads(inner.rfile.readline()))
                inner.wfile.write(json.dumps(self.response).encode() + b"\n")
        super().__init__(path, Handler)


class BrowserTaskHTTPTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.db = root / "bank.sqlite"
        TrajectoryStore(self.db)
        self.broker = FakeBroker(str(root / "broker.sock"))
        self.broker_thread = threading.Thread(target=self.broker.serve_forever, daemon=True)
        self.broker_thread.start()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0),
                                          make_handler(self.db, 20, task_socket=root / "broker.sock"))
        self.http_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.http_thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown(); self.server.server_close(); self.http_thread.join()
        self.broker.shutdown(); self.broker.server_close(); self.broker_thread.join()
        self.temp.cleanup()

    def _post(self, body: bytes, *, origin: str = "http://127.0.0.1:18787",
              host: str = "127.0.0.1:18787", csrf: str | None = None) -> int:
        headers = {"Host": host, "Origin": origin, "Content-Type": "application/json"}
        if csrf is not None:
            headers["X-Crucible-CSRF"] = csrf
        request = Request(self.base + "/api/tasks", data=body, headers=headers, method="POST")
        try:
            with urlopen(request, timeout=3) as response:
                self.last_response = json.load(response)
                return response.status
        except HTTPError as error:
            error.read()
            return error.code

    def _token(self) -> str:
        with urlopen(self.base + "/", timeout=3) as response:
            html = response.read().decode()
        match = re.search(r'data-csrf="([A-Za-z0-9_-]+)"', html)
        self.assertIsNotNone(match)
        self.assertNotIn("__TASK_CSRF__", html)
        return match.group(1)

    def test_forwarded_loopback_port_launches_only_fixed_case(self) -> None:
        token = self._token()
        status = self._post(b'{"case":"safe_demo"}', csrf=token)
        self.assertEqual(status, 202)
        self.assertEqual(self.last_response["task_id"], "task_" + "b" * 16)
        self.assertEqual(self.broker.requests, [{"op": "start", "case": "safe_demo"}])
        with urlopen(self.base + "/api/tasks/current", timeout=3) as response:
            current = json.load(response)
        self.assertEqual(current["status"], "queued")
        self.assertEqual(self.broker.requests[-1], {"op": "current"})

    def test_firewall_gap_case_is_browser_launchable_without_user_supplied_targets(self) -> None:
        token = self._token()
        status = self._post(b'{"case":"firewall_gap_evolution"}', csrf=token)
        self.assertEqual(status, 202)
        self.assertEqual(self.broker.requests, [{"op": "start", "case": "firewall_gap_evolution"}])
        self.assertEqual(self._post(
            b'{"case":"firewall_gap_evolution","url":"https://example.com"}',
            csrf=token), 400)
        self.assertEqual(len(self.broker.requests), 1)

    def test_cross_origin_rebinding_and_arbitrary_fields_are_rejected(self) -> None:
        token = self._token()
        self.assertEqual(self._post(b'{"case":"safe_demo"}', csrf=token,
                                    origin="https://attacker.example"), 403)
        self.assertEqual(self._post(b'{"case":"safe_demo"}', csrf=token,
                                    host="attacker.example", origin="http://attacker.example"), 403)
        self.assertEqual(self._post(b'{"case":"safe_demo"}'), 403)
        self.assertEqual(self._post(b'{"case":"safe_demo","cmd":"rm -rf /"}', csrf=token), 400)
        self.assertEqual(self._post(b'{"case":"safe_demo","case":"readiness_evolution"}', csrf=token), 400)
        self.assertEqual(self.broker.requests, [])
        request = Request(self.base + "/", headers={"Host": "attacker.example"})
        with self.assertRaises(HTTPError) as caught:
            urlopen(request, timeout=3)
        self.assertEqual(caught.exception.code, 403)

    def test_busy_response_and_sanitized_status(self) -> None:
        self.broker.response = {"ok": False, "error": "busy", "private": "secret"}
        self.assertEqual(self._post(b'{"case":"readiness_evolution"}', csrf=self._token()), 409)
        self.broker.response = {"ok": True, "task": {"job_id": None, "task_id": None,
            "case": None, "status": "idle", "proof_complete": None,
            "private": "never forward"}}
        with urlopen(self.base + "/api/tasks/current", timeout=3) as response:
            body = response.read().decode()
        self.assertNotIn("never forward", body)


class BrokerTaskTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.db = Path(self.temp.name) / "bank.sqlite"
        TrajectoryStore(self.db)
        self.lock = Path(self.temp.name) / "deploy.lock"
        self.lock.touch(mode=0o600)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _await_end(self, manager: TaskManager) -> dict:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            task = manager.current()
            if task["status"] in {"complete", "failed"}:
                return task
            time.sleep(0.02)
        self.fail("broker task did not finish")

    def test_atomic_claim_blocks_second_browser_task_and_cli(self) -> None:
        command = [sys.executable, "-c", "import time; time.sleep(0.4)"]
        with mock.patch("crucible.task_broker._child_environment", return_value={"PATH": "/usr/bin:/bin"}), \
             mock.patch("crucible.task_broker._command", return_value=(command, 5)):
            manager = TaskManager(self.db, deploy_lock=self.lock)
            started = manager.start("safe_demo")
            with self.assertRaises(TaskBusyError):
                manager.start("readiness_evolution")
            with self.assertRaises(TaskBusyError):
                TrajectoryStore(self.db).claim_task()
            ended = self._await_end(manager)
        self.assertEqual(ended["status"], "complete")
        self.assertTrue(ended["task_completed"])
        self.assertIsNone(ended["proof_complete"])
        self.assertEqual(TrajectoryStore(self.db, read_only=True).snapshot()["task_id"], started["task_id"])
        self.assertFalse(TrajectoryStore(self.db, read_only=True).snapshot()["active"])

    def test_child_failure_releases_trajectory_and_cannot_claim_proof(self) -> None:
        command = [sys.executable, "-c", "raise SystemExit(2)"]
        with mock.patch("crucible.task_broker._child_environment", return_value={"PATH": "/usr/bin:/bin"}), \
             mock.patch("crucible.task_broker._command", return_value=(command, 5)):
            manager = TaskManager(self.db, deploy_lock=self.lock)
            manager.start("readiness_evolution")
            ended = self._await_end(manager)
        self.assertEqual(ended["status"], "failed")
        self.assertFalse(ended["proof_complete"])
        self.assertEqual(TrajectoryStore(self.db, read_only=True).snapshot()["status"], "failed")

    def test_successful_child_cannot_claim_proof_when_completion_is_not_persisted(self) -> None:
        command = [sys.executable, "-c", "raise SystemExit(0)"]
        with mock.patch("crucible.task_broker._child_environment", return_value={"PATH": "/usr/bin:/bin"}), \
             mock.patch("crucible.task_broker._command", return_value=(command, 5)), \
             mock.patch.object(TrajectoryStore, "finish_task", side_effect=sqlite3.OperationalError("disk full")):
            manager = TaskManager(self.db, deploy_lock=self.lock)
            manager.start("readiness_evolution")
            ended = self._await_end(manager)
        self.assertEqual(ended["status"], "failed")
        self.assertFalse(ended["proof_complete"])
        self.assertFalse(ended["task_completed"])
        self.assertTrue(TrajectoryStore(self.db, read_only=True).snapshot()["active"])

    def test_timeout_uses_graceful_signal_before_force_kill(self) -> None:
        ready = Path(self.temp.name) / "ready"
        cleaned = Path(self.temp.name) / "cleaned"
        code = ("import pathlib,signal,sys,time\n"
                "ready=pathlib.Path(sys.argv[1]); cleaned=pathlib.Path(sys.argv[2])\n"
                "def stop(*_):\n cleaned.write_text('finally ran'); raise SystemExit(3)\n"
                "signal.signal(signal.SIGTERM,stop); ready.touch(); time.sleep(20)\n")
        command = [sys.executable, "-c", code, str(ready), str(cleaned)]
        with mock.patch("crucible.task_broker._child_environment", return_value={"PATH": "/usr/bin:/bin"}), \
             mock.patch("crucible.task_broker._command", return_value=(command, 0.5)):
            manager = TaskManager(self.db, deploy_lock=self.lock)
            manager.start("safe_demo")
            ended = self._await_end(manager)
        self.assertTrue(ready.exists())
        self.assertEqual(cleaned.read_text(), "finally ran")
        self.assertEqual(ended["status"], "failed")
        self.assertFalse(TrajectoryStore(self.db, read_only=True).snapshot()["active"])

    def test_restart_reconciles_dead_owner_as_interrupted(self) -> None:
        store = TrajectoryStore(self.db)
        task_id = store.claim_task()
        with sqlite3.connect(self.db) as db:
            db.execute("UPDATE tasks SET owner_pid=? WHERE task_id=?", (2**30, task_id))
        manager = TaskManager(self.db, deploy_lock=self.lock)
        self.assertEqual(manager.current()["status"], "interrupted")
        self.assertEqual(manager.current()["task_id"], task_id)
        self.assertFalse(store.snapshot()["active"])

    def test_deployment_lock_rejects_new_task_before_claim(self) -> None:
        manager = TaskManager(self.db, deploy_lock=self.lock)
        descriptor = os.open(self.lock, os.O_RDONLY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(TaskBusyError):
                manager.start("safe_demo")
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        self.assertEqual(TrajectoryStore(self.db, read_only=True).snapshot()["status"], "idle")

    def test_known_host_derivation_rejects_ambiguous_or_public_target(self) -> None:
        hosts = Path(self.temp.name) / "known_hosts"
        hosts.write_text("10.12.96.4 ssh-ed25519 AAAA\n")
        self.assertEqual(_remote_target(hosts, ""), "root@10.12.96.4")
        with self.assertRaises(Exception):
            _remote_target(hosts, "root@10.12.96.5")
        hosts.write_text("8.8.8.8 ssh-ed25519 AAAA\n")
        with self.assertRaises(Exception):
            _remote_target(hosts, "")
        hosts.write_text("10.12.96.4 ssh-ed25519 AAAA\n10.12.96.5 ssh-ed25519 BBBB\n")
        with self.assertRaises(Exception):
            _remote_target(hosts, "")

    def test_safe_demo_uses_real_remote_supervisor_and_shared_bank(self) -> None:
        seen: dict = {}
        class FakeSupervisor:
            def __init__(self, root, config, **kwargs):
                seen.update(root=root, config=config, kwargs=kwargs)
            def run_episode(self, scenario, *, adapt):
                seen.update(scenario=scenario, adapt=adapt)
                return {"worker_mode": "vultr", "execution_mode": "remote",
                        "lifecycle": {"runtime": "kata-qemu", "destroyed": True},
                        "flag_captured": False, "action_results_verified": True,
                        "safe_action_executed": True, "task_completed": True,
                        "flag_verifiable": True}
        with mock.patch.dict(os.environ, {"CRUCIBLE_BROKER_TASK_ID": "task_" + "a" * 16}), \
             mock.patch.object(browser_task, "REPO_ROOT", Path(self.temp.name)), \
             mock.patch.object(browser_task, "load_env_local"), \
             mock.patch.object(browser_task, "TrajectoryStore", return_value=object()), \
             mock.patch.object(browser_task, "Supervisor", FakeSupervisor):
            self.assertEqual(browser_task.main(["--case", "safe_demo",
                                                "--trajectory-db", str(self.db)]), 0)
        self.assertEqual(seen["root"], Path(self.temp.name))
        self.assertEqual(seen["config"].mode, "vultr")
        self.assertEqual(seen["config"].execution, "remote")
        self.assertEqual(seen["kwargs"]["task_id"], "task_" + "a" * 16)
        self.assertEqual(seen["scenario"].decoy_family, "egress_mirror")
        self.assertFalse(seen["adapt"])


if __name__ == "__main__":
    unittest.main()
