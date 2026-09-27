"""Live trajectory events must be observable while preserving the sandbox seam."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest import mock

from crucible.experience import ExperienceBank
from crucible.scenarios import CANARY, seed_scenario
from crucible.supervisor import RunConfig, Supervisor
from crucible.trajectory import TaskBusyError, TrajectoryStore


class TrajectoryStoreTests(unittest.TestCase):
    def test_read_only_store_rejects_symlink_database(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "experience.sqlite"
            ExperienceBank(path)
            link = Path(temp) / "linked.sqlite"
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                TrajectoryStore(link, read_only=True)

    def test_read_only_old_bank_and_closed_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "experience.sqlite"
            ExperienceBank(path)
            observer = TrajectoryStore(path, read_only=True)
            self.assertEqual(observer.snapshot()["events"], [])
            self.assertEqual(observer.events_since(), [])
            store = TrajectoryStore(path)
            task_id = store.claim_task()
            store.mark_running(task_id)
            store.append(task_id, "worker", "ok", family="10.2.3.4",
                         action=f"shell {CANARY}", dimension="private-key")
            store.append(task_id, "preexec", "deny", action="http_get", dimension="D6")
            store.finish_task(task_id)
            snapshot = observer.snapshot()
            self.assertFalse(snapshot["active"])
            self.assertEqual(snapshot["status"], "complete")
            self.assertEqual([event["phase"] for event in snapshot["events"]],
                             ["task_start", "worker", "preexec", "task_end"])
            body = json.dumps(snapshot)
            self.assertNotIn(CANARY, body)
            self.assertNotIn("10.2.3.4", body)
            self.assertNotIn("private-key", body)
            self.assertEqual(store.events_since(snapshot["events"][1]["seq"])[0]["phase"], "preexec")

    def test_one_active_task_and_dead_owner_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "experience.sqlite"
            store = TrajectoryStore(path)
            first = store.claim_task()
            with self.assertRaises(TaskBusyError):
                TrajectoryStore(path).claim_task()
            with sqlite3.connect(path) as db:
                db.execute("UPDATE tasks SET owner_pid=? WHERE task_id=?", (99_999_999, first))
            second = store.claim_task()
            self.assertNotEqual(first, second)
            with sqlite3.connect(path) as db:
                status = db.execute("SELECT status FROM tasks WHERE task_id=?", (first,)).fetchone()[0]
            self.assertEqual(status, "interrupted")
            self.assertIn("task_error", [item["phase"] for item in store.events_since()])


class SupervisorTrajectoryTests(unittest.TestCase):
    def test_cli_round_claims_before_red_generation(self) -> None:
        class FakeRemote:
            def create(self, _scenario_dir, _episode_id):
                return "c" * 64

            def execute(self, _cid, _episode_id, _action):
                return {"exit_code": 1, "stdout": "", "stderr": "blocked"}

            def destroy(self, _cid, _episode_id):
                return True

            def cleanup(self, _episode_id):
                return True

        with tempfile.TemporaryDirectory() as temp, \
                mock.patch("crucible.remote.RemoteConfig.from_env", return_value=object()), \
                mock.patch("crucible.remote.RemoteWorkerClient", return_value=FakeRemote()):
            supervisor = Supervisor(temp, RunConfig(execution="remote"))
            entered = threading.Event()
            release = threading.Event()
            original = seed_scenario(1, "egress_mirror")

            def blocked_next(*_args, **_kwargs):
                entered.set()
                self.assertTrue(release.wait(5))
                return original

            outcome = {}
            with mock.patch("crucible.supervisor.RedGenerator.next", side_effect=blocked_next):
                thread = threading.Thread(target=lambda: outcome.setdefault("records", supervisor.run_rounds(1,
                                            adapt=False)), daemon=True)
                thread.start()
                self.assertTrue(entered.wait(5))
                observer = TrajectoryStore(Path(temp) / "data" / "experience.sqlite", read_only=True)
                snapshot = observer.snapshot()
                self.assertTrue(snapshot["active"])
                self.assertEqual([event["phase"] for event in snapshot["events"]],
                                 ["task_start", "red"])
                release.set()
                thread.join(10)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(outcome["records"]), 1)
            self.assertEqual(observer.snapshot()["events"][-1]["phase"], "task_end")

    def test_remote_exec_pending_is_visible_before_response(self) -> None:
        entered = threading.Event()
        release = threading.Event()

        class FakeRemote:
            def create(self, _scenario_dir, _episode_id):
                return "c" * 64

            def execute(self, _cid, _episode_id, _action):
                entered.set()
                if not release.wait(5):
                    raise RuntimeError("test remote timeout")
                return {"exit_code": 1, "stdout": f"{CANARY} 10.2.3.4", "stderr": "blocked"}

            def destroy(self, _cid, _episode_id):
                return True

            def cleanup(self, _episode_id):
                return True

        with tempfile.TemporaryDirectory() as temp, \
                mock.patch("crucible.remote.RemoteConfig.from_env", return_value=object()), \
                mock.patch("crucible.remote.RemoteWorkerClient", return_value=FakeRemote()):
            supervisor = Supervisor(temp, RunConfig(execution="remote"))
            outcome = {}

            def run():
                try:
                    outcome["record"] = supervisor.run_episode(seed_scenario(1, "egress_mirror"))
                except Exception as exc:
                    outcome["error"] = exc

            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            try:
                self.assertTrue(entered.wait(5))
                observer = TrajectoryStore(Path(temp) / "data" / "experience.sqlite", read_only=True)
                snapshot = observer.snapshot()
                self.assertTrue(snapshot["active"])
                self.assertEqual(snapshot["events"][-1]["phase"], "remote_exec")
                self.assertEqual(snapshot["events"][-1]["status"], "pending")
                body = json.dumps(snapshot)
                for forbidden in (CANARY, "10.2.3.4", "c" * 64):
                    self.assertNotIn(forbidden, body)
            finally:
                release.set()
                thread.join(10)
            self.assertFalse(thread.is_alive())
            self.assertNotIn("error", outcome)
            phases = [event["phase"] for event in observer.snapshot()["events"]]
            self.assertIn("result", phases)
            self.assertIn("teardown", phases)
            self.assertEqual(phases[-1], "task_end")


if __name__ == "__main__":
    unittest.main()
