"""Runtime provenance must survive the remote session's full lifecycle."""

from __future__ import annotations

from contextlib import contextmanager
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from crucible.remote import RemoteConfig, RemoteError, RemoteWorkerClient
from crucible.scenarios import seed_scenario
from crucible.supervisor import RunConfig, Supervisor


GATEWAY_PATH = Path(__file__).resolve().parents[1] / "remote-worker-gateway.py"
spec = importlib.util.spec_from_file_location("remote_worker_gateway_provenance", GATEWAY_PATH)
assert spec and spec.loader
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)


class RuntimeProvenanceTests(unittest.TestCase):
    def test_gateway_reads_runtime_under_create_lock_and_attests_it(self) -> None:
        events: list[str] = []

        @contextmanager
        def create_lock():
            events.append("locked")
            try:
                yield
            finally:
                events.append("unlocked")

        def configured_runtime() -> str:
            self.assertEqual(events, ["locked"])
            events.append("read")
            return "kata-qemu"

        cid = "c" * 64
        files = {name: "eA==" for name in ("scenario.json", "README.md", "reference.txt")}
        with mock.patch.object(gateway, "_create_lock", side_effect=create_lock), \
                mock.patch.object(gateway, "_configured_runtime", side_effect=configured_runtime), \
                mock.patch.object(gateway, "_assert_no_gap_artifacts"), \
                mock.patch.object(gateway, "_ensure_capacity"), \
                mock.patch.object(gateway, "_run", return_value=subprocess.CompletedProcess([], 0, cid + "\n", "")) as run, \
                mock.patch.object(gateway, "_session_matches", return_value=True):
            response = gateway.handle({"op": "create", "episode_id": "ep_" + "a" * 12,
                                       "files": files})
        self.assertEqual(events, ["locked", "read", "unlocked"])
        self.assertEqual(response, {"ok": True, "container_id": cid, "runtime": "kata-qemu"})
        self.assertEqual(run.call_args.kwargs["env"]["CRUCIBLE_RUNTIME"], "kata-qemu")

    def test_client_tracks_attested_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            scenario = self._scenario(Path(temp))
            client = self._client(Path(temp))
            cid = "a" * 64
            with mock.patch.object(client, "_call", return_value={"container_id": cid,
                                                                   "runtime": "kata-qemu"}) as call:
                self.assertEqual(client.create(scenario, "ep_" + "a" * 12), cid)
            self.assertEqual(client.runtime_for(cid), "kata-qemu")
            self.assertEqual(call.call_count, 1)

    def test_client_cleans_episode_after_failed_create_attestation(self) -> None:
        cid = "a" * 64
        bad_responses = (
            {"container_id": cid},
            {"container_id": cid, "runtime": "unknown"},
            {"container_id": cid, "runtime": ["kata-qemu"]},
            {"container_id": "bad", "runtime": "kata-qemu"},
        )
        with tempfile.TemporaryDirectory() as temp:
            scenario = self._scenario(Path(temp))
            episode_id = "ep_" + "a" * 12
            for response in bad_responses:
                with self.subTest(response=response):
                    client = self._client(Path(temp))
                    with mock.patch.object(client, "_call", side_effect=[response, {"destroyed": True}]) as call:
                        with self.assertRaises(RemoteError):
                            client.create(scenario, episode_id)
                    self.assertEqual([entry.args[0]["op"] for entry in call.call_args_list],
                                     ["create", "cleanup"])
                    self.assertEqual(call.call_args_list[-1].args[0]["episode_id"], episode_id)
                    self.assertIsNone(client.runtime_for(cid))

            client = self._client(Path(temp))
            with mock.patch.object(client, "_call", side_effect=[RemoteError("lost response"),
                                                                  {"destroyed": True}]) as call:
                with self.assertRaisesRegex(RemoteError, "lost response"):
                    client.create(scenario, episode_id)
            self.assertEqual([entry.args[0]["op"] for entry in call.call_args_list],
                             ["create", "cleanup"])

    def test_required_runtime_rejects_mismatch_before_exec(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            scenario = self._scenario(Path(temp))
            client = self._client(Path(temp))
            episode_id = "ep_" + "a" * 12
            cid = "a" * 64
            with mock.patch.dict(os.environ, {"CRUCIBLE_REQUIRED_RUNTIME": "kata-qemu"}), \
                    mock.patch.object(client, "_call", side_effect=[
                        {"container_id": cid, "runtime": "runc"}, {"destroyed": True}
                    ]) as call:
                with self.assertRaisesRegex(RemoteError, "unexpected worker runtime"):
                    client.create(scenario, episode_id)
            self.assertEqual([item.args[0]["op"] for item in call.call_args_list],
                             ["create", "cleanup"])
            self.assertIsNone(client.runtime_for(cid))

            with mock.patch.dict(os.environ, {"CRUCIBLE_REQUIRED_RUNTIME": "unknown"}), \
                    mock.patch.object(client, "_call") as call:
                with self.assertRaisesRegex(RemoteError, "invalid required worker runtime"):
                    client.create(scenario, episode_id)
                call.assert_not_called()

    def test_supervisor_records_runtime_in_persisted_lifecycle(self) -> None:
        class FakeRemote:
            def create(self, _directory, _episode_id):
                return "a" * 64

            def runtime_for(self, _cid):
                return "kata-qemu"

            def execute(self, _cid, _episode_id, action):
                if action["kind"] == "http_get":
                    return {"exit_code": 77, "stdout": "", "stderr": "remote pre-exec denied",
                            "policy_denial": "D1"}
                return {"exit_code": 0, "stdout": "Local reference dataset: 1, 1, 2, 3, 5, 8.\n",
                        "stderr": ""}

            def destroy(self, _cid, _episode_id):
                return True

            def cleanup(self, _episode_id):
                return True

        with tempfile.TemporaryDirectory() as temp, \
                mock.patch("crucible.remote.RemoteConfig.from_env", return_value=object()), \
                mock.patch("crucible.remote.RemoteWorkerClient", return_value=FakeRemote()):
            supervisor = Supervisor(temp, RunConfig(execution="remote"))
            record = supervisor.run_episode(seed_scenario(1, "egress_mirror"))
            persisted = supervisor.bank.list_episodes(limit=1)[0]
        self.assertEqual(record["lifecycle"]["runtime"], "kata-qemu")
        self.assertEqual(persisted["lifecycle"]["runtime"], "kata-qemu")
        self.assertTrue(record["lifecycle"]["destroyed"])

    @staticmethod
    def _scenario(directory: Path) -> Path:
        scenario = directory / "scenario"
        scenario.mkdir()
        for name in ("scenario.json", "README.md", "reference.txt"):
            (scenario / name).write_text("fixture")
        return scenario

    @staticmethod
    def _client(directory: Path) -> RemoteWorkerClient:
        return RemoteWorkerClient(RemoteConfig("root@10.1.2.3", directory / "identity",
                                               directory / "known_hosts"))


if __name__ == "__main__":
    unittest.main()
