"""The destructive judge string remains test data and must never reach a runner."""

from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from crucible import judge_probe
from crucible.plugins.d3_shell_gate import ShellGatePlugin
from crucible.plugins_api import PluginRegistry
from crucible.supervisor import RunConfig, Supervisor


class JudgeProbeTests(unittest.TestCase):
    def _remote_supervisor(self, root: str) -> Supervisor:
        with mock.patch("crucible.remote.RemoteConfig.from_env", return_value=object()), \
                mock.patch("crucible.remote.RemoteWorkerClient") as client:
            supervisor = Supervisor(root, RunConfig(mode="offline", execution="remote",
                                                    enable_classifier=False))
            supervisor.remote = client.return_value
        return supervisor

    def test_remote_contract_denies_candidate_and_executes_only_safe_read(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            supervisor = self._remote_supervisor(temp)
            supervisor.remote.create.return_value = "a" * 64
            supervisor.remote.execute.return_value = {
                "exit_code": 0, "stdout": "Local reference dataset: 1, 1, 2, 3, 5, 8.\n",
                "stderr": "", "redactions": 0,
            }
            supervisor.remote.destroy.return_value = True
            record = supervisor.run_episode(
                judge_probe.judge_case(), require_first_denial_plugin=ShellGatePlugin.id)
            result = judge_probe.summarize(record, execution="remote")

            self.assertTrue(result["proof_complete"])
            self.assertFalse(result["candidate_dispatched"])
            self.assertIsNone(result["candidate_worker_exit_code"])
            self.assertEqual(result["preexec_plugin"], ShellGatePlugin.id)
            self.assertEqual(result["safe_action_exit_code"], 0)
            supervisor.remote.execute.assert_called_once()
            action = supervisor.remote.execute.call_args.args[2]
            self.assertEqual(action, {"kind": "file_read",
                                      "payload": {"path": "/work/scenario/reference.txt"}})
            supervisor.remote.destroy.assert_called_once()
            phases = [event["phase"] for event in supervisor.trajectory_store.snapshot()["events"]]
            self.assertIn("fixed_probe", phases)
            self.assertNotIn("worker", phases)

    def test_policy_regression_fails_closed_before_any_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            supervisor = self._remote_supervisor(temp)
            supervisor.remote.create.return_value = "b" * 64
            supervisor.remote.destroy.return_value = True
            supervisor.registry = PluginRegistry()  # Simulate the D3 policy being absent.
            with self.assertRaisesRegex(RuntimeError, "not dispatched"):
                supervisor.run_episode(
                    judge_probe.judge_case(), require_first_denial_plugin=ShellGatePlugin.id)
            supervisor.remote.execute.assert_not_called()
            supervisor.remote.destroy.assert_called_once()

    def test_fixed_input_is_exact_and_simulation_cannot_pass_remote_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(judge_probe, "REPO_ROOT", Path(temp)):
            with self.assertRaises(SystemExit), \
                    mock.patch.object(judge_probe, "Supervisor") as supervisor_type:
                judge_probe.main(["--command", "different command", "--execution", "simulate"])
            supervisor_type.assert_not_called()
            output = StringIO()
            with redirect_stdout(output):
                exit_code = judge_probe.main(["--command", judge_probe.JUDGE_COMMAND,
                                              "--execution", "simulate"])
            summary = json.loads(output.getvalue())
            self.assertEqual(exit_code, 1)
            self.assertEqual(summary["preexec_decision"], "deny")
            self.assertTrue(summary["safe_action_works"])
            self.assertFalse(summary["verified_remote"])
            self.assertFalse(summary["proof_complete"])
            path = Path(summary["private_summary"])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)


if __name__ == "__main__":
    unittest.main()
