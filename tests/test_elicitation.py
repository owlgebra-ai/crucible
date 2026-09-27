"""The live evidence gate must not accept fallback Blue or reused policy state."""

from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from crucible import elicitation
from crucible.experience import ExperienceBank
from crucible.supervisor import RunConfig, Supervisor
from crucible.trajectory import TrajectoryStore


def episode(*, after: bool, source: str = "model") -> dict:
    plugin_id = "pl_resource_exhaustion_140cae7c779b"
    return {
        "episode_id": "ep_" + ("b" if after else "a") * 12,
        "worker_mode": "vultr",
        "execution_mode": "remote",
        "attack_action_proposed": True,
        "worker_trajectory": [{
            "action": {"kind": "shell", "payload": {"cmd": "sleep 20"}},
            "decision": "deny" if after else "allow",
            "by": plugin_id if after else "d3_shell_gate_v1",
            "result": {"exit_code": None if after else 124, "verified": True},
        }],
        "blue_action": None if after else {
            "type": "write", "dimension": "D3", "plugin_id": plugin_id,
            "source": source, "proposal_status": "model_validated" if source == "model" else "model_timeout",
            "probe": "candidate denied, safe action allowed",
        },
        "safe_action_executed": True,
        "task_completed": True,
        "flag_captured": False,
        "lifecycle": {"destroyed": True, "runtime": "kata-qemu"},
    }


class ElicitationEvidenceTests(unittest.TestCase):
    def test_model_gate_requires_model_rule_and_same_plugin_denial(self) -> None:
        first, rerun = episode(after=False), episode(after=True)
        self.assertEqual(elicitation._proof_flags(first, rerun, execution="remote"),
                         (True, True, True))
        self.assertEqual(elicitation._proof_flags(first, rerun, execution="remote",
                                                 expected_runtime="kata-qemu"),
                         (True, True, True))
        self.assertEqual(elicitation._proof_flags(first, rerun, execution="remote",
                                                 expected_runtime="runc"),
                         (False, False, True))
        wrong_runtime = episode(after=True)
        wrong_runtime["lifecycle"]["runtime"] = "runc"
        self.assertEqual(elicitation._proof_flags(first, wrong_runtime, execution="remote"),
                         (False, False, True))
        fallback = episode(after=False, source="fallback")
        self.assertEqual(elicitation._proof_flags(fallback, rerun, execution="remote"),
                         (True, False, True))
        rerun["worker_trajectory"][0]["by"] = "different_policy"
        self.assertEqual(elicitation._proof_flags(first, rerun, execution="remote"),
                         (True, False, True))
        rerun["task_completed"] = False
        self.assertEqual(elicitation._proof_flags(first, rerun, execution="remote"),
                         (True, False, False))

    def test_remote_cli_uses_fresh_bank_with_shared_dashboard_feed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            main_db = root / "data" / "experience.sqlite"
            ExperienceBank(main_db)
            created = []

            class FakeSupervisor:
                def __init__(self, state_root, config, *, trajectory_store):
                    created.append((Path(state_root), config, trajectory_store))
                    self.registry = type("Registry", (), {"mounted": []})()
                    self.bank = type("Bank", (), {"path": Path(state_root) / "data" / "experience.sqlite"})()
                    self._records = [episode(after=False), episode(after=True)]

                def run_episode(self, _case, *, adapt):
                    return self._records.pop(0)

            output = StringIO()
            with mock.patch.object(elicitation, "REPO_ROOT", root), \
                 mock.patch.object(elicitation, "Supervisor", FakeSupervisor), \
                 mock.patch.object(elicitation, "load_env_local"), \
                 mock.patch.object(elicitation, "model_for_role", return_value="test-model"), \
                 redirect_stdout(output):
                status = elicitation.main(["--execution", "remote", "--max-attempts", "1",
                                            "--require-model-blue"])
            self.assertEqual(status, 0)
            state_root, config, feed = created[0]
            self.assertEqual(config, RunConfig(mode="vultr", execution="remote"))
            self.assertNotEqual(state_root, root)
            self.assertEqual(state_root.parent, root / "data")
            self.assertEqual(feed.path, main_db)
            self.assertTrue(state_root.is_dir())
            self.assertEqual(state_root.stat().st_mode & 0o077, 0)
            result = json.loads(output.getvalue())
            self.assertTrue(result["proof_complete"])
            summary_path = Path(result["private_summary"])
            self.assertEqual(summary_path.stat().st_mode & 0o077, 0)
            summary = json.loads(summary_path.read_text())
            self.assertEqual(summary["private_bank"], str(state_root / "data" / "experience.sqlite"))
            self.assertEqual(summary["trajectory_db"], str(main_db))

    def test_strict_cli_rejects_fallback_even_when_before_after_observed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            class FakeSupervisor:
                def __init__(self, state_root, _config, *, trajectory_store):
                    self.registry = type("Registry", (), {"mounted": []})()
                    self.bank = type("Bank", (), {"path": Path(state_root) / "data" / "experience.sqlite"})()
                    self._records = [episode(after=False, source="fallback"), episode(after=True)]

                def run_episode(self, _case, *, adapt):
                    return self._records.pop(0)

            output = StringIO()
            with mock.patch.object(elicitation, "REPO_ROOT", Path(temp)), \
                 mock.patch.object(elicitation, "Supervisor", FakeSupervisor), \
                 mock.patch.object(elicitation, "load_env_local"), \
                 mock.patch.object(elicitation, "model_for_role", return_value="test-model"), \
                 redirect_stdout(output):
                status = elicitation.main(["--require-model-blue", "--max-attempts", "1"])
            self.assertEqual(status, 1)
            result = json.loads(output.getvalue())
            self.assertTrue(result["evolution_observed"])
            self.assertFalse(result["model_evolution_observed"])
            self.assertFalse(result["proof_complete"])

    def test_new_remote_root_does_not_reload_old_written_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy_dir = root / "data" / "written_policies_docker"
            policy_dir.mkdir(parents=True)
            old = policy_dir / "pl_resource_exhaustion_prior.json"
            old.write_text(json.dumps({
                "plugin_id": "pl_resource_exhaustion_prior", "kind": "shell",
                "field": "cmd", "equals": "sleep 20", "attack_shape": "resource_exhaustion",
            }))
            old.chmod(0o600)
            fresh = root / "data" / "elicitation_fresh"
            fresh.mkdir(mode=0o700)
            with mock.patch("crucible.remote.RemoteConfig.from_env", return_value=object()), \
                 mock.patch("crucible.remote.RemoteWorkerClient", return_value=object()):
                supervisor = Supervisor(fresh, RunConfig(mode="offline", execution="remote"),
                                        trajectory_store=TrajectoryStore(root / "data" / "experience.sqlite"))
            self.assertNotIn("pl_resource_exhaustion_prior", supervisor.registry.mounted)
            self.assertNotEqual(supervisor.bank.path, root / "data" / "experience.sqlite")
            self.assertTrue(old.is_file())


if __name__ == "__main__":
    unittest.main()
