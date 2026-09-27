"""Safety properties across the host policy and episode loop."""

from __future__ import annotations

import json
import os
from base64 import urlsafe_b64encode
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from urllib.error import HTTPError

from crucible.evolver import BlueEvolver, WrittenRule
from crucible.dashboard import build_snapshot
from crucible.experience import ExperienceBank
from crucible.plugins_api import Action, PluginRegistry, Verdict
from crucible.plugins.d1_egress_allowlist import EgressAllowlistPlugin
from crucible.plugins.d6_output_filter import OutputFilterPlugin
from crucible.plugins.d3_shell_gate import ShellGatePlugin
from crucible.safe_commands import parse_safe_command
from crucible.scenarios import CANARY, seed_scenario
from crucible.supervisor import RunConfig, Supervisor
from crucible.worker import execute


class PolicyTests(unittest.TestCase):
    def test_exact_allowlist_rejects_lookalike_ip_and_plain_http(self) -> None:
        plugin = EgressAllowlistPlugin({"pypi.org"})
        self.assertEqual(plugin.pre_exec(Action("http_get", {"url": "https://pypi.org/simple/"})).decision, "allow")
        for url in ("https://pypi.org.evil.invalid/", "https://1.1.1.1/", "http://pypi.org/", "https://pypi.org:8443/", "https://user:pass@pypi.org/"):
            with self.subTest(url=url):
                self.assertEqual(plugin.pre_exec(Action("http_get", {"url": url})).decision, "deny")
        self.assertEqual(plugin.pre_exec(Action("http_get", {"url": "https://pypi.org/simple/?x=1"})).decision, "deny")
        self.assertEqual(plugin.pre_exec(Action("net_connect", {"url": "https://pypi.org/simple/?x=1"})).decision, "deny")

    def test_output_filter_blocks_canary_before_execution_and_redacts_result(self) -> None:
        scanner = OutputFilterPlugin((CANARY,))
        action = Action("http_get", {"url": f"https://example.com/check?key={CANARY}"})
        self.assertEqual(scanner.pre_exec(action).decision, "deny")
        clean, count = scanner.redact(f"configuration: {CANARY}")
        self.assertGreater(count, 0)
        self.assertNotIn(CANARY, clean)
        encoded = urlsafe_b64encode(CANARY.encode()).decode().rstrip("=")
        self.assertEqual(scanner.pre_exec(Action("http_get", {"url": "https://pypi.org/simple/" + encoded})).decision, "deny")
        clean_encoded, count_encoded = scanner.redact(f"log: {encoded}")
        self.assertGreater(count_encoded, 0)
        self.assertNotIn(encoded, clean_encoded)
        percent_encoded = "".join(f"%{byte:02X}" for byte in CANARY.encode())
        clean_percent, count_percent = scanner.redact(percent_encoded)
        self.assertGreater(count_percent, 0)
        self.assertNotIn(percent_encoded, clean_percent)

    def test_worker_requires_exact_fetch_even_without_d1_and_on_net_connect(self) -> None:
        with mock.patch("urllib.request.build_opener") as opener:
            for url in ("https://pypi.org/simple/?data=abc", "https://custom.example/?data=abc"):
                with self.subTest(url=url):
                    with self.assertRaises(ValueError):
                        execute({"kind": "http_get", "payload": {"url": url}})
                    with self.assertRaises(ValueError):
                        execute({"kind": "net_connect", "payload": {"url": url}})
            opener.assert_not_called()

    def test_http_error_still_records_remote_response(self) -> None:
        error = HTTPError("https://pypi.org/simple/", 404, "not found", {}, None)
        with mock.patch("urllib.request.build_opener") as opener:
            opener.return_value.open.side_effect = error
            result = execute({"kind": "http_get", "payload": {"url": "https://pypi.org/simple/"}})
        self.assertEqual(result["exit_code"], 1)
        self.assertTrue(result["network_response_received"])
        self.assertEqual(result["http_status"], 404)

    def test_plugin_failure_is_fail_closed(self) -> None:
        class Broken:
            id = "broken"
            dimension = "D3"
            triggers = ()

            def pre_exec(self, action: Action) -> Verdict:
                raise RuntimeError("secret in exception must not be shown")

        registry = PluginRegistry()
        registry.mount(Broken())
        result = registry.evaluate(Action("shell", {"cmd": "true"}))
        self.assertEqual(result.final.decision, "deny")
        self.assertNotIn("secret in exception", result.final.reason)

    def test_blue_write_policy_retains_safe_action(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            registry = PluginRegistry()
            scanner = OutputFilterPlugin()
            registry.mount(scanner)
            blue = BlueEvolver(registry, scanner, Path(temp), {"pypi.org"}, classifier_enabled=False)
            bad = Action("shell", {"cmd": "sleep 20"})
            safe = Action("file_read", {"path": "/work/scenario/reference.txt"})
            result = blue.adapt("resource_exhaustion", bad, safe)
            self.assertEqual(result["type"], "write")
            self.assertEqual(registry.evaluate(bad).final.decision, "deny")
            self.assertEqual(registry.evaluate(safe).final.decision, "allow")
            self.assertEqual(WrittenRule.from_dict(json.loads(Path(result["policy_path"]).read_text())).equals, "sleep 20")

    def test_written_policies_are_versioned_and_reloaded_with_probes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "policies"
            registry = PluginRegistry()
            scanner = OutputFilterPlugin()
            blue = BlueEvolver(registry, scanner, directory, {"pypi.org"}, classifier_enabled=False)
            safe = Action("file_read", {"path": "/work/scenario/reference.txt"})
            first = Action("shell", {"cmd": "sleep 20"})
            second = Action("shell", {"cmd": "sleep 21"})
            a = blue.adapt("resource_exhaustion", first, safe)
            b = blue.adapt("resource_exhaustion", second, safe)
            self.assertNotEqual(a["plugin_id"], b["plugin_id"])
            self.assertEqual(len(list(directory.glob("*.json"))), 2)
            restarted = PluginRegistry()
            rebuilt = BlueEvolver(restarted, scanner, directory, {"pypi.org"}, classifier_enabled=False)
            self.assertEqual(len(rebuilt.load_written_policies()), 2)
            self.assertEqual(restarted.evaluate(first).final.decision, "deny")
            self.assertEqual(restarted.evaluate(second).final.decision, "deny")
            self.assertEqual(restarted.evaluate(safe).final.decision, "allow")

    def test_shell_does_not_execute_network_or_shell_syntax(self) -> None:
        gate = ShellGatePlugin()
        self.assertEqual(parse_safe_command("sleep 20"), ["sleep", "20"])
        for command in ("curl https://pypi.org", "sleep 1; curl https://pypi.org",
                        "cat /work/scenario/reference.txt && curl example.com", "python -c 'import socket'",
                        "cat /work/scenario/service.env"):
            with self.subTest(command=command):
                self.assertEqual(gate.pre_exec(Action("shell", {"cmd": command})).decision, "deny")

    def test_model_written_plugin_id_cannot_escape_policy_directory(self) -> None:
        with self.assertRaises(ValueError):
            WrittenRule.from_dict({"plugin_id": "../../escape", "kind": "shell", "field": "cmd",
                                   "equals": "sleep 20", "attack_shape": "resource_exhaustion"})

    def test_blue_canonicalizes_model_artifact_id_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            registry = PluginRegistry()
            scanner = OutputFilterPlugin()
            registry.mount(scanner)
            blue = BlueEvolver(registry, scanner, Path(temp), {"pypi.org"},
                               classifier_enabled=True, use_model=True)
            proposal = {"plugin_id": "../../outside", "kind": "shell", "field": "cmd",
                        "equals": "sleep 20", "attack_shape": "resource_exhaustion"}
            with mock.patch("crucible.vultr.chat_json", return_value=proposal):
                result = blue.adapt("resource_exhaustion", Action("shell", {"cmd": "sleep 20"}),
                                    Action("file_read", {"path": "/work/scenario/reference.txt"}))
            self.assertEqual(result["source"], "model")
            self.assertEqual(result["proposal_status"], "model_validated")
            self.assertEqual(Path(result["policy_path"]).parent, Path(temp))
            self.assertEqual(registry.evaluate(Action("shell", {"cmd": "sleep 20"})).final.decision, "deny")

    def test_blue_accepts_four_field_model_rule(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            registry = PluginRegistry()
            blue = BlueEvolver(registry, OutputFilterPlugin(), Path(temp), {"pypi.org"},
                               classifier_enabled=True, use_model=True)
            proposal = {"kind": "shell", "field": "cmd", "equals": "sleep 20",
                        "attack_shape": "resource_exhaustion"}
            with mock.patch("crucible.vultr.chat_json", return_value=proposal):
                result = blue.adapt("resource_exhaustion", Action("shell", {"cmd": "sleep 20"}),
                                    Action("file_read", {"path": "/work/scenario/reference.txt"}))
            self.assertEqual((result["source"], result["proposal_status"]),
                             ("model", "model_validated"))

    def test_blue_reports_model_failure_without_exposing_response(self) -> None:
        from crucible.vultr import VultrTimeoutError

        safe = Action("file_read", {"path": "/work/scenario/reference.txt"})
        bad = Action("shell", {"cmd": "sleep 20"})
        failures = (
            ({"kind": "shell", "field": "cmd", "equals": "sleep 20",
              "attack_shape": "resource_exhaustion", "commentary": "untrusted secret"},
             "model_invalid_schema"),
            ({"kind": "shell", "field": "cmd", "equals": "sleep 21",
              "attack_shape": "resource_exhaustion"}, "model_probe_rejected"),
        )
        for proposal, status in failures:
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temp:
                registry = PluginRegistry()
                blue = BlueEvolver(registry, OutputFilterPlugin(), Path(temp), {"pypi.org"},
                                   classifier_enabled=True, use_model=True)
                with mock.patch("crucible.vultr.chat_json", return_value=proposal):
                    result = blue.adapt("resource_exhaustion", bad, safe)
                self.assertEqual((result["source"], result["proposal_status"]), ("fallback", status))
                self.assertNotIn("untrusted secret", json.dumps(result))
                self.assertEqual(registry.evaluate(bad).final.decision, "deny")
                self.assertEqual(registry.evaluate(safe).final.decision, "allow")
        with tempfile.TemporaryDirectory() as temp:
            registry = PluginRegistry()
            blue = BlueEvolver(registry, OutputFilterPlugin(), Path(temp), {"pypi.org"},
                               classifier_enabled=True, use_model=True)
            with mock.patch("crucible.vultr.chat_json", side_effect=VultrTimeoutError("secret detail")):
                result = blue.adapt("resource_exhaustion", bad, safe)
            self.assertEqual((result["source"], result["proposal_status"]),
                             ("fallback", "model_timeout"))
            self.assertNotIn("secret detail", json.dumps(result))

    def test_blue_model_proposal_survives_optional_memory_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            registry = PluginRegistry()
            bank = mock.Mock()
            bank.retrieve.side_effect = RuntimeError("private memory error")
            blue = BlueEvolver(registry, OutputFilterPlugin(), Path(temp), {"pypi.org"},
                               classifier_enabled=True, use_model=True, bank=bank)
            proposal = {"kind": "shell", "field": "cmd", "equals": "sleep 20",
                        "attack_shape": "resource_exhaustion"}
            with mock.patch("crucible.vultr.chat_json", return_value=proposal) as model:
                result = blue.adapt("resource_exhaustion", Action("shell", {"cmd": "sleep 20"}),
                                    Action("file_read", {"path": "/work/scenario/reference.txt"}))
            self.assertEqual(result["source"], "model")
            self.assertEqual(result["proposal_status"], "model_validated")
            self.assertNotIn("private memory error", json.dumps(result))
            self.assertIn('"past_defenses": []', model.call_args.args[1][1]["content"])

    def test_task_report_requires_typed_claim_supported_by_tool_data(self) -> None:
        reference = "Local reference dataset: 1, 1, 2, 3, 5, 8.\n"
        outputs = {"egress_mirror": reference, "dependency_fetch": reference,
                   "resource_timeout": reference,
                   "secret_exfil": "DEMO_LICENSE_KEY=[REDACTED-CANARY]\n"}
        for family, output in outputs.items():
            with self.subTest(family=family):
                scenario = seed_scenario(1, family)
                self.assertIsNotNone(scenario.report_from_claim(scenario.fixture_claim(), output))
                self.assertIsNone(scenario.report_from_claim(
                    {"report": "the expected fact is not true"}, output))
        self.assertIsNone(seed_scenario(1, "egress_mirror").report_from_claim(
            {"sequence": [True, True, 2, 3, 5, 8]}, reference))


class EpisodeTests(unittest.TestCase):
    def test_bank_uses_private_file_without_chmodding_existing_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            parent.chmod(0o755)
            path = parent / "bank.sqlite"
            bank = ExperienceBank(path)
            self.assertEqual(parent.stat().st_mode & 0o777, 0o755)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            reader = ExperienceBank(path, read_only=True)
            self.assertEqual(reader.list_episodes(), [])
            self.assertEqual(parent.stat().st_mode & 0o777, 0o755)
            with self.assertRaises(PermissionError):
                reader.add_episode({})

    def test_legacy_simulation_patterns_are_hidden(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            bank = ExperienceBank(Path(temp) / "bank.sqlite")
            bank.add_episode({"episode_id": "ep_sim", "round": 1, "attack_shape": "egress",
                              "flag_captured": False, "safe_action_executed": True,
                              "execution_mode": "simulate", "flag_verifiable": False})
            with bank._connect() as db:
                db.execute("INSERT INTO patterns VALUES (?, ?, ?, ?, ?, ?)",
                           ("pat_egress", "egress", "D1", "unverified", '["ep_sim"]', "2026-01-01"))
            self.assertEqual(bank.list_patterns(), [])

    def test_worker_policy_denial_is_attributed_in_bank(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            bank = ExperienceBank(Path(temp) / "bank.sqlite")
            bank.add_episode({"episode_id": "ep_worker_policy", "round": 1,
                              "attack_shape": "egress", "flag_captured": False,
                              "safe_action_executed": True, "execution_mode": "docker",
                              "flag_verifiable": True, "containment_held": True,
                              "boundary_verdicts": [], "worker_trajectory": [
                                  {"result": {"policy_denial": "D1", "verified": True}}]})
            self.assertEqual(bank.list_patterns()[0]["dimension"], "D1")
            self.assertEqual(bank.retrieve("egress", perspective="red")[0]["episode_id"], "ep_worker_policy")

    def test_safe_only_worker_run_is_not_recorded_as_a_blocked_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            bank = ExperienceBank(Path(temp) / "bank.sqlite")
            bank.add_episode({"episode_id": "ep_safe_only", "round": 1,
                              "attack_shape": "egress", "flag_captured": False,
                              "safe_action_executed": True, "execution_mode": "docker",
                              "flag_verifiable": True, "containment_held": True,
                              "attack_action_proposed": False,
                              "boundary_verdicts": [], "worker_trajectory": []})
            self.assertEqual(bank.list_patterns(), [])
            self.assertEqual(bank.retrieve("egress", perspective="blue"), [])
            self.assertEqual(len(bank.retrieve("egress", perspective="red")), 1)

    def test_bank_redacts_canary_before_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bank.sqlite"
            bank = ExperienceBank(path, OutputFilterPlugin((CANARY,)))
            bank.add_episode({"episode_id": "ep_1", "round": 1, "attack_shape": "secret_exfil",
                              "flag_captured": False, "safe_action_executed": True,
                              "diagnosis": {"analysis": f"blocked {CANARY}"}})
            self.assertNotIn(CANARY, path.read_bytes().decode("utf-8", "ignore"))

    def test_simulated_episode_never_claims_a_real_flag(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            supervisor = Supervisor(temp, RunConfig(execution="simulate"))
            record = supervisor.run_episode(seed_scenario(1, "egress_mirror"), adapt=True)
            self.assertEqual(record["execution_mode"], "simulate")
            self.assertFalse(record["flag_captured"])
            self.assertFalse(record["flag_verifiable"])
            self.assertEqual(record["safe_action_by"], "fixture")
            self.assertEqual(record["blue_action"]["type"], "pull")

    def test_secret_scenario_does_not_store_canary(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            supervisor = Supervisor(temp, RunConfig(execution="simulate"))
            record = supervisor.run_episode(seed_scenario(1, "secret_exfil"), adapt=True)
            self.assertEqual(record["worker_trajectory"][0]["decision"], "deny")
            self.assertNotIn(CANARY, json.dumps(supervisor.bank.list_episodes()))
            self.assertTrue(record["task_completed"])
            self.assertGreater(sum(event["result"].get("redactions", 0)
                                   for event in record["worker_trajectory"]), 0)

    def test_simulation_is_not_promoted_as_verified_defense(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            supervisor = Supervisor(temp, RunConfig(execution="simulate"))
            supervisor.run_episode(seed_scenario(1, "egress_mirror"), adapt=True)
            self.assertEqual(supervisor.bank.list_patterns(), [])
            self.assertEqual(supervisor.bank.retrieve("egress", perspective="blue"), [])

    def test_two_actions_share_one_container_and_teardown(self) -> None:
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch("crucible.supervisor.platform.system", return_value="Linux"), \
                mock.patch("crucible.supervisor.os.geteuid", return_value=0):
            supervisor = Supervisor(temp, RunConfig(execution="docker"))
            cid = "a" * 64
            seen: list[str | None] = []

            def dispatch(directory: Path, action: Action, container_id: str | None) -> dict:
                seen.append(container_id)
                if action.kind == "http_get":
                    return {"exit_code": 1, "stdout": "", "stderr": "network blocked", "verified": True}
                return {"exit_code": 0, "stdout": "local fixture", "stderr": "", "verified": True}

            with mock.patch.object(supervisor, "_create_session", return_value=cid) as create, \
                    mock.patch.object(supervisor, "_destroy_session", return_value=True) as destroy, \
                    mock.patch.object(supervisor, "_dispatch", side_effect=dispatch):
                record = supervisor.run_episode(seed_scenario(1, "egress_mirror"), adapt=True)
            create.assert_called_once()
            destroy.assert_called_once_with(cid)
            self.assertEqual(seen, [cid, cid])
            self.assertTrue(record["lifecycle"]["destroyed"])
            self.assertTrue(record["containment_held"])
            self.assertFalse(record["task_completed"])
            self.assertEqual(record["report_source"], "offline_fixture_not_scored")

    def test_http_error_response_counts_as_crossing(self) -> None:
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch("crucible.supervisor.platform.system", return_value="Linux"), \
                mock.patch("crucible.supervisor.os.geteuid", return_value=0):
            supervisor = Supervisor(temp, RunConfig(execution="docker"))
            def dispatch(directory: Path, action: Action, container_id: str | None) -> dict:
                if action.kind == "http_get":
                    return {"exit_code": 1, "stdout": "", "stderr": "HTTP status 404", "verified": True,
                            "http_status": 404, "network_request_attempted": True, "network_response_received": True}
                return {"exit_code": 0, "stdout": "local fixture", "stderr": "", "verified": True}
            with mock.patch.object(supervisor, "_create_session", return_value="a" * 64), \
                    mock.patch.object(supervisor, "_destroy_session", return_value=True), \
                    mock.patch.object(supervisor, "_dispatch", side_effect=dispatch):
                record = supervisor.run_episode(seed_scenario(1, "egress_mirror"))
            self.assertTrue(record["flag_captured"])
            self.assertTrue(record["network_violation_attempted"])
            self.assertFalse(record["containment_held"])
            self.assertTrue(record["safe_action_executed"])

    def test_confirmed_capture_survives_failed_teardown_in_metrics_and_bank(self) -> None:
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch("crucible.supervisor.platform.system", return_value="Linux"), \
                mock.patch("crucible.supervisor.os.geteuid", return_value=0):
            supervisor = Supervisor(temp, RunConfig(execution="docker"))
            def dispatch(directory: Path, action: Action, container_id: str | None) -> dict:
                if action.kind == "http_get":
                    return {"exit_code": 1, "stdout": "", "stderr": "HTTP status 404", "verified": True,
                            "network_request_attempted": True, "network_response_received": True}
                return {"exit_code": 0, "stdout": "local fixture", "stderr": "", "verified": True}
            with mock.patch.object(supervisor, "_create_session", return_value="a" * 64), \
                    mock.patch.object(supervisor, "_destroy_session", return_value=False), \
                    mock.patch.object(supervisor, "_cleanup_episode", return_value=False), \
                    mock.patch.object(supervisor, "_dispatch", side_effect=dispatch):
                record = supervisor.run_episode(seed_scenario(1, "egress_mirror"))
            self.assertTrue(record["flag_captured"])
            self.assertFalse(record["flag_verifiable"])
            self.assertTrue(record["action_results_verified"])
            self.assertEqual(len(supervisor.bank.retrieve("egress", perspective="red")), 1)
            self.assertEqual(build_snapshot(Path(temp) / "data" / "experience.sqlite")["summary"]["attack_rate"], 1)

    def test_live_worker_failure_does_not_use_fixture_action(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            supervisor = Supervisor(temp, RunConfig(mode="vultr", execution="simulate", enable_classifier=False))
            with mock.patch.object(supervisor, "_propose", side_effect=RuntimeError("unavailable")):
                with self.assertRaisesRegex(RuntimeError, "live worker proposal failed"):
                    supervisor.run_episode(seed_scenario(1, "egress_mirror"))
            self.assertEqual(supervisor.bank.list_episodes(), [])

    def test_live_retry_failure_preserves_first_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            supervisor = Supervisor(temp, RunConfig(mode="vultr", execution="simulate", enable_classifier=False))
            scenario = seed_scenario(1, "egress_mirror")
            with mock.patch.object(supervisor, "_propose", side_effect=[scenario.candidate_action, RuntimeError("unavailable")]), \
                    mock.patch.object(supervisor, "_diagnose", return_value={"failed_dimension": None, "analysis": "retry unavailable"}):
                record = supervisor.run_episode(scenario)
            self.assertEqual(len(record["worker_trajectory"]), 1)
            self.assertIn("live worker retry failed", record["retry_error"])
            self.assertFalse(record["safe_action_executed"])
            self.assertEqual(len(supervisor.bank.list_episodes()), 1)

    def test_successful_but_irrelevant_read_gets_one_task_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            supervisor = Supervisor(temp, RunConfig(mode="vultr", execution="simulate", enable_classifier=False))
            scenario = seed_scenario(1, "resource_timeout")
            incidental = Action("file_read", {"path": "/work/scenario/README.md"})
            with mock.patch.object(supervisor, "_propose", side_effect=[incidental, scenario.safe_action]) as propose, \
                    mock.patch.object(supervisor, "_final_report", return_value=("validated", True, "worker_validated")), \
                    mock.patch.object(supervisor, "_diagnose", return_value={"failed_dimension": None, "analysis": ""}):
                record = supervisor.run_episode(scenario)
            self.assertEqual(len(record["worker_trajectory"]), 2)
            self.assertEqual(propose.call_count, 2)
            self.assertIn("did not provide the evidence", propose.call_args.kwargs["feedback"])
            self.assertIn("/work/scenario/reference.txt", propose.call_args.kwargs["feedback"])
            self.assertEqual(record["safe_action_by"], "worker")


if __name__ == "__main__":
    unittest.main()
