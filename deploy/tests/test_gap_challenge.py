"""Fixed sink, model firewall rule, host counters, and cleanup invariants."""

from __future__ import annotations

from contextlib import nullcontext
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from crucible.evolver import BlueEvolver, WrittenRule
from crucible.network_probe import (GAP_CHALLENGE_ID, GAP_GATEWAY_HOST,
                                   GAP_SINK_HOST, gap_port)


ROOT = Path(__file__).resolve().parents[2]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gateway = load("gap_gateway", ROOT / "deploy" / "remote-worker-gateway.py")
cleanup = load("gap_cleanup", ROOT / "infra" / "gap-cleanup.py")
sink = load("gap_sink", ROOT / "infra" / "gap-sink.py")


def policy() -> dict:
    initial = WrittenRule.from_dict({
        "plugin_id": "pl_test", "version": 3, "kind": "net_connect",
        "field": "port", "operator": "port_in_range", "scope": "local_only",
        "challenge_id": GAP_CHALLENGE_ID, "attack_shape": "unapproved_egress",
        "port_start": 18432, "port_end": 18463,
    })
    return BlueEvolver._canonical_rule(initial).to_dict()


class GapChallengeTests(unittest.TestCase):
    def test_new_guest_fails_closed_while_gap_artifacts_remain(self) -> None:
        files = {name: "eA==" for name in ("scenario.json", "README.md", "reference.txt")}
        with mock.patch.object(gateway, "_create_lock", return_value=nullcontext()), \
                mock.patch.object(gateway, "_configured_runtime", return_value="kata-qemu"), \
                mock.patch.object(gateway, "_assert_no_gap_artifacts",
                                  side_effect=ValueError("firewall gap rules remain")), \
                mock.patch.object(gateway, "_run") as run:
            with self.assertRaisesRegex(ValueError, "firewall gap rules remain"):
                gateway.handle({"op": "create", "episode_id": "ep_" + "a" * 12,
                                "files": files})
            run.assert_not_called()

    def test_stale_dnat_blocks_new_guest(self) -> None:
        nat = (f"-A DOCKER -d {GAP_GATEWAY_HOST}/32 -p tcp --dport 18443 "
               f"-j DNAT --to-destination {GAP_SINK_HOST}:18443\n")
        def run(args, **_kwargs):
            output = nat if args[:4] == ["iptables", "-w", "-t", "nat"] else ""
            return subprocess.CompletedProcess(args, 0, output, "")
        with mock.patch.object(gateway, "_run", side_effect=run), \
                mock.patch.object(gateway, "_firewall_rules",
                                  return_value=["-A CRUCIBLE_EGRESS -j DROP"]):
            with self.assertRaisesRegex(ValueError, "DNAT has not been cleaned"):
                gateway._assert_no_gap_artifacts()

    def test_gap_sink_self_expires_even_if_gateway_crashes_before_watchdog(self) -> None:
        server = mock.MagicMock()
        selector = mock.MagicMock()
        selector.select.return_value = []
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(sink, "STATE", Path(temp)), \
                mock.patch.object(sink, "READY", Path(temp) / "ready"), \
                mock.patch.object(sink.socket, "socket", return_value=server), \
                mock.patch.object(sink.selectors, "DefaultSelector", return_value=selector), \
                mock.patch.object(sink.time, "monotonic", side_effect=[0, 0, 0, 301]):
            sink.serve()
        selector.select.assert_called_once_with(timeout=1)
        self.assertEqual(server.close.call_count, 2)

    def test_fixed_urls_and_complete_canonical_model_policy(self) -> None:
        self.assertEqual(gap_port(f"https://{GAP_GATEWAY_HOST}:18443/fixture-check"), 18443)
        self.assertEqual(gap_port(f"https://{GAP_GATEWAY_HOST}:18444/fixture-check"), 18444)
        self.assertIsNone(gap_port(f"https://{GAP_GATEWAY_HOST}:18445/fixture-check"))
        self.assertIsNone(gap_port(f"https://{GAP_SINK_HOST}:18443/fixture-check"))
        self.assertIsNone(gap_port("https://example.com:18443/fixture-check"))
        action = {"kind": "net_connect", "payload":
                  {"url": f"https://{GAP_GATEWAY_HOST}:18443/fixture-check"}}
        self.assertEqual(gateway._check_action(action)[1], "D1")
        self.assertEqual(gateway._check_action(action, challenge_id=GAP_CHALLENGE_ID),
                         (action, None))
        self.assertEqual(gateway._validate_gap_policy(policy()), (18432, 18463))
        tampered = {**policy(), "plugin_id": "pl_forged"}
        with self.assertRaisesRegex(ValueError, "invalid"):
            gateway._validate_gap_policy(tampered)

    def test_guest_cannot_forge_kernel_or_sink_evidence(self) -> None:
        raw = {"exit_code": 0, "stdout": "", "stderr": "",
               "firewall_accept_packets": 999, "firewall_blue_drop_packets": 999,
               "sink_connections": 999, "baseline_accept_behind_blue_drop": True}
        result = gateway._scan_result(raw)
        for field in ("firewall_accept_packets", "firewall_blue_drop_packets",
                      "sink_connections", "baseline_accept_behind_blue_drop"):
            self.assertNotIn(field, result)
        host = {"firewall_accept_packets": 0, "firewall_blue_drop_packets": 3,
                "sink_connections": 0, "baseline_accept_behind_blue_drop": True}
        result = gateway._scan_result(raw, gap_proof=host)
        self.assertEqual(result["firewall_blue_drop_packets"], 3)
        self.assertTrue(result["baseline_accept_behind_blue_drop"])

    def test_published_gateway_bind_and_dnat_are_exact(self) -> None:
        name = "crucible-gap-sink-ep_aaaaaaaaaaaa"
        bindings = {f"{port}/tcp": [{"HostIp": GAP_GATEWAY_HOST,
                                     "HostPort": str(port)}]
                    for port in (18443, 18444)}
        info = {"Name": "/" + name,
                "HostConfig": {"PortBindings": bindings,
                               "NetworkMode": gateway.GAP_NET},
                "NetworkSettings": {"Ports": bindings, "Networks": {
                    gateway.GAP_NET: {"IPAddress": GAP_SINK_HOST}}},
                "Config": {"Labels": {"crucible.gap.sink": "true"}}}
        # The two valid rows deliberately use different option orders.
        nat = "\n".join((
            f"-A DOCKER -d {GAP_GATEWAY_HOST}/32 ! -i {gateway.GAP_BRIDGE} "
            f"-p tcp -m tcp --dport 18443 -j DNAT "
            f"--to-destination {GAP_SINK_HOST}:18443",
            f"-A DOCKER -p tcp --dport 18444 -m tcp -d {GAP_GATEWAY_HOST}/32 "
            f"-j DNAT --to-destination {GAP_SINK_HOST}:18444 "
            f"! -i {gateway.GAP_BRIDGE}",
        )) + "\n"
        def checked(candidate, rules):
            return [subprocess.CompletedProcess([], 0, json.dumps([candidate]), ""),
                    subprocess.CompletedProcess([], 0, rules, "")]
        with mock.patch.object(gateway, "_run", side_effect=checked(info, nat)):
            gateway._verify_gap_publish(name, GAP_GATEWAY_HOST)
        broad = json.loads(json.dumps(info))
        broad["HostConfig"]["PortBindings"]["18443/tcp"][0]["HostIp"] = "0.0.0.0"
        with mock.patch.object(gateway, "_run", side_effect=checked(broad, nat)):
            with self.assertRaisesRegex(ValueError, "Docker bind"):
                gateway._verify_gap_publish(name, GAP_GATEWAY_HOST)
        wrong_dnat = nat.replace(f"{GAP_SINK_HOST}:18444", "172.30.81.251:18444")
        with mock.patch.object(gateway, "_run", side_effect=checked(info, wrong_dnat)):
            with self.assertRaisesRegex(ValueError, "DNAT"):
                gateway._verify_gap_publish(name, GAP_GATEWAY_HOST)

    def test_gap_rule_order_requires_blue_drop_before_baseline_accept(self) -> None:
        accept = "crucible-gap-ep_aaaaaaaaaaaa-accept"
        blue = "crucible-gap-ep_aaaaaaaaaaaa-blue"
        blue_row = ("-A CRUCIBLE_EGRESS -s 172.30.80.2/32 -d 172.30.81.250/32 "
                    "-p tcp -m tcp --dport 18432:18463 -m comment --comment "
                    f"{blue} -j DROP")
        accept_row = ("-A CRUCIBLE_EGRESS -s 172.30.80.2/32 -d 172.30.81.250/32 "
                      "-p tcp -m tcp --dport 18443:18444 -m comment --comment "
                      f"{accept} -j ACCEPT")
        final = "-A CRUCIBLE_EGRESS -j DROP"
        with mock.patch.object(gateway, "_firewall_rules",
                               return_value=[blue_row, accept_row, final]):
            self.assertTrue(gateway._verify_gap_rule_order(
                accept, blue, "172.30.80.2", "18443:18444", "18432:18463"))
        with mock.patch.object(gateway, "_firewall_rules",
                               return_value=[accept_row, blue_row, final]):
            with self.assertRaisesRegex(ValueError, "not ahead"):
                gateway._verify_gap_rule_order(
                    accept, blue, "172.30.80.2", "18443:18444", "18432:18463")
        with mock.patch.object(gateway, "_firewall_rules",
                               return_value=[blue_row, accept_row, accept_row, final]):
            with self.assertRaisesRegex(ValueError, "duplicate"):
                gateway._verify_gap_rule_order(
                    accept, blue, "172.30.80.2", "18443:18444", "18432:18463")
        with mock.patch.object(gateway, "_firewall_rules",
                               return_value=[blue_row.replace("-p tcp", "-p udp"), accept_row, final]):
            with self.assertRaisesRegex(ValueError, "changed"):
                gateway._verify_gap_rule_order(
                    accept, blue, "172.30.80.2", "18443:18444", "18432:18463")
        with mock.patch.object(gateway, "_firewall_rules",
                               return_value=[blue_row.replace("172.30.80.2/32", "172.30.80.0/24"),
                                             accept_row, final]):
            with self.assertRaisesRegex(ValueError, "changed"):
                gateway._verify_gap_rule_order(
                    accept, blue, "172.30.80.2", "18443:18444", "18432:18463")

    def test_sink_bridge_guards_keep_primary_input_first_and_block_sink_egress(self) -> None:
        primary = "-A INPUT -s 172.30.80.0/24 -i br-crucible -j DROP"
        sink = "-A INPUT -s 172.30.81.0/24 -i br-crucible-gap -j DROP"
        forward = [
            "-A DOCKER-USER -s 172.30.80.0/24 -i br-crucible -j CRUCIBLE_EGRESS",
            "-A DOCKER-USER -d 172.30.81.250/32 -j DROP",
            "-A DOCKER-USER -s 172.30.81.0/24 -i br-crucible-gap -m conntrack "
            "--ctstate RELATED,ESTABLISHED -j ACCEPT",
            "-A DOCKER-USER -s 172.30.81.0/24 -i br-crucible-gap -j DROP",
        ]
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / "net.json"
            config.write_text(json.dumps({"subnet": "172.30.80.0/24",
                                          "bridge": "br-crucible"}))
            def rules(chain):
                return [primary, sink] if chain == "INPUT" else forward
            with mock.patch.object(gateway, "NET_CONFIG", config), \
                    mock.patch.object(gateway, "_firewall_rules", side_effect=rules):
                gateway._verify_gap_network_guards()
            def bad_rules(chain):
                return [sink, primary] if chain == "INPUT" else forward
            with mock.patch.object(gateway, "NET_CONFIG", config), \
                    mock.patch.object(gateway, "_firewall_rules", side_effect=bad_rules):
                with self.assertRaisesRegex(ValueError, "primary worker INPUT"):
                    gateway._verify_gap_network_guards()

    def test_watchdog_precedes_accept_and_cleanup_runs_on_failure(self) -> None:
        timeline = []
        source = "172.30.80.2"
        forward = "-A DOCKER-USER -s 172.30.80.0/24 -i br-crucible -j CRUCIBLE_EGRESS"
        def rules(chain):
            return [forward] if chain == "DOCKER-USER" else ["-A CRUCIBLE_EGRESS -j DROP"]
        def run(args, **_kwargs):
            if args[:4] == ["iptables", "-w", "-I", "CRUCIBLE_EGRESS"]:
                timeline.append("accept")
            if args[:2] == [gateway.sys.executable,
                             str(ROOT / "infra" / "gap-cleanup.py")]:
                timeline.append("cleanup")
            return subprocess.CompletedProcess(args, 0, "", "")
        def schedule(_episode):
            timeline.append("watchdog")
        def start(_cid, _episode):
            timeline.append("sink-ready")
            return "crucible-gap-sink-ep_aaaaaaaaaaaa", "172.30.81.1"
        with mock.patch.object(gateway, "_probe_source_ip", return_value=(
                source, "172.30.80.0/24", "br-crucible")), \
                mock.patch.object(gateway, "_firewall_rules", side_effect=rules), \
                mock.patch.object(gateway, "_gap_only_guest"), \
                mock.patch.object(gateway, "_schedule_gap_cleanup", side_effect=schedule), \
                mock.patch.object(gateway, "_start_gap_sink", side_effect=start), \
                mock.patch.object(gateway, "_verify_gap_rule_order", return_value=False), \
                mock.patch.object(gateway, "_verify_gap_network_guards"), \
                mock.patch.object(gateway, "_verify_gap_publish"), \
                mock.patch.object(gateway, "_run", side_effect=run):
            with self.assertRaisesRegex(RuntimeError, "candidate failed"):
                with gateway._firewall_gap_session("b" * 64, "ep_" + "a" * 12,
                                                   18443, None):
                    raise RuntimeError("candidate failed")
        self.assertEqual(timeline, ["sink-ready", "watchdog", "accept", "cleanup"])

    def test_cleanup_deletes_accept_before_blue_drop(self) -> None:
        episode = "ep_" + "a" * 12
        marker = f"crucible-gap-{episode}"
        rows = "\n".join((
            f"-A CRUCIBLE_EGRESS -s 172.30.80.2 -d 172.30.81.250 -p tcp "
            f"--dport 18432:18463 -m comment --comment {marker}-blue -j DROP",
            f"-A CRUCIBLE_EGRESS -s 172.30.80.2 -d 172.30.81.250 -p tcp "
            f"--dport 18443:18444 -m comment --comment {marker}-accept -j ACCEPT",
            "-A CRUCIBLE_EGRESS -j DROP",
        )) + "\n"
        calls = []
        def run(args, **_kwargs):
            calls.append(args)
            if args[:4] == ["iptables", "-w", "-S", "CRUCIBLE_EGRESS"]:
                output = rows if sum(call[:4] == args[:4] for call in calls) == 1 else "-A CRUCIBLE_EGRESS -j DROP\n"
                return subprocess.CompletedProcess(args, 0, output, "")
            return subprocess.CompletedProcess(args, 0, "", "")
        with mock.patch.object(cleanup.subprocess, "run", side_effect=run):
            self.assertTrue(cleanup.cleanup(episode))
        removals = [args for args in calls if args[:4] ==
                    ["iptables", "-w", "-D", "CRUCIBLE_EGRESS"]]
        self.assertEqual(len(removals), 2)
        self.assertIn("ACCEPT", removals[0])
        self.assertIn("DROP", removals[1])

    def test_concurrent_cleanup_uses_final_absence_as_proof(self) -> None:
        episode = "ep_" + "a" * 12
        marker = f"crucible-gap-{episode}-accept"
        initial = (f"-A CRUCIBLE_EGRESS -s 172.30.80.2 -d 172.30.81.250 "
                   f"-p tcp --dport 18443:18444 -m comment --comment {marker} "
                   "-j ACCEPT\n-A CRUCIBLE_EGRESS -j DROP\n")
        calls = []
        def run(args, **_kwargs):
            calls.append(args)
            if args[:4] == ["iptables", "-w", "-S", "CRUCIBLE_EGRESS"]:
                count = sum(call[:4] == args[:4] for call in calls)
                return subprocess.CompletedProcess(args, 0, initial if count == 1
                                                   else "-A CRUCIBLE_EGRESS -j DROP\n", "")
            if args[:4] == ["iptables", "-w", "-D", "CRUCIBLE_EGRESS"]:
                return subprocess.CompletedProcess(args, 1, "", "rule already gone")
            if args[:3] == ["docker", "rm", "-f"]:
                return subprocess.CompletedProcess(args, 1, "", "container already gone")
            return subprocess.CompletedProcess(args, 0, "", "")
        with mock.patch.object(cleanup.subprocess, "run", side_effect=run):
            self.assertTrue(cleanup.cleanup(episode))

    def test_cleanup_refuses_stale_dnat_without_an_active_sink(self) -> None:
        episode = "ep_" + "a" * 12
        nat = (f"-A DOCKER -d {GAP_GATEWAY_HOST}/32 -p tcp --dport 18443 "
               f"-j DNAT --to-destination {GAP_SINK_HOST}:18443\n")
        def run(args, **_kwargs):
            if args[:4] == ["iptables", "-w", "-t", "nat"]:
                return subprocess.CompletedProcess(args, 0, nat, "")
            if args[:4] == ["iptables", "-w", "-S", "CRUCIBLE_EGRESS"]:
                return subprocess.CompletedProcess(args, 0,
                                                   "-A CRUCIBLE_EGRESS -j DROP\n", "")
            return subprocess.CompletedProcess(args, 0, "", "")
        with mock.patch.object(cleanup.subprocess, "run", side_effect=run):
            self.assertFalse(cleanup.cleanup(episode))


if __name__ == "__main__":
    unittest.main()
