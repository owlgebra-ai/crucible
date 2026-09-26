"""The public export must never copy private episode text into Pages."""

import json
from pathlib import Path
import tempfile
import unittest

from crucible.experience import ExperienceBank
from crucible.public_demo import APPROVED_REPORTS, export, parse_wall_proof, public_snapshot


PRIVATE_PROOF_MARKER = "PRIVATE_PROOF_MARKER_953b2395"


def wall_transcript(runtime="runc"):
    checks = [
        "container ID", "immutable image ID", "read-only rootfs", "no host binds",
        "non-root worker", "no capabilities", f"{runtime} runtime",
        "seccomp profile", "no new privileges", "DNS upstream loopback", "pids limit",
    ]
    lines = [
        "[1/5] Host virtualization",
        "CPU virtualization flag: PRESENT",
        "/dev/kvm read/write: UNAVAILABLE ([Errno 2] No such file or directory)",
        "[2/5] Container and policy probe",
        *(f"{name}: OK" for name in checks),
        "container ID: " + "a" * 64,
        "image ID: sha256:" + "b" * 64,
        f"container runtime: {runtime}",
    ]
    if runtime == "runsc-oci":
        lines.append("runsc-oci runtime: verified (runsc version 20260926.0; "
                     "--oci-seccomp, --network=sandbox, --platform=systrap)")
    lines.extend([
        "Policy bridge: br-crucible (crucible-net, 172.30.99.0/24)",
        "Probe container IPv4: 172.30.99.2",
        json.dumps({"hostname": PRIVATE_PROOF_MARKER,
                    "uname": {"node": PRIVATE_PROOF_MARKER},
                    "direct_egress": "TIMEOUT",
                    "direct_egress_error": PRIVATE_PROOF_MARKER,
                    "allowlisted_tls": "TLSv1.3",
                    "external_dns": "UNRESOLVED",
                    "external_dns_error": PRIVATE_PROOF_MARKER,
                    "ptrace": "BLOCKED"}, sort_keys=True),
        "[3/5] Kernel drop evidence",
        "Direct-IP destination: 1.1.1.1:443",
        "Probe-specific packets immediately before default DROP: 3",
        "Default DROP remains the next and final egress rule",
        "[4/5] Container teardown",
        "No container remains for proof-" + "c" * 16,
        "[5/5] Wall proof complete",
    ])
    return "\n".join(lines) + "\n"


class PublicDemoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / "bank.sqlite"
        self.site = self.root / "site"

    def tearDown(self):
        self.temp.cleanup()

    def test_closed_schema_drops_all_free_form_text(self):
        secret = "UNKNOWN_SECRET_8ef145e51"
        source = {
            "summary": {"total": 1, "docker": 1, "simulated": 0,
                        "unverified_docker": 0, "attack_rate": 0,
                        "safe_rate": 1, "fixture_rate": 0,
                        "extra": secret},
            "curves": [{"episode": 1, "round": 1, "attack_rate": 0,
                        "safe_rate": 1, "host_ip": secret}],
            "events": [{"round": 1, "action": "http_get", "detail": secret,
                        "decision": "deny", "dimension": "d6_output_filter_v1",
                        "reason": secret, "mode": "docker", "exit_code": None,
                        "url": "https://example.com/?key=" + secret}],
            "patterns": [{"pattern_id": secret, "attack_shape": "secret_exfil",
                          "dimension": "D6", "recommended_defense": secret,
                          "supporting_count": 1}],
            "latest_report": {"text": secret, "episode_id": secret,
                              "mode": "docker"},
            "wall_proof": {"raw_transcript": secret},
            "extra": secret,
        }
        result = public_snapshot(source)
        body = json.dumps(result)
        self.assertNotIn(secret, body)
        self.assertEqual(result["events"][0]["dimension"], "D6 output filter")
        self.assertEqual(result["events"][0]["detail"], "")
        self.assertEqual(result["patterns"][0]["recommended_defense"], "Outbound secret scan")
        self.assertEqual(result["summary"]["model_live"], 0)
        self.assertEqual(result["summary"]["probe_live"], 0)
        self.assertIsNone(result["latest_report"])

    def test_export_has_no_unknown_secret_even_when_bank_contains_it(self):
        secret = "UNKNOWN_SECRET_5d9ec45a"
        bank = ExperienceBank(self.db)
        bank.add_episode({
            "episode_id": "episode_" + secret, "round": 1,
            "attack_shape": "secret_exfil", "flag_captured": False,
            "flag_verifiable": True, "action_results_verified": True,
            "safe_action_executed": True,
            "task_completed": True, "containment_held": True,
            "execution_mode": "docker", "final_report": secret,
            "worker_trajectory": [{"action": {"kind": "http_get",
                                               "payload": {"url": "https://example.com/" + secret}},
                                   "decision": "deny", "by": secret,
                                   "reason": secret, "result": {"exit_code": None, "verified": True}},
                                  {"action": {"kind": "file_read", "payload": {"path": "/work/scenario/reference.txt"}},
                                   "decision": "allow", "by": "stack",
                                   "result": {"exit_code": 0, "verified": True}}],
            "boundary_verdicts": [],
            "blue_action": {"plugin_id": secret},
        })
        summary = export(self.db, self.site, require_docker=True)
        self.assertEqual(summary["docker"], 1)
        html = (self.site / "index.html").read_text()
        body = (self.site / "snapshot.json").read_text()
        self.assertNotIn(secret, html + body)
        self.assertNotIn("/api/snapshot", html)
        self.assertIn("./snapshot.json", html)
        self.assertIn("Content-Security-Policy", html)
        self.assertEqual(json.loads(body)["patterns"][0]["attack_shape"],
                         "Secret in outbound request")

    def test_only_exact_approved_report_is_public(self):
        report = sorted(APPROVED_REPORTS)[0]
        result = public_snapshot({"latest_report": {"text": report,
                                                    "mode": "docker",
                                                    "episode_id": "private-id"}})
        self.assertEqual(result["latest_report"]["text"], report)
        self.assertNotIn("private-id", json.dumps(result))

    def test_pages_gate_rejects_simulation_only(self):
        bank = ExperienceBank(self.db)
        bank.add_episode({"episode_id": "sim", "round": 1,
                          "attack_shape": "egress", "flag_captured": False,
                          "safe_action_executed": True, "execution_mode": "simulate"})
        with self.assertRaisesRegex(ValueError, "requires at least one verified container-backed"):
            export(self.db, self.site, require_live=True)
        self.assertFalse(self.site.exists())

    def test_remote_mode_is_distinct_and_satisfies_verified_live_gate(self):
        bank = ExperienceBank(self.db)
        bank.add_episode({
            "episode_id": "unverified_remote", "round": 1, "attack_shape": "egress",
            "flag_captured": False, "flag_verifiable": True,
            "action_results_verified": False,
            "safe_action_executed": False, "execution_mode": "remote",
        })
        with self.assertRaisesRegex(ValueError, "requires at least one verified container-backed"):
            export(self.db, self.site, require_live=True)
        self.assertFalse(self.site.exists())
        bank.add_episode({
            "episode_id": "verified_remote", "round": 2, "attack_shape": "egress",
            "flag_captured": False, "flag_verifiable": True,
            "action_results_verified": True, "safe_action_executed": True,
            "task_completed": True, "containment_held": True,
            "execution_mode": "remote", "final_report": sorted(APPROVED_REPORTS)[0],
            "worker_trajectory": [{"action": {"kind": "file_read", "payload": {"path": "/work/scenario/reference.txt"}},
                                   "decision": "allow", "by": "stack",
                                   "result": {"exit_code": 0, "verified": True}}],
            "boundary_verdicts": [],
        })
        proof = self.root / "wall-proof.txt"
        proof.write_text(wall_transcript())
        summary = export(self.db, self.site, require_live=True,
                         wall_proof_path=proof, wall_runtime="runc",
                         require_wall_proof=True)
        self.assertEqual(summary["docker"], 0)
        self.assertEqual(summary["remote"], 2)
        self.assertEqual(summary["live"], 2)
        self.assertEqual(summary["verified_live"], 1)
        self.assertEqual(summary["unverified_remote"], 1)
        snapshot = json.loads((self.site / "snapshot.json").read_text())
        self.assertEqual(snapshot["events"][0]["mode"], "remote")
        self.assertEqual(snapshot["latest_report"]["mode"], "remote")
        html = (self.site / "index.html").read_text()
        self.assertIn("same-host Docker", html)
        self.assertIn("remote sandbox VM", html)
        self.assertNotIn("cumulative Docker runs", html)
        # The compatibility flag accepts the same verified remote record.
        export(self.db, self.site, require_docker=True,
               wall_proof_path=proof, wall_runtime="runc", require_wall_proof=True)

    def test_output_symlinks_are_rejected(self):
        ExperienceBank(self.db)
        self.site.mkdir()
        (self.site / "index.html").symlink_to(self.db)
        with self.assertRaisesRegex(ValueError, "cannot be a symlink"):
            export(self.db, self.site)

    def test_wall_proof_summary_excludes_private_transcript_fields(self):
        for runtime in ("runc", "runsc-oci"):
            with self.subTest(runtime=runtime):
                result = parse_wall_proof(wall_transcript(runtime),
                                          expected_runtime=runtime)
                self.assertEqual(result["status"], "checks_passed")
                self.assertEqual(result["runtime"], runtime)
                self.assertEqual(result["drop_packets"], 3)
                self.assertTrue(result["direct_ip_drop"])
                body = json.dumps(result)
                for private in (PRIVATE_PROOF_MARKER, "172.30.99.2", "1.1.1.1",
                                "a" * 64, "b" * 64, "c" * 16, "20260926.0"):
                    self.assertNotIn(private, body)

    def test_wall_proof_rejects_missing_failed_or_conflicting_checks(self):
        valid = wall_transcript()
        failures = [
            valid.replace("seccomp profile: OK\n", ""),
            valid.replace("seccomp profile: OK", "seccomp profile: FAILED"),
            valid.replace("seccomp profile: OK", "seccomp profile: OK\nseccomp profile: FAILED"),
            valid.replace('"direct_egress": "TIMEOUT"', '"direct_egress": "LEAK"'),
            valid.replace('"direct_egress": "TIMEOUT"',
                          '"direct_egress": "LEAK", "direct_egress": "TIMEOUT"'),
            valid.replace('"allowlisted_tls": "TLSv1.3"', '"allowlisted_tls": "FAILED"'),
            valid.replace('"external_dns": "UNRESOLVED"', '"external_dns": "LEAK"'),
            valid.replace('"ptrace": "BLOCKED"', '"ptrace": "FAILED"'),
            valid.replace("default DROP: 3", "default DROP: 0"),
            valid.replace("Default DROP remains the next and final egress rule\n", ""),
            valid.replace("Probe container IPv4: 172.30.99.2",
                          "Probe container IPv4: 192.0.2.2"),
            valid.replace("No container remains for proof-" + "c" * 16 + "\n", ""),
            valid.replace("[5/5] Wall proof complete\n", ""),
            valid + valid,
            valid + "UNVERIFIED: later failure\n",
        ]
        for index, transcript in enumerate(failures):
            with self.subTest(case=index):
                with self.assertRaisesRegex(ValueError, "incomplete or failed"):
                    parse_wall_proof(transcript, expected_runtime="runc")
        runsc = wall_transcript("runsc-oci")
        missing_attestation = runsc.replace(
            "runsc-oci runtime: verified (runsc version 20260926.0; "
            "--oci-seccomp, --network=sandbox, --platform=systrap)\n", "")
        with self.assertRaisesRegex(ValueError, "incomplete or failed"):
            parse_wall_proof(missing_attestation, expected_runtime="runsc-oci")
        with self.assertRaisesRegex(ValueError, "incomplete or failed"):
            parse_wall_proof(runsc, expected_runtime="runc")

    def test_pages_gate_requires_wall_proof_and_docker_episode(self):
        ExperienceBank(self.db).add_episode({
            "episode_id": "ep_1", "round": 1, "attack_shape": "egress",
            "flag_captured": False, "flag_verifiable": True,
            "action_results_verified": True, "safe_action_executed": True,
            "execution_mode": "docker",
            "worker_trajectory": [{"action": {"kind": "file_read", "payload": {"path": "/work/scenario/reference.txt"}},
                                   "decision": "allow", "by": "stack",
                                   "result": {"exit_code": 0, "verified": True}}],
        })
        with self.assertRaisesRegex(ValueError, "requires a wall proof"):
            export(self.db, self.site, require_docker=True, require_wall_proof=True)
        self.assertFalse(self.site.exists())
        private_proof = self.root / "wall-proof.txt"
        private_proof.write_text(wall_transcript())
        with self.assertRaisesRegex(ValueError, "explicit runc or runsc-oci"):
            export(self.db, self.site, require_docker=True,
                   wall_proof_path=private_proof, require_wall_proof=True)
        summary = export(self.db, self.site, require_docker=True,
                         wall_proof_path=private_proof, wall_runtime="runc",
                         require_wall_proof=True)
        self.assertEqual(summary["docker"], 1)
        body = (self.site / "snapshot.json").read_text()
        html = (self.site / "index.html").read_text()
        self.assertEqual(json.loads(body)["wall_proof"]["drop_packets"], 3)
        self.assertIn("VM wall transcript", html)
        self.assertIn("Transcript checks passed", html)
        self.assertNotIn(PRIVATE_PROOF_MARKER, body + html)

    def test_failed_proof_does_not_replace_existing_pages_files(self):
        ExperienceBank(self.db)
        self.site.mkdir()
        (self.site / "index.html").write_text("previous page")
        (self.site / "snapshot.json").write_text("previous snapshot")
        proof = self.root / "failed-proof.txt"
        proof.write_text(wall_transcript().replace("default DROP: 3", "default DROP: 0"))
        with self.assertRaisesRegex(ValueError, "incomplete or failed"):
            export(self.db, self.site, wall_proof_path=proof,
                   wall_runtime="runc", require_wall_proof=True)
        self.assertEqual((self.site / "index.html").read_text(), "previous page")
        self.assertEqual((self.site / "snapshot.json").read_text(), "previous snapshot")


if __name__ == "__main__":
    unittest.main()
