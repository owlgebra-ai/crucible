"""Worker-side D6 checks at the JSON output boundary."""

from __future__ import annotations

from base64 import b64encode
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from crucible import worker
from crucible.network_probe import PROBE_URLS, probe_host
from crucible.scenarios import CANARY, seed_scenario
from crucible.secret_scan import DEMO_CANARY


class WorkerOutputTests(unittest.TestCase):
    def _run_main(self, action: dict, root: Path) -> tuple[str, dict]:
        output = io.StringIO()
        source = io.TextIOWrapper(io.BytesIO(json.dumps(action).encode()))
        with (mock.patch.object(worker, "WORK", root),
              mock.patch.object(worker.sys, "argv", ["worker", "--action-file", "-"]),
              mock.patch.object(worker.sys, "stdin", source),
              redirect_stdout(output)):
            self.assertEqual(worker.main(), 0)
        wire = output.getvalue()
        return wire, json.loads(wire)

    def test_file_result_is_scanned_before_worker_stdout(self) -> None:
        self.assertEqual(CANARY, DEMO_CANARY)
        encoded = b64encode(CANARY.encode()).decode()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "service.env").write_text(
                f"DEMO_LICENSE_KEY={CANARY}\nencoded={encoded}\n"
                "OPENAI_API_KEY=examplelongsecretvalue\n")
            wire, result = self._run_main(
                {"kind": "file_read", "payload": {"path": "service.env"}}, root)
        self.assertNotIn(CANARY, wire)
        self.assertNotIn(encoded, wire)
        self.assertNotIn("examplelongsecretvalue", wire)
        self.assertIn("DEMO_LICENSE_KEY=[REDACTED-CANARY]", result["stdout"])
        self.assertGreaterEqual(result["redactions"], 3)
        self.assertTrue(result["output_blocked"])
        self.assertIsNotNone(seed_scenario(1, "secret_exfil").report_from_claim(
            {"license_present": True, "credential_disclosed": False}, result["stdout"]))

    def test_exception_text_never_reaches_worker_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wire, result = self._run_main(
                {"kind": CANARY, "payload": {}}, Path(directory))
        self.assertNotIn(CANARY, wire)
        self.assertEqual(result["stderr"], "worker action failed")
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(worker, "execute", side_effect=worker.PolicyDenied(
                    "D3", f"blocked {CANARY}")):
                wire, result = self._run_main(
                    {"kind": "shell", "payload": {"cmd": "pwd"}}, Path(directory))
        self.assertNotIn(CANARY, wire)
        self.assertEqual(result["stderr"], "worker policy denied")
        self.assertEqual(result["policy_denial"], "D3")

    def test_output_is_bounded_after_scanning(self) -> None:
        result = worker.sanitize_result({"exit_code": 0,
            "stdout": "x" * worker.MAX_OUTPUT + CANARY,
            "stderr": "Bearer abcdefghijklmnopqrstuvwxyz"})
        self.assertEqual(len(result["stdout"]), worker.MAX_OUTPUT)
        self.assertNotIn(CANARY, json.dumps(result))
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", json.dumps(result))
        self.assertTrue(result["truncated"])
        self.assertEqual(result["redactions"], 2)

    def test_file_canary_crossing_output_limit_is_scanned(self) -> None:
        encoded = b64encode(CANARY.encode()).decode()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "large.txt").write_text("x" * (worker.MAX_OUTPUT - 5) + encoded)
            wire, result = self._run_main(
                {"kind": "file_read", "payload": {"path": "large.txt"}}, root)
        self.assertNotIn(encoded[:20], wire)
        self.assertLessEqual(len(result["stdout"]), worker.MAX_OUTPUT)
        self.assertTrue(result["truncated"])
        self.assertTrue(result["output_blocked"])

    def test_fixed_network_probe_uses_no_dns_or_application_payload(self) -> None:
        self.assertEqual(probe_host("https://203.0.113.10:443/fixture-check"), "203.0.113.10")
        self.assertIsNone(probe_host("https://203.0.113.12:443/fixture-check"))
        self.assertIsNone(probe_host("https://203.0.113.10:443/fixture-check?key=secret"))
        self.assertEqual(len(PROBE_URLS), 2)
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        connection.connect.side_effect = TimeoutError()
        with mock.patch.object(worker.socket, "socket", return_value=connection) as factory:
            result = worker.execute({"kind": "net_connect", "payload":
                {"url": "https://203.0.113.10:443/fixture-check"}})
        factory.assert_called_once_with(worker.socket.AF_INET, worker.socket.SOCK_STREAM)
        connection.connect.assert_called_once_with(("203.0.113.10", 443))
        connection.send.assert_not_called()
        connection.sendall.assert_not_called()
        self.assertTrue(result["network_request_attempted"])
        self.assertFalse(result["network_response_received"])
        with self.assertRaises(worker.PolicyDenied) as denied:
            worker.execute({"kind": "net_connect", "payload":
                {"url": "https://203.0.113.12:443/fixture-check"}})
        self.assertEqual(denied.exception.dimension, "D1")


if __name__ == "__main__":
    unittest.main()
