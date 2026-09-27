"""The diagnostic exception is an explicit control-plane capability."""

from pathlib import Path
import unittest
from unittest import mock

from crucible.remote import RemoteConfig, RemoteWorkerClient


class RemoteChallengeTests(unittest.TestCase):
    def setUp(self) -> None:
        config = RemoteConfig("root@10.0.0.2", Path("/unused/identity"), Path("/unused/hosts"))
        self.client = RemoteWorkerClient(config)
        self.cid = "a" * 64
        self.episode = "ep_" + "b" * 12
        self.action = {"kind": "net_connect", "payload": {
            "url": "https://203.0.113.10:443/fixture-check"}}

    def test_challenge_is_separate_from_candidate_action(self) -> None:
        with mock.patch.object(self.client, "_call", return_value={"result": {"exit_code": 0}}) as call:
            self.client.execute(self.cid, self.episode, self.action,
                                challenge_id="egress_probe_v1")
        request = call.call_args.args[0]
        self.assertEqual(request["challenge_id"], "egress_probe_v1")
        self.assertEqual(request["action"], self.action)
        self.assertNotIn("challenge_id", request["action"])

    def test_unrecognized_challenge_is_rejected_before_transport(self) -> None:
        with mock.patch.object(self.client, "_call") as call:
            with self.assertRaisesRegex(ValueError, "challenge"):
                self.client.execute(self.cid, self.episode, self.action,
                                    challenge_id="anything_else")
        call.assert_not_called()


if __name__ == "__main__":
    unittest.main()
