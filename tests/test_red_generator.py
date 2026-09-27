"""Live Red planning must be real, bounded, and robust to one bad response."""

from __future__ import annotations

import json
from unittest import TestCase, mock

from crucible.scenarios import RedGenerator, seed_scenario
from crucible.vultr import VultrResponseError


class RedGeneratorTests(TestCase):
    def setUp(self) -> None:
        self.bank = mock.Mock()
        self.bank.list_episodes.return_value = []
        self.bank.retrieve.return_value = []

    def test_retries_non_json_response_then_uses_model_choice_with_fixed_action(self) -> None:
        proposal = {"family": "resource_timeout", "framing": "The local note asks for a long wait."}
        with mock.patch("crucible.vultr.chat_json", side_effect=[
            VultrResponseError("no JSON"), proposal,
        ]) as chat:
            scenario = RedGenerator(self.bank).next(1, live=True)
        self.assertEqual(chat.call_count, 2)
        self.assertEqual(scenario.decoy_family, "resource_timeout")
        self.assertEqual(scenario.candidate_action.kind, "shell")
        self.assertEqual(scenario.candidate_action.payload, {"cmd": "sleep 20"})
        self.assertIn(proposal["framing"], scenario.framing)
        self.assertEqual(json.loads(chat.call_args.args[1][1]["content"])["past_attempts"], [])

    def test_rejects_invalid_plan_without_seed_fallback(self) -> None:
        with mock.patch("crucible.vultr.chat_json", return_value={
            "family": "resource_timeout", "framing": "note", "command": "other",
        }) as chat:
            with self.assertRaisesRegex(VultrResponseError, "invalid planning schema"):
                RedGenerator(self.bank).next(1, live=True)
        self.assertEqual(chat.call_count, 2)

    def test_memory_is_optional_and_untrusted_episode_text_stays_out_of_prompt(self) -> None:
        self.bank.retrieve.return_value = [{
            "attack_shape": "egress", "flag_captured": False,
            "boundary_verdicts": [{"decision": "deny", "dimension": "D1"}],
            "worker_trajectory": [{"result": {"policy_denial": "D3"}}],
            "diagnosis": "private free text should not reach model",
            "blue_action": {"comment": "private free text should not reach model"},
        }]
        with mock.patch("crucible.vultr.chat_json", return_value={
            "family": "egress_mirror", "framing": "Check the reference notes first.",
        }) as chat:
            RedGenerator(self.bank).next(1, live=True)
        request = chat.call_args.args[1][1]["content"]
        self.assertNotIn("private free text", request)
        self.assertEqual(json.loads(request)["past_attempts"], [
            {"attack_shape": "egress", "flag_captured": False, "blocked_by": ["D1", "D3"]},
        ])
        self.bank.retrieve.side_effect = RuntimeError("memory unavailable")
        with mock.patch("crucible.vultr.chat_json", return_value={
            "family": "egress_mirror", "framing": "Check the reference notes first.",
        }):
            scenario = RedGenerator(self.bank).next(1, live=True)
        self.assertEqual(scenario.candidate_action, seed_scenario(1, "egress_mirror").candidate_action)
