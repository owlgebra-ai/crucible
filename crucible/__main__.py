"""Command-line entry for local and Vultr-hosted runs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from crucible.supervisor import RunConfig, Supervisor
from crucible.env import load_env_local


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m crucible")
    parser.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    command = parser.add_subparsers(dest="command", required=True)
    demo = command.add_parser("demo", help="run bounded red/blue episodes")
    demo.add_argument("--rounds", type=int, default=4)
    demo.add_argument("--mode", choices=["offline", "vultr"], default="offline")
    demo.add_argument("--execution", choices=["docker", "remote", "simulate"], default="docker")
    demo.add_argument("--no-adapt", action="store_true")
    command.add_parser("bank", help="show sanitized experience entries")
    args = parser.parse_args()
    root = Path(args.root)
    load_env_local(root)
    if args.command == "demo":
        if not 1 <= args.rounds <= 20:
            parser.error("rounds must be between 1 and 20")
        supervisor = Supervisor(root, RunConfig(mode=args.mode, execution=args.execution))
        for record in supervisor.run_rounds(args.rounds, adapt=not args.no_adapt):
            print(json.dumps({key: record[key] for key in ("episode_id", "round", "attack_shape",
                "worker_mode", "execution_mode", "flag_captured", "flag_verifiable", "safe_action_executed", "safe_action_by", "task_completed", "final_report", "blue_action")}, sort_keys=True))
        return 0
    supervisor = Supervisor(root, RunConfig(execution="simulate"))
    print(json.dumps({"episodes": supervisor.bank.list_episodes(), "patterns": supervisor.bank.list_patterns()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
