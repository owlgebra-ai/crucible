"""Private-hop deploy options must preserve host pinning and shell boundaries."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy" / "ssh-deploy.sh"


class SSHDeployJumpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        bin_dir = self.base / "bin"
        bin_dir.mkdir()
        self.log = self.base / "calls.jsonl"
        shim = (f"#!{sys.executable}\n"
                "import json, os, pathlib, sys\n"
                "with open(os.environ['MOCK_SSH_LOG'], 'a') as out:\n"
                "    out.write(json.dumps([pathlib.Path(sys.argv[0]).name, sys.argv[1:]]) + '\\n')\n")
        for name in ("ssh", "scp"):
            path = bin_dir / name
            path.write_text(shim)
            path.chmod(0o755)
        self.env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}",
                    "MOCK_SSH_LOG": str(self.log)}
        self.target_key = self.base / "target.key"
        self.target_hosts = self.base / "target.known_hosts"
        self.jump_key = self.base / "jump' $(touch HACKED) key"
        self.jump_hosts = self.base / "jump' hosts"
        for path in (self.target_key, self.target_hosts, self.jump_key, self.jump_hosts):
            path.write_text("test fixture\n")

    def run_deploy(self, *args):
        return subprocess.run(["bash", str(DEPLOY), *args], cwd=ROOT,
                              env=self.env, text=True, capture_output=True,
                              timeout=30)

    def calls(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    @staticmethod
    def option(args, name):
        values = [args[i + 1] for i, value in enumerate(args[:-1])
                  if value == "-o" and args[i + 1].startswith(name + "=")]
        if len(values) != 1:
            raise AssertionError(f"expected one {name} option, got {values!r}")
        return values[0].split("=", 1)[1]

    def test_direct_mode_keeps_proxy_disabled(self):
        result = self.run_deploy("--target", "root@sandbox.example", "--identity", str(self.target_key),
                                 "--known-hosts", str(self.target_hosts), "--sandbox", "--apply")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertEqual([item[0] for item in calls], ["ssh", "scp", "ssh"])
        for _, args in calls:
            self.assertEqual(self.option(args, "ProxyCommand"), "none")
            self.assertEqual(self.option(args, "StrictHostKeyChecking"), "yes")

    def test_private_hop_pins_both_hosts_and_shell_quotes_jump_paths(self):
        result = self.run_deploy(
            "--target", "root@10.0.0.4", "--identity", str(self.target_key),
            "--known-hosts", str(self.target_hosts),
            "--target-host-key-alias", "sandbox.example",
            "--jump-target", "root@control.example", "--jump-identity", str(self.jump_key),
            "--jump-known-hosts", str(self.jump_hosts), "--jump-port", "2222",
            "--sandbox", "--apply")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertEqual([item[0] for item in calls], ["ssh", "scp", "ssh"])
        proxies = []
        for _, args in calls:
            proxies.append(self.option(args, "ProxyCommand"))
            self.assertEqual(self.option(args, "StrictHostKeyChecking"), "yes")
            self.assertEqual(self.option(args, "UserKnownHostsFile"), str(self.target_hosts))
            self.assertEqual(self.option(args, "HostKeyAlias"), "sandbox.example")
            self.assertIn("-F", args)
            self.assertIn("/dev/null", args)
        self.assertEqual(len(set(proxies)), 1)
        check = subprocess.run(["/bin/sh", "-c", proxies[0]], cwd=self.base,
                               env=self.env, capture_output=True, text=True, timeout=5)
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertFalse((self.base / "HACKED").exists())
        name, args = self.calls()[-1]
        self.assertEqual(name, "ssh")
        self.assertEqual(self.option(args, "StrictHostKeyChecking"), "yes")
        self.assertEqual(self.option(args, "UserKnownHostsFile"), str(self.jump_hosts))
        self.assertEqual(self.option(args, "ProxyCommand"), "none")
        self.assertIn(str(self.jump_key), args)
        self.assertEqual(args[-1], "root@control.example")
        self.assertIn("%h:%p", args)
        self.assertIn("2222", args)

    def test_incomplete_or_hostile_jump_options_stop_before_network(self):
        base = ["--target", "root@10.0.0.4", "--identity", str(self.target_key),
                "--known-hosts", str(self.target_hosts), "--apply"]
        invalid = [
            ["--jump-target", "root@control.example"],
            ["--jump-identity", str(self.jump_key)],
            ["--jump-target", "root@control.example;touch HACKED",
             "--jump-identity", str(self.jump_key), "--jump-known-hosts", str(self.jump_hosts)],
            ["--target-host-key-alias", "sandbox.example;touch HACKED"],
            ["--jump-port", "not-a-port"],
        ]
        for options in invalid:
            with self.subTest(options=options):
                result = self.run_deploy(*base, *options)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main()
