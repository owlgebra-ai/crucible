"""VM2 release must refuse to change policy while a managed guest exists."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CHECK = ROOT / "deploy" / "check-sandbox-idle.py"
BOOTSTRAP = ROOT / "deploy" / "bootstrap-sandbox-vm.sh"


class SandboxIdleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.bin_dir = Path(self.temp.name)
        docker = self.bin_dir / "docker"
        docker.write_text(
            f"#!{sys.executable}\n"
            "import os, sys\n"
            "expected = ['ps', '-aq', '--no-trunc', '--filter', 'label=crucible.managed=true']\n"
            "if sys.argv[1:] != expected: sys.exit(99)\n"
            "print(os.environ.get('MOCK_CONTAINERS', ''), end='')\n"
            "sys.exit(int(os.environ.get('MOCK_DOCKER_EXIT', '0')))\n"
        )
        docker.chmod(0o755)

    def check(self, *, containers: str = "", docker_exit: int = 0) -> subprocess.CompletedProcess[str]:
        env = {**os.environ, "PATH": f"{self.bin_dir}:{os.environ['PATH']}",
               "MOCK_CONTAINERS": containers, "MOCK_DOCKER_EXIT": str(docker_exit)}
        return subprocess.run([sys.executable, str(CHECK)], cwd=ROOT, env=env,
                              capture_output=True, text=True, timeout=5)

    def test_empty_host_allows_release(self) -> None:
        self.assertEqual(self.check().returncode, 0)

    def test_managed_guest_blocks_release_without_exposing_id(self) -> None:
        cid = "a" * 64
        result = self.check(containers=cid + "\n")
        self.assertEqual(result.returncode, 75)
        self.assertNotIn(cid, result.stdout + result.stderr)

    def test_docker_error_or_unparseable_ids_fail_closed(self) -> None:
        self.assertEqual(self.check(docker_exit=1).returncode, 77)
        self.assertEqual(self.check(containers="truncated-id\n").returncode, 77)

    def test_bootstrap_holds_gateway_lock_before_policy_changes(self) -> None:
        source = BOOTSTRAP.read_text()
        self.assertLess(source.index("flock -n 8"),
                        source.index('python3 "$RELEASE/deploy/check-sandbox-idle.py"'))
        self.assertLess(source.index('python3 "$RELEASE/deploy/check-sandbox-idle.py"'),
                        source.index('bash "$RELEASE/infra/setup-net.sh"'))


if __name__ == "__main__":
    unittest.main()
