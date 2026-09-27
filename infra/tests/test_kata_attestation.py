"""Kata must be a specific KVM-backed guest, not a renamed runc runtime."""

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "verify-kata.py"
SPEC = importlib.util.spec_from_file_location("verify_kata", SOURCE)
assert SPEC and SPEC.loader
verify_kata = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_kata)


CID = "a" * 64
QEMU = Path("/opt/kata/bin/qemu-system-x86_64")


def sample_config():
    return {
        "runtime": {"hypervisor_name": "qemu", "disable_guest_seccomp": False},
        "hypervisor": {"qemu": {
            "path": str(QEMU),
            "virtio_fs_daemon": "/opt/kata/libexec/virtiofsd",
            "kernel": "/opt/kata/share/kata-containers/vmlinux",
            "image": "/opt/kata/share/kata-containers/guest.image",
            "seccomp_sandbox": "on,obsolete=deny,spawn=deny",
        }},
    }


def sample_container():
    return {
        "Id": CID,
        "State": {"Running": True},
        "Config": {"Labels": {"crucible.managed": "true"}, "User": "10001:10001"},
        "HostConfig": {
            "Runtime": "kata-qemu", "ReadonlyRootfs": True, "Binds": None,
            "Memory": 512 * 1024 * 1024, "MemorySwap": 512 * 1024 * 1024,
            "NanoCpus": 1_000_000_000, "PidsLimit": 64,
            "SecurityOpt": ['seccomp={"defaultAction":"SCMP_ACT_ERRNO"}', "no-new-privileges:true"],
        },
        "NetworkSettings": {"Networks": {"crucible-net": {"IPAddress": "172.30.80.2"}}},
    }


class KataAttestationTests(unittest.TestCase):
    def test_daemon_alias_must_point_to_pinned_shim_and_config(self):
        correct = {"runtimes": {"kata-qemu": {
            "runtimeType": "/opt/kata/runtime-rs/bin/containerd-shim-kata-v2",
            "options": {"ConfigPath": "/etc/crucible/kata-qemu.toml"},
        }}, "default-runtime": "runc"}
        verify_kata.validate_docker_config(correct)
        for bad in (
            {"runtimes": {"kata-qemu": {"runtimeType": "/usr/bin/runc"}}},
            {**correct, "default-runtime": "kata-qemu"},
            {"runtimes": {}},
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                verify_kata.validate_docker_config(bad)

    def test_config_rejects_disabled_guest_or_qemu_seccomp(self):
        config = sample_config()
        self.assertEqual(verify_kata.validate_kata_config(config)["qemu_sha256"], QEMU)
        for section, key, value in (
            ("runtime", "disable_guest_seccomp", True),
            ("runtime", "hypervisor_name", "dragonball"),
            ("hypervisor.qemu", "seccomp_sandbox", "off"),
            ("hypervisor.qemu", "path", "/usr/bin/qemu-system-x86_64"),
        ):
            altered = json.loads(json.dumps(config))
            target = altered["hypervisor"]["qemu"] if section == "hypervisor.qemu" else altered[section]
            target[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                verify_kata.validate_kata_config(altered)

    def test_loaded_docker_alias_must_match_pinned_shim_and_config(self):
        correct = {"kata-qemu": {
            "runtimeType": str(verify_kata.SHIM),
            "options": {"ConfigPath": str(verify_kata.CONFIG)},
            "path": "", "runtimeArgs": None,
            "status": {"io.containerd.runtime.v2.task": "ok"},
        }}
        verify_kata.validate_live_runtime(correct)
        for bad in (
            {},
            {"kata-qemu": {**correct["kata-qemu"], "runtimeType": "/usr/bin/runc"}},
            {"kata-qemu": {**correct["kata-qemu"], "options": {}}},
            {"kata-qemu": {**correct["kata-qemu"], "runtimeArgs": ["--unsafe"]}},
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                verify_kata.validate_live_runtime(bad)

    def test_task_must_have_effective_kata_runtime_and_limits(self):
        container = sample_container()
        verify_kata.validate_container(container, "crucible-net")
        for section, key, value in (
            ("HostConfig", "Runtime", "runc"),
            ("HostConfig", "Memory", 0),
            ("HostConfig", "NanoCpus", 0),
            ("HostConfig", "ReadonlyRootfs", False),
            ("Config", "User", "0:0"),
        ):
            altered = json.loads(json.dumps(container))
            altered[section][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                verify_kata.validate_container(altered, "crucible-net")
        with self.assertRaises(ValueError):
            verify_kata.validate_container(container, "different-network")
        verify_kata.validate_container(container, "crucible-net", {"defaultAction": "SCMP_ACT_ERRNO"})
        with self.assertRaises(ValueError):
            verify_kata.validate_container(container, "crucible-net", {"defaultAction": "SCMP_ACT_ALLOW"})

    def test_installer_requires_explicit_apply(self):
        installer = SOURCE.with_name("install-kata.sh")
        result = subprocess.run(["bash", str(installer)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--apply", result.stderr)

    def test_qemu_proof_binds_container_name_to_kvm_fd_and_sandbox(self):
        with tempfile.TemporaryDirectory() as root:
            proc = Path(root)
            task = proc / "4321"
            (task / "fd").mkdir(parents=True)
            argv = [str(QEMU), "-name", f"sandbox-{CID}",
                    "-machine", "q35,accel=kvm", "-sandbox", "on"]
            (task / "cmdline").write_bytes(b"\0".join(item.encode() for item in argv) + b"\0")
            (task / "fd" / "3").symlink_to("/dev/kvm")
            self.assertEqual(verify_kata.qemu_kvm_pid(CID, QEMU, proc), 4321)
            with self.assertRaises(ValueError):
                verify_kata.qemu_kvm_pid("b" * 64, QEMU, proc)
            (task / "fd" / "3").unlink()
            with self.assertRaises(ValueError):
                verify_kata.qemu_kvm_pid(CID, QEMU, proc)
            (task / "fd" / "3").symlink_to("/dev/kvm")
            argv[-1] = "off"
            (task / "cmdline").write_bytes(b"\0".join(item.encode() for item in argv) + b"\0")
            with self.assertRaises(ValueError):
                verify_kata.qemu_kvm_pid(CID, QEMU, proc)


if __name__ == "__main__":
    unittest.main()
