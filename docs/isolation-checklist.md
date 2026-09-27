# Isolation checklist: what the worker actually runs inside

The reference slide distinguishes four execution boundaries. Its highlighted
microVM row is a **target**, not evidence that CRUCIBLE already uses one. This
checklist separates the boundary between the two Vultr instances from the
boundary around each task on the sandbox instance.

```text
Vultr VM1: model calls, supervisor, bank, dashboard, credentials
    │ approved, typed action over pinned private-VPC SSH
    ▼
Vultr VM2: forced gateway, Docker, network policy
    └── historical task worker: disposable runc container
        (shares VM2's Linux kernel)
```

| Reference tier | Boundary | CRUCIBLE status on 27 Sep 2026 |
| --- | --- | --- |
| **01 In-process** | Untrusted code runs in the application worker or a host subprocess. | **Excluded from the live worker path.** The control VM sends bounded actions to VM2. Stock DSH tool providers are a host-execution seam demonstration and are not used as containment evidence. |
| **02 Container (`runc`)** | Namespaces, cgroups, seccomp and other Linux controls; the workload shares its host's kernel. | **Historical live proof.** VM2 ran disposable Docker `runc` workers. Its wall transcript checked the effective runtime, read-only root filesystem, non-root user, dropped capabilities, custom seccomp, resource limits, egress rule, denied `ptrace`, and teardown. A host-kernel flaw could still compromise VM2. |
| **03 User-space kernel (gVisor)** | `runsc` intercepts application system calls in a user-space application kernel. | **Optional code path, not live-attested.** The `runsc-oci` configuration and verifier exist, but the recorded episodes and wall proof are `runc`. |
| **04 Per-task VM (Kata / QEMU)** | A VMM starts a guest with its own Linux kernel for each task. | **Target pending live proof.** No historical episode can be relabeled tier 04. A VX1 plan or readable `/dev/kvm` only shows a prerequisite; it does not show a Kata worker booted, handled an action, or was destroyed. |

The **two Vultr VMs** keep VM1's inference key and private bank away from the
task-execution host. That is a useful control-plane boundary,
but it does not change a `runc` task into a microVM. The saved
[`sleep 20` evolution](real-model-elicitation.md) is an observed policy
improvement with a real candidate and Blue model. Its kernel evidence remains
the separate `runc` wall probe, not the `sleep 20` trajectory itself.

The fixed [`rm -rf /` judge probe](judge-proof.md) checked
the **pre-exec policy seam**: the control supervisor denied the typed action
before dispatch and the VM2 gateway independently denied it before the
container runner. The command never ran. VM survival after that probe does
not measure how `runc`, gVisor or Kata would contain an executed destructive
command. A contained test of a destructive operation would require a disposable
guest and a narrowly scoped guest-only target, with the guest and VM2 inspected
afterward; the fixed pre-exec test makes no such claim.

## Gates before calling a new Kata episode tier 04

All gates apply to **one recorded live task**, including its approved safe
action, and must be repeated for the same effective runner used by the model
loop. Installation output, a Docker runtime alias, and `/dev/kvm` alone do
not satisfy them. Keep host identifiers and raw outputs in private evidence;
publish a reviewed, bounded summary.

1. **Effective runtime and VMM.** Record the task container's immutable image
   and ID privately. `docker inspect` must report the intended Kata runtime
   for that exact container; inspect the daemon's runtime mapping and pin the
   Kata configuration to QEMU. Link the task to a live Kata shim and QEMU
   process. An alias that resolves to `runc` fails this gate.
2. **Active hardware virtualization and guest kernel.** Confirm `/dev/kvm` is
   readable by the Kata shim **and** that the task's QEMU process actually
   opened KVM. Record host `uname -r` and the kernel identity reported by the
   task workload inside the guest, plus the pinned Kata guest kernel and QEMU
   configuration. A difference in `uname` is supporting evidence; the VMM,
   KVM, configuration and task linkage establish the guest boundary.
3. **Task execution, not a smoke-only guest.** Run a real model-driven CRUCIBLE
   episode through VM1's supervisor and VM2's forced gateway. Its approved
   action must execute in that same Kata guest and return a verified result.
   Preserve the task report and the episode's runtime provenance. A standalone
   `docker run --runtime kata` hello-world does not upgrade the model loop.
4. **Filesystem, privilege and resource policy.** Inspect the effective worker
   configuration: read-only root filesystem, scoped writable mounts, no host
   bind or Docker socket, non-root user, no added capabilities, no new
   privileges, and CPU, memory, process and time bounds. Confirm any mounts
   exposed through Kata's guest-sharing mechanism contain no host credentials.
5. **Syscall policy at the guest exec seam.** Verify the custom OCI seccomp
   policy is accepted by the effective Kata runtime and applies to task
   commands started with `docker exec`. Perform the existing unprivileged
   `PTRACE_TRACEME` probe from the task guest and record its `EPERM`. If the guest runtime ignores the
   profile, report D2 as unverified for Kata rather than borrowing the `runc`
   result. A denied call alone is insufficient without the runtime/profile
   configuration evidence.
6. **Network policy on the actual guest path.** Run the pinned-host TLS
   positive test and external-DNS/direct-IP negative tests from the task
   guest. Record its source address and the probe-specific packet count at
   the enforced default-drop rule, including IPv6 handling. Kata may route
   differently from `runc`; if VM2's `DOCKER-USER` rule is bypassed, repair and
   reprove the guest path before claiming D1.
7. **Credential and output boundary.** Verify the guest lacks Vultr
   inference/management keys, VM1's private bank, the host Docker socket and
   unrestricted VM1 access. Exercise a fake canary through the real guest
   result path and verify gateway and control-plane output scans redact it
   before records or dashboard display.
8. **Per-task lifecycle.** Show two episodes use distinct Kata guests. After
   each episode, including timeout and failure paths, confirm the task
   container, Kata shim, QEMU process, guest state and temporary mounts are
   gone. VM1 and VM2 must remain healthy, and the legitimate safe task must
   still complete after the blocked or failed action.

Only after these gates pass should the judge-facing copy say **“tier 04
verified for this Kata episode.”** Historical `runc` counts, curves and
before/after records retain their tier 02 label. A guest kernel reduces the
shared-kernel exposure of `runc`; it is not a guarantee against VMM, host or
cloud-hypervisor vulnerabilities.

## Primary references

- [Docker Engine security](https://docs.docker.com/engine/security/) explains
  namespaces, kernel controls and the privileged Docker daemon.
- [Docker seccomp profiles](https://docs.docker.com/engine/security/seccomp)
  documents profile installation and syscall denial.
- [Docker firewall integration](https://docs.docker.com/engine/network/packet-filtering-firewalls/)
  documents Docker's bridge firewall behavior; the CRUCIBLE guest packet
  counter must independently verify its actual route.
- [gVisor security architecture](https://gvisor.dev/docs/architecture_guide/intro/)
  describes the user-space application kernel and its distinction from a VM.
- [Kata Containers quick start](https://github.com/kata-containers/kata-containers/blob/main/docs/quick-start-guide.md)
  explains `runc`'s shared kernel and Kata's guest kernel.
- [Kata Containers installation](https://github.com/kata-containers/kata-containers/blob/main/docs/installation.md)
  specifies KVM, Docker runtime mapping, QEMU configuration and a guest-kernel
  check.
