"""Narrow VM1 task launcher behind a credential-free browser dashboard.

The Unix socket accepts only two fixed, server-owned cases. This service runs
separately from the web process, owns the inference/SSH credentials, reserves
the shared trajectory slot, and never returns prompts, commands, or stdout.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import grp
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import signal
import socket
import socketserver
import stat
import struct
import subprocess
import sys
import threading
from uuid import uuid4

from crucible.trajectory import TaskBusyError, TrajectoryStore


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SOCKET = Path("/run/crucible-task/task.sock")
DEPLOY_LOCK = Path("/var/lock/crucible-deploy.lock")
_CASES = frozenset({"safe_demo", "readiness_evolution"})
_RFC1918 = tuple(ipaddress.IPv4Network(cidr) for cidr in
                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
_TASK = re.compile(r"task_[a-f0-9]{16}\Z")


class BrokerUnavailable(RuntimeError):
    """The fixed task cannot run with the currently installed VM1 resources."""


def _private_path(value: str, label: str, *, owner: int = 0) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise BrokerUnavailable(f"{label} unavailable")
    info = path.stat()
    if info.st_uid != owner or info.st_mode & 0o077 or info.st_size == 0:
        raise BrokerUnavailable(f"{label} unavailable")
    return path


def _remote_target(hosts: Path, configured: str) -> str:
    """Derive the worker solely from one pinned private-IP host-key entry."""
    try:
        lines = [line.strip() for line in hosts.read_text().splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
    except (OSError, UnicodeError):
        raise BrokerUnavailable("remote host pin unavailable") from None
    if len(lines) != 1:
        raise BrokerUnavailable("remote host pin must identify one worker")
    fields = lines[0].split()
    if len(fields) != 3 or fields[1] not in {"ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"}:
        raise BrokerUnavailable("remote host pin is ambiguous")
    try:
        address = ipaddress.IPv4Address(fields[0])
    except ipaddress.AddressValueError:
        raise BrokerUnavailable("remote host pin must use private IPv4") from None
    if not any(address in network for network in _RFC1918):
        raise BrokerUnavailable("remote host pin must use private IPv4")
    target = "root@" + str(address)
    if configured and configured != target:
        raise BrokerUnavailable("remote target does not match pinned host")
    return target


def _child_environment(task_id: str) -> dict[str, str]:
    if not _TASK.fullmatch(task_id):
        raise BrokerUnavailable("invalid broker task")
    inference = _private_path(os.getenv("CRUCIBLE_ENV_FILE", "/etc/crucible/inference.env"),
                              "inference key")
    identity = _private_path(os.getenv("CRUCIBLE_REMOTE_IDENTITY", "/etc/crucible/worker_ed25519"),
                             "remote identity")
    known_hosts = _private_path(os.getenv("CRUCIBLE_REMOTE_KNOWN_HOSTS", "/etc/crucible/worker_known_hosts"),
                                "remote host pin")
    target = _remote_target(known_hosts, os.getenv("CRUCIBLE_REMOTE_TARGET", ""))
    return {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": "/var/lib/crucible",
            "CRUCIBLE_ENV_FILE": str(inference), "CRUCIBLE_REMOTE_TARGET": target,
            "CRUCIBLE_REMOTE_IDENTITY": str(identity),
            "CRUCIBLE_REMOTE_KNOWN_HOSTS": str(known_hosts),
            "CRUCIBLE_REQUIRED_RUNTIME": "kata-qemu",
            "CRUCIBLE_BROKER_TASK_ID": task_id}


def _command(case: str, db_path: Path) -> tuple[list[str], int]:
    if case == "safe_demo":
        return ([sys.executable, "-m", "crucible.browser_task", "--case", "safe_demo",
                 "--trajectory-db", str(db_path)], 600)
    if case == "readiness_evolution":
        return ([sys.executable, "-m", "crucible.elicitation", "--execution", "remote",
                 "--max-attempts", "3", "--require-model-blue", "--require-runtime",
                 "kata-qemu", "--trajectory-db", str(db_path)], 1800)
    raise ValueError("unsupported task case")


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class TaskManager:
    """One broker job and one atomic trajectory reservation at a time."""

    def __init__(self, db_path: Path, *, deploy_lock: Path = DEPLOY_LOCK) -> None:
        self.db_path = db_path
        self.deploy_lock = deploy_lock
        self._lock = threading.Lock()
        self._job: dict | None = None
        self._thread: threading.Thread | None = None
        self._process: subprocess.Popen | None = None
        self._stopping = False
        store = TrajectoryStore(db_path)
        store.reconcile_interrupted()
        latest = store.snapshot(limit=1)
        if latest["status"] == "interrupted":
            self._job = {"job_id": None, "task_id": latest["task_id"], "case": None,
                         "status": "interrupted", "proof_complete": False,
                         "started_at": None, "finished_at": _timestamp()}

    def current(self) -> dict:
        with self._lock:
            if self._job is None:
                return {"job_id": None, "task_id": None, "case": None,
                        "status": "idle", "proof_complete": None, "task_completed": None}
            return dict(self._job)

    def start(self, case: str) -> dict:
        if case not in _CASES:
            raise ValueError("unsupported task case")
        lock_fd: int | None = None
        try:
            lock_fd = os.open(self.deploy_lock, os.O_RDONLY | os.O_NOFOLLOW)
            lock_info = os.fstat(lock_fd)
            if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != os.geteuid():
                raise BrokerUnavailable("deployment lock unavailable")
            fcntl.flock(lock_fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            if lock_fd is not None:
                os.close(lock_fd)
            raise TaskBusyError("deployment in progress") from None
        except OSError:
            if lock_fd is not None:
                os.close(lock_fd)
            raise BrokerUnavailable("deployment lock unavailable") from None
        except BrokerUnavailable:
            if lock_fd is not None:
                os.close(lock_fd)
            raise
        try:
            with self._lock:
                if self._stopping:
                    raise BrokerUnavailable("task broker is stopping")
                if self._job is not None and self._job["status"] in {"queued", "running"}:
                    raise TaskBusyError("a browser task is already active")
                # Validate resources before claiming the one active trajectory slot.
                # A missing key may not strand an active row in the bank.
                _child_environment("task_" + "0" * 16)
                store = TrajectoryStore(self.db_path)
                task_id = store.claim_task()
                job = {"job_id": "job_" + uuid4().hex[:16], "task_id": task_id,
                       "case": case, "status": "queued", "proof_complete": None,
                       "task_completed": None,
                       "started_at": _timestamp(), "finished_at": None}
                self._job = job
                try:
                    thread = threading.Thread(target=self._run, args=(case, task_id), daemon=True)
                    self._thread = thread
                    thread.start()
                except Exception:
                    store.finish_task(task_id, "failed")
                    self._job["status"] = "failed"
                    self._job["proof_complete"] = False
                    self._job["task_completed"] = False
                    self._job["finished_at"] = _timestamp()
                    raise BrokerUnavailable("task launcher unavailable") from None
                return dict(job)
        finally:
            assert lock_fd is not None
            os.close(lock_fd)

    def _run(self, case: str, task_id: str) -> None:
        store: TrajectoryStore | None = None
        process: subprocess.Popen | None = None
        succeeded = False
        try:
            store = TrajectoryStore(self.db_path)
            command, timeout = _command(case, self.db_path)
            env = _child_environment(task_id)
            store.mark_running(task_id)
            with self._lock:
                if self._stopping:
                    raise BrokerUnavailable("task broker is stopping")
                assert self._job is not None and self._job["task_id"] == task_id
                self._job["status"] = "running"
                process = subprocess.Popen(command, cwd=REPO_ROOT, env=env,
                                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                           stderr=subprocess.DEVNULL, start_new_session=True)
                self._process = process
            try:
                succeeded = process.wait(timeout=timeout) == 0
                with self._lock:
                    succeeded = succeeded and not self._stopping
            except subprocess.TimeoutExpired:
                self._terminate(process)
        except Exception:
            # The browser receives only a generic failed state, never a path,
            # model response, prompt, command, credential, or worker output.
            succeeded = False
            if process is not None and process.poll() is None:
                try:
                    self._terminate(process)
                except Exception:
                    pass
        finally:
            try:
                if store is None:
                    store = TrajectoryStore(self.db_path)
                store.finish_task(task_id, "complete" if succeeded else "failed")
            finally:
                with self._lock:
                    self._process = None
                    if self._job is not None and self._job["task_id"] == task_id:
                        self._job["status"] = "complete" if succeeded else "failed"
                        self._job["proof_complete"] = (succeeded if case == "readiness_evolution" else None)
                        self._job["task_completed"] = (succeeded if case == "safe_demo" else None)
                        self._job["finished_at"] = _timestamp()

    @staticmethod
    def _terminate(process: subprocess.Popen) -> None:
        if process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=90)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=10)

    def stop(self) -> None:
        """Gracefully stop the child so its Supervisor tears down VM2."""
        with self._lock:
            self._stopping = True
            process, thread = self._process, self._thread
        if process is not None:
            self._terminate(process)
        if thread is not None:
            thread.join(timeout=100)
            if thread.is_alive() and process is not None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                thread.join(timeout=10)


class BrokerServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, socket_path: Path, manager: TaskManager, *, allowed_uids: set[int]):
        self.manager = manager
        self.allowed_uids = allowed_uids
        super().__init__(str(socket_path), BrokerHandler)


class BrokerHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(3)
        try:
            if hasattr(socket, "SO_PEERCRED"):
                credentials = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                                       struct.calcsize("3i"))
                _pid, uid, _gid = struct.unpack("3i", credentials)
                if uid not in self.server.allowed_uids:
                    self._reply({"ok": False, "error": "forbidden"})
                    return
            else:
                self._reply({"ok": False, "error": "peer identity unavailable"})
                return
            raw = self.rfile.readline(257)
            if not raw or len(raw) > 256 or not raw.endswith(b"\n"):
                raise ValueError("invalid request")
            def unique_object(pairs: list[tuple[str, object]]) -> dict:
                result: dict = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("duplicate key")
                    result[key] = value
                return result
            request = json.loads(raw, object_pairs_hook=unique_object)
            if not isinstance(request, dict):
                raise ValueError("invalid request")
            if request == {"op": "current"}:
                self._reply({"ok": True, "task": self.server.manager.current()})
            elif (set(request) == {"op", "case"} and request.get("op") == "start"
                  and isinstance(request.get("case"), str) and request["case"] in _CASES):
                self._reply({"ok": True, "task": self.server.manager.start(request["case"])})
            else:
                raise ValueError("invalid request")
        except TaskBusyError:
            self._reply({"ok": False, "error": "busy"})
        except BrokerUnavailable:
            self._reply({"ok": False, "error": "unavailable"})
        except (ValueError, UnicodeError, json.JSONDecodeError):
            self._reply({"ok": False, "error": "invalid_request"})
        except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
            return
        except Exception:
            self._reply({"ok": False, "error": "unavailable"})

    def _reply(self, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"
        if len(body) <= 1024:
            self.wfile.write(body)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path, default=DEFAULT_SOCKET)
    parser.add_argument("--db", type=Path, required=True)
    args = parser.parse_args(argv)
    if os.geteuid() != 0 or sys.platform != "linux":
        parser.error("the task broker requires Linux root")
    group_id = grp.getgrnam("crucible").gr_gid
    dashboard_uid = pwd.getpwnam("crucible").pw_uid
    directory = args.socket.parent
    info = directory.stat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != group_id
            or stat.S_IMODE(info.st_mode) != 0o750):
        parser.error("socket directory must be root:crucible mode 0750")
    if args.socket.exists() or args.socket.is_symlink():
        parser.error("refusing an existing broker socket path")
    if not args.db.is_absolute() or args.db.is_symlink() or not args.db.is_file():
        parser.error("--db must name an existing absolute regular file")
    manager = TaskManager(args.db)
    with BrokerServer(args.socket, manager, allowed_uids={0, dashboard_uid}) as server:
        socket_info = args.socket.stat()
        if (socket_info.st_uid, socket_info.st_gid) != (0, group_id):
            os.chown(args.socket, 0, group_id)
        os.chmod(args.socket, 0o660)
        def stop_server(_signal: int, _frame: object) -> None:
            # shutdown() must run outside serve_forever's thread.
            threading.Thread(target=server.shutdown, daemon=True).start()
        signal.signal(signal.SIGTERM, stop_server)
        try:
            server.serve_forever(poll_interval=0.25)
        except KeyboardInterrupt:
            pass
        finally:
            manager.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
