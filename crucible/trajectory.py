"""Private, bounded trajectory feed for a loopback dashboard.

This store intentionally records *states*, never prompts, command payloads,
container identifiers, network addresses, stdout, stderr, or model responses.
It is safe to read while another process is running an episode. The dashboard
must still be bound to loopback: this is an observability feed, not a public API.
"""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import re
import sqlite3
from urllib.parse import quote
from uuid import uuid4


_TASK = re.compile(r"task_[a-f0-9]{16}\Z")
_PHASE_LABELS = {
    "task_start": "Task started",
    "scenario": "Scenario selected",
    "red": "Red agent preparing a decoy",
    "sandbox": "Sandbox container starting",
    "worker": "Worker agent choosing an action",
    "fixed_probe": "Fixed judge action checked",
    "preexec": "Pre-execution policy judgment",
    "remote_exec": "Sandbox action in progress",
    "result": "Sandbox action finished",
    "supervisor": "Supervisor checking the result",
    "blue": "Blue agent reviewing the defense",
    "teardown": "Sandbox container teardown",
    "task_end": "Task complete",
    "task_error": "Task failed",
}
_STATUS = frozenset({"queued", "running", "pending", "allow", "deny", "ok", "failed", "interrupted"})
_ACTIONS = frozenset({"shell", "http_get", "file_read", "file_write", "net_connect", "output"})
_DIMENSIONS = frozenset({"D1", "D2", "D3", "D4", "D5", "D6"})
_FAMILIES = frozenset({"egress_mirror", "dependency_fetch", "secret_exfil", "resource_timeout"})
_FINISHED = frozenset({"complete", "failed", "interrupted"})
_ACTIVE = ("queued", "running")
_MAX_EVENTS = 300


class TaskBusyError(RuntimeError):
    """A trajectory task is already running."""


class TrajectoryStore:
    """SQLite-backed event feed with one active task across local processes."""

    def __init__(self, path: str | Path, *, read_only: bool = False) -> None:
        self.path = Path(path)
        self.read_only = read_only
        if self.path.is_symlink():
            raise ValueError("trajectory database cannot be a symlink")
        if read_only:
            return
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        except FileExistsError:
            if self.path.stat().st_mode & 0o077:
                raise PermissionError("trajectory database permissions must be owner-only")
        else:
            os.close(descriptor)
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    owner_pid INTEGER NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT
                );
                CREATE UNIQUE INDEX IF NOT EXISTS one_active_trajectory_task
                    ON tasks ((1)) WHERE status IN ('queued', 'running');
                CREATE TABLE IF NOT EXISTS events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    episode_id TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    label TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                );
            """)

    def _connect(self) -> sqlite3.Connection:
        if self.read_only:
            db = sqlite3.connect(f"file:{quote(str(self.path.resolve()))}?mode=ro", uri=True, timeout=10)
        else:
            db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        return db

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    @staticmethod
    def _detail(*, family: str = "", action: str = "", dimension: str = "",
                exit_code: int | None = None) -> str:
        # Build display text only from closed enums and bounded integers. Raw
        # action arguments and result text cannot enter this path.
        parts: list[str] = []
        if family in _FAMILIES:
            parts.append(family.replace("_", " "))
        if action in _ACTIONS:
            parts.append(action.replace("_", " "))
        if dimension in _DIMENSIONS:
            parts.append(dimension)
        if type(exit_code) is int and -255 <= exit_code <= 255:
            parts.append(f"exit {exit_code}")
        return " · ".join(parts)

    def _event(self, db: sqlite3.Connection, task_id: str, phase: str, status: str,
               *, family: str = "", action: str = "", dimension: str = "",
               exit_code: int | None = None) -> None:
        if not _TASK.fullmatch(task_id) or phase not in _PHASE_LABELS or status not in _STATUS:
            raise ValueError("invalid trajectory event")
        db.execute("""INSERT INTO events
            (task_id, episode_id, phase, label, detail, status, timestamp)
            VALUES (?, '', ?, ?, ?, ?, ?)""",
            (task_id, phase, _PHASE_LABELS[phase], self._detail(
                family=family, action=action, dimension=dimension, exit_code=exit_code),
             status, self._now()))
        db.execute("DELETE FROM events WHERE seq <= (SELECT COALESCE(MAX(seq), 0) - ? FROM events)",
                   (_MAX_EVENTS,))

    def claim_task(self) -> str:
        """Reserve the single active slot before starting any model or worker work."""
        if self.read_only:
            raise PermissionError("trajectory store is read-only")
        task_id = "task_" + uuid4().hex[:16]
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            active = db.execute("SELECT task_id, owner_pid FROM tasks WHERE status IN (?, ?) LIMIT 1",
                                _ACTIVE).fetchone()
            if active:
                try:
                    os.kill(active["owner_pid"], 0)
                except ProcessLookupError:
                    # The owning CLI died without a final event. Do not infer
                    # whether its container was destroyed or its task succeeded.
                    db.execute("UPDATE tasks SET status='interrupted', finished_at=? WHERE task_id=?",
                               (self._now(), active["task_id"]))
                    self._event(db, active["task_id"], "task_error", "interrupted")
                except PermissionError:
                    raise TaskBusyError("another task is already running") from None
                else:
                    raise TaskBusyError("another task is already running")
            db.execute("INSERT INTO tasks VALUES (?, 'queued', ?, ?, NULL)",
                       (task_id, os.getpid(), self._now()))
            self._event(db, task_id, "task_start", "queued")
        return task_id

    def mark_running(self, task_id: str) -> None:
        if self.read_only:
            raise PermissionError("trajectory store is read-only")
        if not _TASK.fullmatch(task_id):
            raise ValueError("invalid task ID")
        with self._connect() as db:
            db.execute("UPDATE tasks SET status='running' WHERE task_id=? AND status='queued'", (task_id,))

    def append(self, task_id: str, phase: str, status: str = "running", *,
               family: str = "", action: str = "", dimension: str = "",
               exit_code: int | None = None) -> None:
        if self.read_only:
            raise PermissionError("trajectory store is read-only")
        with self._connect() as db:
            row = db.execute("SELECT status FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if not row or row[0] in _FINISHED:
                return
            self._event(db, task_id, phase, status, family=family, action=action,
                        dimension=dimension, exit_code=exit_code)

    def finish_task(self, task_id: str, status: str = "complete") -> None:
        if self.read_only:
            raise PermissionError("trajectory store is read-only")
        if not _TASK.fullmatch(task_id) or status not in _FINISHED:
            raise ValueError("invalid task completion")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status FROM tasks WHERE task_id=?", (task_id,)).fetchone()
            if not row or row[0] in _FINISHED:
                return
            db.execute("UPDATE tasks SET status=?, finished_at=? WHERE task_id=?",
                       (status, self._now(), task_id))
            phase = "task_end" if status == "complete" else "task_error"
            self._event(db, task_id, phase, "ok" if status == "complete" else status)

    @staticmethod
    def _records(rows: list[sqlite3.Row]) -> list[dict]:
        return [dict(row) for row in rows]

    def snapshot(self, limit: int = 100) -> dict:
        limit = max(1, min(int(limit), _MAX_EVENTS))
        empty = {"available": True, "active": False, "task_id": None, "status": "idle", "events": []}
        try:
            with self._connect() as db:
                task = db.execute("SELECT task_id, status FROM tasks ORDER BY rowid DESC LIMIT 1").fetchone()
                if not task:
                    return empty
                rows = db.execute("SELECT * FROM events WHERE task_id=? ORDER BY seq DESC LIMIT ?",
                                  (task["task_id"], limit)).fetchall()
        except (sqlite3.OperationalError, FileNotFoundError):
            return empty
        return {"available": True, "active": task["status"] in _ACTIVE, "task_id": task["task_id"],
                "status": task["status"], "events": self._records(list(reversed(rows)))}

    def events_since(self, seq: int = 0, limit: int = 100) -> list[dict]:
        seq = max(0, int(seq))
        limit = max(1, min(int(limit), _MAX_EVENTS))
        try:
            with self._connect() as db:
                rows = db.execute("SELECT * FROM events WHERE seq>? ORDER BY seq LIMIT ?",
                                  (seq, limit)).fetchall()
        except (sqlite3.OperationalError, FileNotFoundError):
            return []
        return self._records(rows)
