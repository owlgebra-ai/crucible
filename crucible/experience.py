"""D5 episode memory and distilled attack/defense patterns."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sqlite3
from urllib.parse import quote
from typing import Any

from crucible.plugins.d6_output_filter import OutputFilterPlugin


def _tokens(value: str) -> set[str]:
    return set(re.findall(r"[a-z0-9_]{3,}", value.lower()))


def _credible_docker_episode(entry: dict[str, Any]) -> bool:
    return entry.get("execution_mode") in {"docker", "remote"} and (
        entry.get("flag_verifiable") is True or
        (entry.get("flag_captured") is True and entry.get("action_results_verified") is True)
    )


class ExperienceBank:
    def __init__(self, path: str | Path, scanner: OutputFilterPlugin | None = None,
                 *, read_only: bool = False) -> None:
        self.path = Path(path)
        self.read_only = read_only
        if not read_only:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.is_symlink():
            raise ValueError("experience database cannot be a symlink")
        if read_only:
            if not self.path.is_file():
                raise FileNotFoundError(self.path)
        else:
            try:
                descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            except FileExistsError:
                if self.path.stat().st_mode & 0o077:
                    raise PermissionError("experience database permissions must be owner-only")
            else:
                os.close(descriptor)
        self.scanner = scanner or OutputFilterPlugin()
        if read_only:
            return
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS episodes (
                  episode_id TEXT PRIMARY KEY,
                  round INTEGER NOT NULL,
                  attack_shape TEXT NOT NULL,
                  flag_captured INTEGER NOT NULL,
                  safe_action_executed INTEGER NOT NULL,
                  record_json TEXT NOT NULL,
                  created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS patterns (
                  pattern_id TEXT PRIMARY KEY,
                  attack_shape TEXT NOT NULL,
                  dimension TEXT NOT NULL,
                  recommended_defense TEXT NOT NULL,
                  supporting_episodes TEXT NOT NULL,
                  updated_at TEXT NOT NULL
                );
            """)
            columns = {row[1] for row in db.execute("PRAGMA table_info(episodes)")}
            if "task_completed" in columns and "safe_action_executed" not in columns:
                db.execute("ALTER TABLE episodes RENAME COLUMN task_completed TO safe_action_executed")

    def _connect(self) -> sqlite3.Connection:
        if self.read_only:
            return sqlite3.connect(f"file:{quote(str(self.path.resolve()))}?mode=ro", uri=True, timeout=10)
        return sqlite3.connect(self.path, timeout=10)

    def add_episode(self, record: dict[str, Any]) -> None:
        if self.read_only:
            raise PermissionError("experience bank is read-only")
        required = {"episode_id", "round", "attack_shape", "flag_captured", "safe_action_executed"}
        if not required.issubset(record):
            raise ValueError(f"episode missing: {sorted(required - record.keys())}")
        raw = json.dumps(record, sort_keys=True, ensure_ascii=True)
        clean, _ = self.scanner.redact(raw)
        # Redaction may replace bytes inside JSON string values; JSON encoding remains valid.
        json.loads(clean)
        with self._connect() as db:
            db.execute("""INSERT INTO episodes VALUES (?, ?, ?, ?, ?, ?, ?)""", (
                str(record["episode_id"]), int(record["round"]), str(record["attack_shape"]),
                int(bool(record["flag_captured"])), int(bool(record["safe_action_executed"])),
                clean, datetime.now(timezone.utc).isoformat(),
            ))
        if _credible_docker_episode(record):
            self.distill(str(record["attack_shape"]))

    def list_episodes(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute("SELECT record_json FROM episodes ORDER BY created_at DESC, rowid DESC LIMIT ?", (limit,)).fetchall()
        entries = [json.loads(row[0]) for row in rows]
        for entry in entries:
            if "safe_action_executed" not in entry and "task_completed" in entry:
                entry["safe_action_executed"] = bool(entry.pop("task_completed"))
                entry["safe_action_by"] = entry.pop("completed_by", "legacy_record")
        return entries

    def list_patterns(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute("SELECT pattern_id, attack_shape, dimension, recommended_defense, supporting_episodes FROM patterns ORDER BY updated_at DESC").fetchall()
            episode_rows = db.execute("SELECT episode_id, record_json FROM episodes").fetchall()
        verified_ids: set[str] = set()
        for episode_id, raw in episode_rows:
            entry = json.loads(raw)
            if _credible_docker_episode(entry) and entry.get("attack_action_proposed") is not False:
                verified_ids.add(episode_id)
        out: list[dict[str, Any]] = []
        for row in rows:
            supporting = json.loads(row[4])
            if not isinstance(supporting, list) or not supporting or any(
                episode_id not in verified_ids for episode_id in supporting
            ):
                continue
            out.append({"pattern_id": row[0], "attack_shape": row[1], "dimension": row[2],
                        "recommended_defense": row[3], "supporting_episodes": supporting})
        return out

    def distill(self, attack_shape: str) -> None:
        with self._connect() as db:
            rows = db.execute("SELECT record_json FROM episodes WHERE attack_shape=? ORDER BY created_at DESC, rowid DESC LIMIT 20", (attack_shape,)).fetchall()
        if not rows:
            return
        episodes = [json.loads(row[0]) for row in rows]
        episodes = [entry for entry in episodes if _credible_docker_episode(entry) and
                    entry.get("attack_action_proposed") is not False]
        if not episodes:
            return
        blocked = [entry for entry in episodes if entry.get("containment_held") and
                   (entry.get("safe_action_executed") or entry.get("task_completed"))]
        winning = blocked[0] if blocked else episodes[0]
        verdicts = winning.get("boundary_verdicts", [])
        fired = [item.get("dimension", "") for item in verdicts if item.get("decision") == "deny"]
        worker_denials = [event.get("result", {}).get("policy_denial")
                          for event in winning.get("worker_trajectory", [])
                          if isinstance(event, dict) and event.get("result", {}).get("policy_denial") in
                          {"D1", "D2", "D3", "D4", "D5", "D6"}]
        dimension = fired[0] if fired else worker_denials[0] if worker_denials else "unattributed"
        defense = (winning.get("blue_action") or {}).get("plugin_id") or ("review and add defense" if not blocked else "existing mounted controls")
        supporting = [entry["episode_id"] for entry in episodes]
        pattern_id = "pat_" + re.sub(r"[^a-z0-9_]+", "_", attack_shape.lower())[:64]
        with self._connect() as db:
            db.execute("""INSERT INTO patterns VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(pattern_id) DO UPDATE SET dimension=excluded.dimension,
                recommended_defense=excluded.recommended_defense,
                supporting_episodes=excluded.supporting_episodes,
                updated_at=excluded.updated_at""", (
                pattern_id, attack_shape, dimension, str(defense), json.dumps(supporting),
                datetime.now(timezone.utc).isoformat(),
            ))

    def retrieve(self, query: str, *, perspective: str, top_n: int = 5, hosted: bool = False) -> list[dict[str, Any]]:
        """Retrieve relevant attempts or successful defenses for red/blue."""
        if perspective not in {"red", "blue"}:
            raise ValueError("perspective must be red or blue")
        entries = [entry for entry in self.list_episodes(limit=500) if _credible_docker_episode(entry)]
        candidates = (entries if perspective == "red" else
                      [entry for entry in entries if entry.get("attack_action_proposed") is not False and
                       entry.get("containment_held") and entry.get("safe_action_executed")])
        query_terms = _tokens(query)
        candidates.sort(key=lambda entry: len(query_terms & _tokens(
            entry.get("attack_shape", "") + " " + entry.get("diagnosis", {}).get("analysis", "")
        )), reverse=True)
        if hosted and candidates:
            try:
                from crucible.vultr import rerank
                documents = [json.dumps(entry, sort_keys=True) for entry in candidates[:30]]
                ranked = rerank(query, documents, top_n=min(top_n, len(documents)))
                indices = [item.get("index") for item in ranked]
                selected = [candidates[index] for index in indices if isinstance(index, int) and 0 <= index < len(documents)]
                if selected:
                    return selected
            except Exception:
                pass  # Local retrieval remains available if the optional reranker fails.
        return candidates[:top_n]
