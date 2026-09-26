"""SQLite 持久化：版本化对象、运行事实、检查点、事件、发布候选与审批。

所有已发布规则与事实只追加、不覆盖；多语句写入通过 ``transaction()`` 保持原子性。
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager

from .util import canonical, digest_of

SCHEMA = """
CREATE TABLE IF NOT EXISTS policies (
  tenant TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  body TEXT NOT NULL,
  digest TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  PRIMARY KEY (tenant, policy_id, version)
);
CREATE TABLE IF NOT EXISTS scenarios (
  tenant TEXT NOT NULL,
  scenario_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  body TEXT NOT NULL,
  digest TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  PRIMARY KEY (tenant, scenario_id, version)
);
CREATE TABLE IF NOT EXISTS fixtures (
  tenant TEXT NOT NULL,
  fixture_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  body TEXT NOT NULL,
  digest TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  PRIMARY KEY (tenant, fixture_id, version)
);
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY,
  tenant TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  policy_version INTEGER NOT NULL,
  scenario_id TEXT NOT NULL,
  scenario_version INTEGER NOT NULL,
  fixture_id TEXT NOT NULL,
  fixture_version INTEGER NOT NULL,
  status TEXT NOT NULL,
  clock_start TEXT NOT NULL,
  lease_owner TEXT,
  lease_expires_at TEXT,
  attempt INTEGER NOT NULL DEFAULT 0,
  steps_done INTEGER NOT NULL DEFAULT 0,
  duration_ms INTEGER NOT NULL DEFAULT 0,
  digest TEXT,
  created_at TEXT NOT NULL,
  completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_runs_gate
  ON runs (tenant, policy_id, policy_version, scenario_id, status);
CREATE TABLE IF NOT EXISTS step_results (
  run_id TEXT NOT NULL,
  step_index INTEGER NOT NULL,
  action TEXT NOT NULL,
  decision TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  verdict TEXT NOT NULL,
  resolved_path TEXT,
  detail TEXT NOT NULL,
  at TEXT NOT NULL,
  duration_ms INTEGER NOT NULL,
  PRIMARY KEY (run_id, step_index)
);
CREATE TABLE IF NOT EXISTS manifest_entries (
  run_id TEXT NOT NULL,
  path TEXT NOT NULL,
  digest TEXT NOT NULL,
  persistent INTEGER NOT NULL,
  step_index INTEGER NOT NULL,
  PRIMARY KEY (run_id, path)
);
CREATE TABLE IF NOT EXISTS checkpoints (
  run_id TEXT NOT NULL,
  step_index INTEGER NOT NULL,
  state TEXT NOT NULL,
  saved_at TEXT NOT NULL,
  PRIMARY KEY (run_id, step_index)
);
CREATE TABLE IF NOT EXISTS events (
  event_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  aggregate_id TEXT NOT NULL,
  payload TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  actor_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_aggregate ON events (aggregate_id, occurred_at);
CREATE TABLE IF NOT EXISTS candidates (
  tenant TEXT NOT NULL,
  candidate_id TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  policy_version INTEGER NOT NULL,
  gate TEXT NOT NULL,
  status TEXT NOT NULL,
  decision TEXT,
  created_at TEXT NOT NULL,
  decided_at TEXT,
  PRIMARY KEY (tenant, candidate_id)
);
CREATE TABLE IF NOT EXISTS approvals (
  approval_id TEXT PRIMARY KEY,
  tenant TEXT NOT NULL,
  candidate_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  decision TEXT NOT NULL,
  reason TEXT NOT NULL,
  approver TEXT NOT NULL,
  created_at TEXT NOT NULL
);
"""

_KIND_TABLE = {"policy": "policies", "scenario": "scenarios", "fixture": "fixtures"}
_KIND_KEY = {"policy": "policy_id", "scenario": "scenario_id", "fixture": "fixture_id"}


def content_digest(body: dict) -> str:
    """版本化对象的内容摘要（不含 version 字段）。"""
    return digest_of({k: v for k, v in body.items() if k != "version"})


class Store:
    """SQLite 存储。变更方法须在 ``transaction()`` 内调用以保证原子性。"""

    def __init__(self, path: str = ":memory:"):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout = 30000")
        if path != ":memory:":
            self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    @contextmanager
    def transaction(self):
        with self.conn:
            yield self.conn

    # ---- 版本化对象（策略 / 场景 / 夹具）----

    def save_object(self, kind: str, tenant: str, body: dict, actor: str, at: str) -> dict:
        """内容寻址版本化：内容未变返回现有版本，变化则追加新版本。"""
        table = _KIND_TABLE[kind]
        key = _KIND_KEY[kind]
        obj_id = body[key]
        digest = content_digest(body)
        row = self.conn.execute(
            f"SELECT version, digest FROM {table} WHERE tenant=? AND {key}=? "
            "ORDER BY version DESC LIMIT 1",
            (tenant, obj_id),
        ).fetchone()
        if row is not None and row["digest"] == digest:
            return {"id": obj_id, "version": row["version"], "digest": digest, "created": False}
        version = row["version"] + 1 if row is not None else 1
        stored = dict(body)
        stored["version"] = version
        self.conn.execute(
            f"INSERT INTO {table} (tenant, {key}, version, body, digest, created_at, created_by) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (tenant, obj_id, version, canonical(stored), digest, at, actor),
        )
        return {"id": obj_id, "version": version, "digest": digest, "created": True}

    def get_object(self, kind: str, tenant: str, obj_id: str, version: int | None = None) -> dict:
        table = _KIND_TABLE[kind]
        key = _KIND_KEY[kind]
        if version is None:
            row = self.conn.execute(
                f"SELECT body FROM {table} WHERE tenant=? AND {key}=? ORDER BY version DESC LIMIT 1",
                (tenant, obj_id),
            ).fetchone()
        else:
            row = self.conn.execute(
                f"SELECT body FROM {table} WHERE tenant=? AND {key}=? AND version=?",
                (tenant, obj_id, version),
            ).fetchone()
        if row is None:
            raise KeyError(f"{kind} 不存在：{obj_id}@{version if version is not None else 'latest'}")
        return json.loads(row["body"])

    # ---- 运行 ----

    def insert_run(self, record: dict) -> None:
        self.conn.execute(
            "INSERT INTO runs (run_id, tenant, policy_id, policy_version, scenario_id, "
            "scenario_version, fixture_id, fixture_version, status, clock_start, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record["run_id"], record["tenant"], record["policy_id"], record["policy_version"],
                record["scenario_id"], record["scenario_version"], record["fixture_id"],
                record["fixture_version"], record["status"], record["clock_start"],
                record["created_at"],
            ),
        )

    def get_run(self, run_id: str) -> dict:
        row = self.conn.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        if row is None:
            raise KeyError(f"运行不存在：{run_id}")
        return dict(row)

    def list_runs(self, tenant: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT run_id, scenario_id, policy_id, policy_version, status, digest, created_at "
            "FROM runs WHERE tenant=? ORDER BY created_at, run_id",
            (tenant,),
        ).fetchall()
        return [dict(r) for r in rows]

    def lease_run(self, run_id: str, owner: str, expires_at: str, now: str) -> bool:
        """原子租约：仅当运行待领取或租约已过期时生效，保证只有一个执行器获胜。"""
        cur = self.conn.execute(
            "UPDATE runs SET status='leased', lease_owner=?, lease_expires_at=?, attempt=attempt+1 "
            "WHERE run_id=? AND (status='queued' OR (status IN ('leased','running') "
            "AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?))",
            (owner, expires_at, run_id, now),
        )
        return cur.rowcount == 1

    def next_leasable_run(self, tenant: str, now: str) -> str | None:
        row = self.conn.execute(
            "SELECT run_id FROM runs WHERE tenant=? AND (status='queued' OR (status IN "
            "('leased','running') AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?)) "
            "ORDER BY created_at, run_id LIMIT 1",
            (tenant, now),
        ).fetchone()
        return row["run_id"] if row else None

    def set_running(self, run_id: str) -> None:
        self.conn.execute("UPDATE runs SET status='running' WHERE run_id=? AND status='leased'",
                          (run_id,))

    def set_steps_done(self, run_id: str, steps_done: int) -> None:
        self.conn.execute("UPDATE runs SET steps_done=MAX(steps_done, ?) WHERE run_id=?",
                          (steps_done, run_id))

    def complete_run(self, run_id: str, status: str, digest: str, duration_ms: int, at: str) -> None:
        self.conn.execute(
            "UPDATE runs SET status=?, digest=?, duration_ms=?, completed_at=?, "
            "lease_owner=NULL, lease_expires_at=NULL "
            "WHERE run_id=? AND status IN ('leased','running')",
            (status, digest, duration_ms, at, run_id),
        )

    def latest_completed_run(self, tenant: str, policy_id: str, policy_version: int,
                             scenario_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM runs WHERE tenant=? AND policy_id=? AND policy_version=? AND "
            "scenario_id=? AND status IN ('passed','failed') "
            "ORDER BY created_at DESC, rowid DESC LIMIT 1",
            (tenant, policy_id, policy_version, scenario_id),
        ).fetchone()
        return dict(row) if row else None

    # ---- 步骤、清单与检查点 ----

    def record_step(self, run_id: str, step_index: int, record: dict) -> None:
        """幂等记录步骤：同一步重复写入时校验内容一致，防止双计数。"""
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO step_results (run_id, step_index, action, decision, "
            "reason_code, verdict, resolved_path, detail, at, duration_ms) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id, step_index, canonical(record["action"]), record["decision"],
                record["reason_code"], record["verdict"], record["resolved_path"],
                canonical(record["detail"]), record["at"], record["duration_ms"],
            ),
        )
        if cur.rowcount == 0:
            existing = self.conn.execute(
                "SELECT decision, reason_code, verdict, at FROM step_results "
                "WHERE run_id=? AND step_index=?",
                (run_id, step_index),
            ).fetchone()
            same = existing is not None and (
                existing["decision"], existing["reason_code"], existing["verdict"], existing["at"]
            ) == (record["decision"], record["reason_code"], record["verdict"], record["at"])
            if not same:
                raise RuntimeError(f"步骤事实冲突：run={run_id} step={step_index}")

    def steps_of(self, run_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM step_results WHERE run_id=? ORDER BY step_index", (run_id,)
        ).fetchall()
        return [
            {
                "run_id": r["run_id"], "step_index": r["step_index"],
                "action": json.loads(r["action"]), "decision": r["decision"],
                "reason_code": r["reason_code"], "verdict": r["verdict"],
                "resolved_path": r["resolved_path"], "detail": json.loads(r["detail"]),
                "at": r["at"], "duration_ms": r["duration_ms"],
            }
            for r in rows
        ]

    def add_manifest(self, run_id: str, entries: list[dict]) -> None:
        for entry in entries:
            self.conn.execute(
                "INSERT OR REPLACE INTO manifest_entries (run_id, path, digest, persistent, "
                "step_index) VALUES (?, ?, ?, ?, ?)",
                (run_id, entry["path"], entry["digest"], int(entry["persistent"]),
                 entry["step_index"]),
            )

    def manifest_of(self, run_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM manifest_entries WHERE run_id=? ORDER BY path", (run_id,)
        ).fetchall()
        return [
            {"run_id": r["run_id"], "path": r["path"], "digest": r["digest"],
             "persistent": bool(r["persistent"]), "step_index": r["step_index"]}
            for r in rows
        ]

    def save_checkpoint(self, run_id: str, step_index: int, state: dict, at: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO checkpoints (run_id, step_index, state, saved_at) "
            "VALUES (?, ?, ?, ?)",
            (run_id, step_index, canonical(state), at),
        )

    def latest_checkpoint(self, run_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT step_index, state FROM checkpoints WHERE run_id=? "
            "ORDER BY step_index DESC LIMIT 1",
            (run_id,),
        ).fetchone()
        if row is None:
            return None
        return {"step_index": row["step_index"], "state": json.loads(row["state"])}

    def checkpoint_count(self, run_id: str) -> int:
        return self.conn.execute(
            "SELECT COUNT(*) AS n FROM checkpoints WHERE run_id=?", (run_id,)
        ).fetchone()["n"]

    # ---- 事件（只追加）----

    def emit_event(self, event_id: str, event_type: str, aggregate_id: str,
                   payload: dict, occurred_at: str, actor_id: str) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO events (event_id, event_type, aggregate_id, payload, "
            "occurred_at, actor_id) VALUES (?, ?, ?, ?, ?, ?)",
            (event_id, event_type, aggregate_id, canonical(payload), occurred_at, actor_id),
        )

    def events_for(self, aggregate_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM events WHERE aggregate_id=? ORDER BY occurred_at, event_id",
            (aggregate_id,),
        ).fetchall()
        return [
            {"event_id": r["event_id"], "event_type": r["event_type"],
             "aggregate_id": r["aggregate_id"], "payload": json.loads(r["payload"]),
             "occurred_at": r["occurred_at"], "actor_id": r["actor_id"]}
            for r in rows
        ]

    def all_events(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM events ORDER BY occurred_at, event_id"
        ).fetchall()
        return [
            {"event_id": r["event_id"], "event_type": r["event_type"],
             "aggregate_id": r["aggregate_id"], "payload": json.loads(r["payload"]),
             "occurred_at": r["occurred_at"], "actor_id": r["actor_id"]}
            for r in rows
        ]

    # ---- 发布候选与审批 ----

    def create_candidate(self, tenant: str, candidate_id: str, policy_id: str,
                         policy_version: int, gate: dict, at: str) -> None:
        self.conn.execute(
            "INSERT INTO candidates (tenant, candidate_id, policy_id, policy_version, gate, "
            "status, created_at) VALUES (?, ?, ?, ?, ?, 'draft', ?)",
            (tenant, candidate_id, policy_id, policy_version, canonical(gate), at),
        )

    def get_candidate(self, tenant: str, candidate_id: str) -> dict:
        row = self.conn.execute(
            "SELECT * FROM candidates WHERE tenant=? AND candidate_id=?",
            (tenant, candidate_id),
        ).fetchone()
        if row is None:
            raise KeyError(f"发布候选不存在：{candidate_id}")
        result = dict(row)
        result["gate"] = json.loads(result["gate"])
        result["decision"] = json.loads(result["decision"]) if result["decision"] else None
        return result

    def update_candidate_decision(self, tenant: str, candidate_id: str, status: str,
                                  decision: dict, decided_at: str) -> None:
        # 已发布的候选不可改写
        self.conn.execute(
            "UPDATE candidates SET status=?, decision=?, decided_at=? "
            "WHERE tenant=? AND candidate_id=? AND status != 'released'",
            (status, canonical(decision), decided_at, tenant, candidate_id),
        )

    def add_approval(self, approval_id: str, tenant: str, candidate_id: str, scope: str,
                     decision: str, reason: str, approver: str, at: str) -> None:
        self.conn.execute(
            "INSERT INTO approvals (approval_id, tenant, candidate_id, scope, decision, reason, "
            "approver, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (approval_id, tenant, candidate_id, scope, decision, reason, approver, at),
        )

    def approvals_of(self, tenant: str, candidate_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM approvals WHERE tenant=? AND candidate_id=? "
            "ORDER BY created_at, approval_id",
            (tenant, candidate_id),
        ).fetchall()
        return [dict(r) for r in rows]

    def latest_approval(self, tenant: str, candidate_id: str, scope: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM approvals WHERE tenant=? AND candidate_id=? AND scope=? "
            "ORDER BY created_at DESC, approval_id DESC LIMIT 1",
            (tenant, candidate_id, scope),
        ).fetchone()
        return dict(row) if row else None
