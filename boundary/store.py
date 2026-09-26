"""SQLite 存储层：版本化对象、运行、步骤、检查点、候选与事件日志。

所有写操作都在事务内完成；事件日志只追加，保证审计可追溯。
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS policies (
    policy_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    content_json TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'draft',
    created_at TEXT NOT NULL,
    PRIMARY KEY (policy_id, version)
);
CREATE TABLE IF NOT EXISTS scenarios (
    scenario_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    content_json TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (scenario_id, version)
);
CREATE TABLE IF NOT EXISTS fixtures (
    fixture_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    content_json TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (fixture_id, version)
);
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    scenario_id TEXT NOT NULL,
    scenario_version INTEGER NOT NULL,
    policy_id TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    fixture_id TEXT NOT NULL,
    fixture_version INTEGER NOT NULL,
    task_id TEXT NOT NULL,
    clock_json TEXT NOT NULL,
    state TEXT NOT NULL,
    outcome TEXT,
    budget_json TEXT,
    digest TEXT,
    manifest_hash TEXT,
    executor_id TEXT,
    fencing_token INTEGER NOT NULL DEFAULT 0,
    lease_expires_at TEXT,
    created_at TEXT NOT NULL,
    completed_at TEXT
);
CREATE TABLE IF NOT EXISTS steps (
    run_id TEXT NOT NULL,
    step_index INTEGER NOT NULL,
    step_key TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    expect TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    duration_ms REAL NOT NULL,
    recorded_at TEXT NOT NULL,
    fencing_token INTEGER NOT NULL,
    PRIMARY KEY (run_id, step_index)
);
CREATE TABLE IF NOT EXISTS manifest (
    run_id TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    origin_step INTEGER NOT NULL,
    PRIMARY KEY (run_id, path)
);
CREATE TABLE IF NOT EXISTS checkpoints (
    run_id TEXT NOT NULL,
    step_index INTEGER NOT NULL,
    state_hash TEXT NOT NULL,
    saved_at TEXT NOT NULL,
    PRIMARY KEY (run_id, step_index)
);
CREATE TABLE IF NOT EXISTS candidates (
    candidate_id TEXT PRIMARY KEY,
    policy_id TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    requirements_json TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'draft',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    scope TEXT NOT NULL,
    decision TEXT NOT NULL,
    approver TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evaluations (
    evaluation_id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL,
    verdict TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    evaluated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    actor_id TEXT NOT NULL
);
"""


class Store:
    """对 SQLite 的薄封装；调用方负责在事务内组合多个写操作。"""

    def __init__(self, path: str = ":memory:"):
        self.conn = sqlite3.connect(path, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self._tx_depth = 0
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    @contextmanager
    def transaction(self):
        """可重入事务：嵌套调用并入最外层事务，便于服务层组合。"""
        if self._tx_depth > 0:
            self._tx_depth += 1
            try:
                yield
            finally:
                self._tx_depth -= 1
            return
        self.conn.execute("BEGIN IMMEDIATE")
        self._tx_depth = 1
        try:
            yield
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        finally:
            self._tx_depth = 0

    # ---- 基础读写 ----
    def _one(self, sql: str, params: tuple = ()) -> dict | None:
        row = self.conn.execute(sql, params).fetchone()
        return dict(row) if row is not None else None

    def _all(self, sql: str, params: tuple = ()) -> list[dict]:
        return [dict(row) for row in self.conn.execute(sql, params)]

    def _exec(self, sql: str, params: tuple = ()) -> None:
        self.conn.execute(sql, params)

    def count(self, table: str) -> int:
        assert table in {
            "policies", "scenarios", "fixtures", "runs", "steps", "manifest",
            "checkpoints", "candidates", "approvals", "evaluations", "events",
        }
        return self._one(f"SELECT COUNT(*) AS n FROM {table}")["n"]

    # ---- 版本化对象 ----
    def next_version(self, table: str, id_column: str, object_id: str) -> int:
        row = self._one(
            f"SELECT MAX(version) AS v FROM {table} WHERE {id_column} = ?", (object_id,)
        )
        return (row["v"] or 0) + 1

    def insert_policy(self, policy_id, version, content_json, content_hash, created_at):
        self._exec(
            "INSERT INTO policies VALUES (?, ?, ?, ?, 'draft', ?)",
            (policy_id, version, content_json, content_hash, created_at),
        )

    def get_policy(self, policy_id, version):
        return self._one(
            "SELECT * FROM policies WHERE policy_id = ? AND version = ?",
            (policy_id, version),
        )

    def set_policy_state(self, policy_id, version, state):
        self._exec(
            "UPDATE policies SET state = ? WHERE policy_id = ? AND version = ?",
            (state, policy_id, version),
        )

    def insert_scenario(self, scenario_id, version, content_json, content_hash, created_at):
        self._exec(
            "INSERT INTO scenarios VALUES (?, ?, ?, ?, ?)",
            (scenario_id, version, content_json, content_hash, created_at),
        )

    def get_scenario(self, scenario_id, version):
        return self._one(
            "SELECT * FROM scenarios WHERE scenario_id = ? AND version = ?",
            (scenario_id, version),
        )

    def insert_fixture(self, fixture_id, version, content_json, content_hash, created_at):
        self._exec(
            "INSERT INTO fixtures VALUES (?, ?, ?, ?, ?)",
            (fixture_id, version, content_json, content_hash, created_at),
        )

    def get_fixture(self, fixture_id, version):
        return self._one(
            "SELECT * FROM fixtures WHERE fixture_id = ? AND version = ?",
            (fixture_id, version),
        )

    # ---- 运行 ----
    def insert_run(self, record: dict) -> None:
        self._exec(
            "INSERT INTO runs(run_id, scenario_id, scenario_version, policy_id, "
            "policy_version, fixture_id, fixture_version, task_id, clock_json, state, "
            "outcome, budget_json, digest, manifest_hash, executor_id, fencing_token, "
            "lease_expires_at, created_at, completed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, 0, NULL, ?, NULL)",
            (
                record["run_id"], record["scenario_id"], record["scenario_version"],
                record["policy_id"], record["policy_version"], record["fixture_id"],
                record["fixture_version"], record["task_id"], record["clock_json"],
                record["state"], record["created_at"],
            ),
        )

    def get_run(self, run_id):
        return self._one("SELECT * FROM runs WHERE run_id = ?", (run_id,))

    def update_run(self, run_id, **fields) -> None:
        assignments = ", ".join(f"{name} = ?" for name in fields)
        self._exec(
            f"UPDATE runs SET {assignments} WHERE run_id = ?",
            (*fields.values(), run_id),
        )

    def list_runs(self):
        return self._all("SELECT * FROM runs ORDER BY created_at, run_id")

    def latest_completed_run(self, policy_id, policy_version, scenario_id,
                             scenario_version, fixture_id, fixture_version):
        return self._one(
            "SELECT * FROM runs WHERE policy_id = ? AND policy_version = ? "
            "AND scenario_id = ? AND scenario_version = ? AND fixture_id = ? "
            "AND fixture_version = ? AND state IN ('passed', 'failed') "
            "ORDER BY rowid DESC LIMIT 1",
            (policy_id, policy_version, scenario_id, scenario_version,
             fixture_id, fixture_version),
        )

    # ---- 步骤 ----
    def insert_step(self, run_id, step_index, step_key, decision, reason_code,
                    expect, payload_json, duration_ms, recorded_at, fencing_token):
        self._exec(
            "INSERT INTO steps VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, step_index, step_key, decision, reason_code, expect,
             payload_json, duration_ms, recorded_at, fencing_token),
        )

    def get_step(self, run_id, step_index):
        return self._one(
            "SELECT * FROM steps WHERE run_id = ? AND step_index = ?",
            (run_id, step_index),
        )

    def list_steps(self, run_id):
        return self._all(
            "SELECT * FROM steps WHERE run_id = ? ORDER BY step_index", (run_id,)
        )

    def delete_steps_after(self, run_id, step_index):
        self._exec(
            "DELETE FROM steps WHERE run_id = ? AND step_index > ?",
            (run_id, step_index),
        )

    def delete_all_steps(self, run_id):
        self._exec("DELETE FROM steps WHERE run_id = ?", (run_id,))

    # ---- 文件清单 ----
    def upsert_manifest(self, run_id, entries):
        for entry in entries:
            self._exec(
                "INSERT OR REPLACE INTO manifest VALUES (?, ?, ?, ?, ?)",
                (run_id, entry["path"], entry["sha256"], entry["size_bytes"],
                 entry["origin_step"]),
            )

    def list_manifest(self, run_id):
        return self._all(
            "SELECT * FROM manifest WHERE run_id = ? ORDER BY path", (run_id,)
        )

    def delete_manifest_after(self, run_id, step_index):
        self._exec(
            "DELETE FROM manifest WHERE run_id = ? AND origin_step > ?",
            (run_id, step_index),
        )

    def delete_all_manifest(self, run_id):
        self._exec("DELETE FROM manifest WHERE run_id = ?", (run_id,))

    # ---- 检查点 ----
    def insert_checkpoint(self, run_id, step_index, state_hash, saved_at):
        self._exec(
            "INSERT OR REPLACE INTO checkpoints VALUES (?, ?, ?, ?)",
            (run_id, step_index, state_hash, saved_at),
        )

    def latest_checkpoint(self, run_id):
        return self._one(
            "SELECT * FROM checkpoints WHERE run_id = ? "
            "ORDER BY step_index DESC LIMIT 1",
            (run_id,),
        )

    def list_checkpoints(self, run_id):
        return self._all(
            "SELECT * FROM checkpoints WHERE run_id = ? ORDER BY step_index",
            (run_id,),
        )

    def delete_checkpoint(self, run_id, step_index):
        self._exec(
            "DELETE FROM checkpoints WHERE run_id = ? AND step_index = ?",
            (run_id, step_index),
        )

    # ---- 候选与审批 ----
    def insert_candidate(self, candidate_id, policy_id, policy_version,
                         requirements_json, created_at):
        self._exec(
            "INSERT INTO candidates VALUES (?, ?, ?, ?, 'draft', ?)",
            (candidate_id, policy_id, policy_version, requirements_json, created_at),
        )

    def get_candidate(self, candidate_id):
        return self._one(
            "SELECT * FROM candidates WHERE candidate_id = ?", (candidate_id,)
        )

    def update_candidate_state(self, candidate_id, state):
        self._exec(
            "UPDATE candidates SET state = ? WHERE candidate_id = ?",
            (state, candidate_id),
        )

    def insert_approval(self, approval_id, candidate_id, kind, scope, decision,
                        approver, reason, created_at):
        self._exec(
            "INSERT INTO approvals VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (approval_id, candidate_id, kind, scope, decision, approver, reason,
             created_at),
        )

    def list_approvals(self, candidate_id):
        return self._all(
            "SELECT * FROM approvals WHERE candidate_id = ? ORDER BY created_at, "
            "approval_id",
            (candidate_id,),
        )

    def insert_evaluation(self, evaluation_id, candidate_id, verdict, evidence_json,
                          evaluated_at):
        self._exec(
            "INSERT INTO evaluations VALUES (?, ?, ?, ?, ?)",
            (evaluation_id, candidate_id, verdict, evidence_json, evaluated_at),
        )

    def latest_evaluation(self, candidate_id):
        return self._one(
            "SELECT * FROM evaluations WHERE candidate_id = ? "
            "ORDER BY rowid DESC LIMIT 1",
            (candidate_id,),
        )

    # ---- 事件日志 ----
    def append_event(self, event_id, event_type, aggregate_id, payload_json,
                     occurred_at, actor_id):
        self._exec(
            "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?)",
            (event_id, event_type, aggregate_id, payload_json, occurred_at, actor_id),
        )

    def list_events(self, aggregate_id=None):
        if aggregate_id is None:
            return self._all("SELECT * FROM events ORDER BY rowid")
        return self._all(
            "SELECT * FROM events WHERE aggregate_id = ? ORDER BY rowid",
            (aggregate_id,),
        )
