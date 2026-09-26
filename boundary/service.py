"""平台门面：版本化对象、确定性运行、租约、检查点、发布门禁与差异查询。"""
from __future__ import annotations

import json
from datetime import timedelta

from . import models
from .canon import canonical, hash_obj, sha256_text
from .clock import FrozenClock, SystemClock, iso, parse_iso
from .diff import diff_step_payloads
from .engine import Engine
from .errors import (
    BoundaryError,
    DeterminismError,
    LeaseConflictError,
    NotFoundError,
    StaleLeaseError,
)
from .fixtures import VirtualFS
from .store import Store

TERMINAL_RUN_STATES = ("passed", "failed", "blocked")
APPROVAL_KINDS = ("must_pass", "budget")


def evaluate_budget(policy_content: dict, step_payloads: list[dict]) -> dict:
    """按策略中的 performance_budget 评估步骤耗时。"""
    budget = policy_content.get("performance_budget", {})
    max_step = budget.get("max_step_ms")
    max_run = budget.get("max_run_ms")
    durations = [float(payload["duration_ms"]) for payload in step_payloads]
    step_violations = [
        index for index, value in enumerate(durations)
        if max_step is not None and value > float(max_step)
    ]
    run_ms = sum(durations)
    run_violation = bool(max_run is not None and run_ms > float(max_run))
    return {
        "max_step_ms": max_step,
        "max_run_ms": max_run,
        "run_ms": run_ms,
        "step_violations": step_violations,
        "run_violation": run_violation,
        "ok": not step_violations and not run_violation,
    }


class BoundaryService:
    """隔离边界回归平台的服务门面。

    clock 决定事件与租约的时间语义；每次运行的步骤计时由运行自带的
    冻结时钟驱动（queue_run 的 clock_start / step_ms_default）。
    """

    def __init__(self, db_path: str = ":memory:", clock=None):
        self.store = Store(db_path)
        self.clock = clock or SystemClock()

    def close(self) -> None:
        self.store.close()

    # ---- 内部工具 ----
    def _now(self) -> str:
        return iso(self.clock.now())

    def _event(self, event_type: str, aggregate_id: str, payload: dict,
               actor: str) -> None:
        event_id = f"evt-{self.store.count('events') + 1:06d}"
        self.store.append_event(
            event_id, event_type, aggregate_id, canonical(payload),
            self._now(), actor,
        )

    def _require_run(self, run_id: str) -> dict:
        run = self.store.get_run(run_id)
        if run is None:
            raise NotFoundError(f"运行不存在：{run_id}")
        return run

    # ---- 版本化对象 ----
    def create_policy(self, policy_id: str, content: dict,
                      actor: str = "system") -> int:
        """登记新的策略版本；已登记版本不可变。"""
        with self.store.transaction():
            version = self.store.next_version("policies", "policy_id", policy_id)
            self.store.insert_policy(policy_id, version, canonical(content),
                                     hash_obj(content), self._now())
            self._event("policy.created", policy_id, {
                "version": version, "content_hash": hash_obj(content),
            }, actor)
        return version

    def create_scenario(self, scenario_id: str, content: dict,
                        actor: str = "system") -> int:
        """登记新的场景版本；步骤类型必须在已知原语集合内。"""
        steps = content.get("steps")
        if not isinstance(steps, list) or not steps:
            raise BoundaryError("场景必须包含非空 steps 列表")
        for index, spec in enumerate(steps):
            if spec.get("kind") not in models.STEP_KINDS:
                raise BoundaryError(
                    f"步骤 {index} 类型未知：{spec.get('kind')}"
                )
        with self.store.transaction():
            version = self.store.next_version("scenarios", "scenario_id",
                                              scenario_id)
            self.store.insert_scenario(scenario_id, version, canonical(content),
                                       hash_obj(content), self._now())
            self._event("scenario.versioned", scenario_id, {
                "version": version, "content_hash": hash_obj(content),
            }, actor)
        return version

    def create_fixture(self, fixture_id: str, content: dict,
                       actor: str = "system") -> int:
        """登记新的夹具版本；内容是冻结的虚拟文件系统视图。"""
        with self.store.transaction():
            version = self.store.next_version("fixtures", "fixture_id", fixture_id)
            self.store.insert_fixture(fixture_id, version, canonical(content),
                                      hash_obj(content), self._now())
            self._event("fixture.versioned", fixture_id, {
                "version": version, "content_hash": hash_obj(content),
            }, actor)
        return version

    # ---- 运行排队与租约 ----
    def queue_run(self, scenario_id: str, scenario_version: int,
                  policy_id: str, policy_version: int,
                  fixture_id: str, fixture_version: int, *,
                  clock_start: str | None = None,
                  step_ms_default: float = 5.0,
                  nonce: str | None = None,
                  actor: str = "system") -> str:
        """把一次运行排入队列；运行绑定冻结的策略、场景与夹具版本。"""
        scenario = self.store.get_scenario(scenario_id, scenario_version)
        if scenario is None:
            raise NotFoundError(f"场景版本不存在：{scenario_id}@{scenario_version}")
        if self.store.get_policy(policy_id, policy_version) is None:
            raise NotFoundError(f"策略版本不存在：{policy_id}@{policy_version}")
        if self.store.get_fixture(fixture_id, fixture_version) is None:
            raise NotFoundError(f"夹具版本不存在：{fixture_id}@{fixture_version}")
        clock_config = {
            "start": clock_start or self._now(),
            "step_ms_default": float(step_ms_default),
        }
        nonce = nonce or sha256_text(
            canonical({"clock": clock_config, "seq": self.store.count("runs")})
        )[:12]
        run_id = "run-" + sha256_text(canonical({
            "scenario": [scenario_id, scenario_version],
            "policy": [policy_id, policy_version],
            "fixture": [fixture_id, fixture_version],
            "clock": clock_config,
            "nonce": nonce,
        }))[:16]
        with self.store.transaction():
            if self.store.get_run(run_id) is not None:
                return run_id
            task_id = json.loads(scenario["content_json"]).get("task_id", "task-1")
            self.store.insert_run({
                "run_id": run_id,
                "scenario_id": scenario_id,
                "scenario_version": scenario_version,
                "policy_id": policy_id,
                "policy_version": policy_version,
                "fixture_id": fixture_id,
                "fixture_version": fixture_version,
                "task_id": task_id,
                "clock_json": canonical(clock_config),
                "state": "queued",
                "created_at": self._now(),
            })
            self._event("run.queued", run_id, {
                "scenario_id": scenario_id, "scenario_version": scenario_version,
                "policy_id": policy_id, "policy_version": policy_version,
                "fixture_id": fixture_id, "fixture_version": fixture_version,
                "clock": clock_config,
            }, actor)
        return run_id

    def claim_run(self, run_id: str, executor_id: str,
                  lease_seconds: float = 30.0,
                  actor: str = "system") -> dict | None:
        """争领运行租约。租约未过期且属于他人时返回 None。

        成功时 fencing_token 单调递增，旧令牌立即失效。
        """
        with self.store.transaction():
            run = self._require_run(run_id)
            if run["state"] in TERMINAL_RUN_STATES:
                return None
            now = self.clock.now()
            expires_at = run["lease_expires_at"]
            if expires_at and parse_iso(expires_at) > now \
                    and run["executor_id"] != executor_id:
                return None
            token = int(run["fencing_token"]) + 1
            lease_expires = iso(now + timedelta(seconds=lease_seconds))
            self.store.update_run(
                run_id,
                executor_id=executor_id,
                fencing_token=token,
                lease_expires_at=lease_expires,
                state="leased",
            )
            self._event("run.leased", run_id, {
                "executor_id": executor_id, "fencing_token": token,
                "lease_expires_at": lease_expires,
            }, actor)
        return {
            "run_id": run_id,
            "executor_id": executor_id,
            "fencing_token": token,
            "lease_expires_at": lease_expires,
        }

    # ---- 步骤录入与检查点 ----
    def record_step(self, run_id: str, payload: dict, produced: list[dict],
                    fencing_token: int, actor: str = "system") -> bool:
        """录入一步结果。重复录入相同结果是幂等空操作（不双计数）；
        录入不同结果说明确定性被破坏，运行转为 blocked。"""
        try:
            with self.store.transaction():
                run = self._require_run(run_id)
                if int(run["fencing_token"]) != int(fencing_token):
                    raise StaleLeaseError(
                        f"运行 {run_id} 的栅栏令牌已失效："
                        f"持有 {run['fencing_token']}，收到 {fencing_token}"
                    )
                existing = self.store.get_step(run_id, payload["step_index"])
                if existing is not None:
                    if existing["payload_json"] == canonical(payload):
                        return False
                    raise DeterminismError(
                        f"运行 {run_id} 步骤 {payload['step_index']} "
                        "被录入了不同结果"
                    )
                self.store.insert_step(
                    run_id, payload["step_index"], payload["key"],
                    payload["decision"], payload["reason_code"],
                    payload["expect"], canonical(payload),
                    payload["duration_ms"], self._now(), fencing_token,
                )
                self.store.upsert_manifest(run_id, produced)
                if run["state"] in ("leased", "paused"):
                    self.store.update_run(run_id, state="running")
                self._event("step.recorded", run_id, {
                    "step_index": payload["step_index"], "key": payload["key"],
                    "decision": payload["decision"],
                    "reason_code": payload["reason_code"],
                }, actor)
            return True
        except DeterminismError:
            # 在事务外标记，避免随冲突回滚
            self.store.update_run(run_id, state="blocked")
            raise

    def save_checkpoint(self, run_id: str, step_index: int, fencing_token: int,
                        actor: str = "system") -> str:
        """在 step_index 处保存检查点；状态摘要覆盖 0..step_index 的步骤。"""
        with self.store.transaction():
            run = self._require_run(run_id)
            if int(run["fencing_token"]) != int(fencing_token):
                raise StaleLeaseError(f"运行 {run_id} 的栅栏令牌已失效")
            payloads = [
                json.loads(row["payload_json"])
                for row in self.store.list_steps(run_id)
                if row["step_index"] <= step_index
            ]
            state_hash = hash_obj(payloads)
            self.store.insert_checkpoint(run_id, step_index, state_hash,
                                         self._now())
            self._event("checkpoint.saved", run_id, {
                "step_index": step_index, "state_hash": state_hash,
            }, actor)
        return state_hash

    def _resume_position(self, run_id: str) -> int:
        """定位最近的安全检查点并截断未验证的尾部，返回下一步下标。"""
        with self.store.transaction():
            while True:
                checkpoint = self.store.latest_checkpoint(run_id)
                steps = self.store.list_steps(run_id)
                if checkpoint is None:
                    if steps:
                        self.store.delete_all_steps(run_id)
                        self.store.delete_all_manifest(run_id)
                    return 0
                payloads = [
                    json.loads(row["payload_json"]) for row in steps
                    if row["step_index"] <= checkpoint["step_index"]
                ]
                if hash_obj(payloads) == checkpoint["state_hash"]:
                    self.store.delete_steps_after(run_id,
                                                  checkpoint["step_index"])
                    self.store.delete_manifest_after(run_id,
                                                     checkpoint["step_index"])
                    return checkpoint["step_index"] + 1
                # 检查点与已录步骤不一致：不安全，回退到更早的检查点
                self.store.delete_checkpoint(run_id, checkpoint["step_index"])

    # ---- 运行执行 ----
    def _build_engine(self, run: dict) -> tuple[Engine, dict, list[dict]]:
        policy_row = self.store.get_policy(run["policy_id"],
                                           run["policy_version"])
        scenario_row = self.store.get_scenario(run["scenario_id"],
                                               run["scenario_version"])
        fixture_row = self.store.get_fixture(run["fixture_id"],
                                             run["fixture_version"])
        policy = json.loads(policy_row["content_json"])
        scenario = json.loads(scenario_row["content_json"])
        fixture = json.loads(fixture_row["content_json"])
        clock_config = json.loads(run["clock_json"])
        engine = Engine(
            policy, VirtualFS(fixture), task_id=run["task_id"],
            default_step_ms=clock_config.get("step_ms_default", 5.0),
        )
        engine.restore_usage(self.store.list_manifest(run["run_id"]))
        return engine, policy, scenario["steps"]

    def execute_run(self, run_id: str, executor_id: str, *,
                    lease_seconds: float = 30.0,
                    checkpoint_every: int = 1,
                    stop_after: int | None = None,
                    actor: str = "system") -> dict:
        """从安全检查点位置继续执行直到完成或 stop_after 步。

        stop_after 用于模拟执行器中断：运行保持 paused，租约仍持有，
        之后可由任意执行器在租约过期后接管续跑。
        """
        run = self._require_run(run_id)
        if run["state"] in TERMINAL_RUN_STATES:
            return self.get_run(run_id)
        lease = self.claim_run(run_id, executor_id, lease_seconds, actor)
        if lease is None:
            raise LeaseConflictError(f"运行 {run_id} 正被其他执行器租用")
        token = lease["fencing_token"]
        start = self._resume_position(run_id)
        run = self._require_run(run_id)
        engine, _policy, step_specs = self._build_engine(run)
        executed = 0
        for index in range(start, len(step_specs)):
            result = engine.execute_step(step_specs[index], index)
            self.record_step(run_id, result["payload"], result["produced"],
                             token, actor)
            executed += 1
            if (index + 1) % checkpoint_every == 0:
                self.save_checkpoint(run_id, index, token, actor)
            if stop_after is not None and executed >= stop_after:
                self.store.update_run(run_id, state="paused")
                return self.get_run(run_id)
        self.complete_run(run_id, token, actor)
        return self.get_run(run_id)

    def resume_run(self, run_id: str, executor_id: str, **kwargs) -> dict:
        """失败中断后的续跑入口；语义与 execute_run 相同。"""
        return self.execute_run(run_id, executor_id, **kwargs)

    def complete_run(self, run_id: str, fencing_token: int,
                     actor: str = "system") -> str:
        """收尾运行：判定结果、评估预算、计算摘要与清单哈希。"""
        with self.store.transaction():
            run = self._require_run(run_id)
            if int(run["fencing_token"]) != int(fencing_token):
                raise StaleLeaseError(f"运行 {run_id} 的栅栏令牌已失效")
            _engine, policy, step_specs = self._build_engine(run)
            rows = self.store.list_steps(run_id)
            if len(rows) != len(step_specs):
                raise BoundaryError(
                    f"运行 {run_id} 尚未完成全部步骤："
                    f"{len(rows)}/{len(step_specs)}"
                )
            payloads = [json.loads(row["payload_json"]) for row in rows]
            mismatches = [
                p["key"] for p in payloads if p["decision"] != p["expect"]
            ]
            outcome = "passed" if not mismatches else "failed"
            budget = evaluate_budget(policy, payloads)
            manifest = self.store.list_manifest(run_id)
            manifest_view = [
                {"path": m["path"], "sha256": m["sha256"],
                 "size_bytes": m["size_bytes"], "origin_step": m["origin_step"]}
                for m in manifest
            ]
            digest = hash_obj({
                "policy": {"policy_id": run["policy_id"],
                           "version": run["policy_version"],
                           "content_hash": self.store.get_policy(
                               run["policy_id"], run["policy_version"]
                           )["content_hash"]},
                "scenario": {"scenario_id": run["scenario_id"],
                             "version": run["scenario_version"],
                             "content_hash": self.store.get_scenario(
                                 run["scenario_id"], run["scenario_version"]
                             )["content_hash"]},
                "fixture": {"fixture_id": run["fixture_id"],
                            "version": run["fixture_version"],
                            "content_hash": self.store.get_fixture(
                                run["fixture_id"], run["fixture_version"]
                            )["content_hash"]},
                "clock": json.loads(run["clock_json"]),
                "task_id": run["task_id"],
                "steps": payloads,
                "manifest": manifest_view,
                "outcome": outcome,
                "budget_ok": budget["ok"],
            })
            self.store.update_run(
                run_id,
                state=outcome,
                outcome=outcome,
                budget_json=canonical(budget),
                digest=digest,
                manifest_hash=hash_obj(manifest_view),
                completed_at=self._now(),
            )
            self._event("run.completed", run_id, {
                "outcome": outcome, "digest": digest,
                "budget_ok": budget["ok"], "mismatched_steps": mismatches,
            }, actor)
        return digest

    # ---- 发布门禁 ----
    def create_candidate(self, policy_id: str, policy_version: int,
                         requirements: list[dict],
                         actor: str = "system") -> str:
        """创建发布候选：一组必须全部通过的 (场景, 夹具) 组合。"""
        if self.store.get_policy(policy_id, policy_version) is None:
            raise NotFoundError(f"策略版本不存在：{policy_id}@{policy_version}")
        for req in requirements:
            if self.store.get_scenario(req["scenario_id"],
                                       req["scenario_version"]) is None:
                raise NotFoundError(
                    f"场景版本不存在：{req['scenario_id']}@{req['scenario_version']}"
                )
            if self.store.get_fixture(req["fixture_id"],
                                      req["fixture_version"]) is None:
                raise NotFoundError(
                    f"夹具版本不存在：{req['fixture_id']}@{req['fixture_version']}"
                )
        candidate_id = "cand-" + sha256_text(canonical({
            "policy": [policy_id, policy_version],
            "requirements": requirements,
            "seq": self.store.count("candidates"),
        }))[:16]
        with self.store.transaction():
            self.store.insert_candidate(candidate_id, policy_id, policy_version,
                                        canonical(requirements), self._now())
            self._event("candidate.created", candidate_id, {
                "policy_id": policy_id, "policy_version": policy_version,
                "requirements": requirements,
            }, actor)
        return candidate_id

    def approve(self, candidate_id: str, kind: str, scope: str, decision: str,
                approver: str, reason: str) -> str:
        """登记例外审批，覆盖某个具体违例（kind + scope）。"""
        if self.store.get_candidate(candidate_id) is None:
            raise NotFoundError(f"候选不存在：{candidate_id}")
        if kind not in APPROVAL_KINDS:
            raise BoundaryError(f"未知审批类型：{kind}")
        if decision not in ("approved", "rejected"):
            raise BoundaryError(f"未知审批结论：{decision}")
        approval_id = f"appr-{self.store.count('approvals') + 1:04d}"
        with self.store.transaction():
            self.store.insert_approval(approval_id, candidate_id, kind, scope,
                                       decision, approver, reason, self._now())
            self._event("approval.recorded", candidate_id, {
                "approval_id": approval_id, "kind": kind, "scope": scope,
                "decision": decision, "approver": approver,
            }, approver)
        return approval_id

    def evaluate_candidate(self, candidate_id: str,
                           actor: str = "system") -> dict:
        """评估发布门禁：必过场景、性能预算、例外审批三者同时满足才发布。"""
        with self.store.transaction():
            candidate = self.store.get_candidate(candidate_id)
            if candidate is None:
                raise NotFoundError(f"候选不存在：{candidate_id}")
            requirements = json.loads(candidate["requirements_json"])
            policy_row = self.store.get_policy(candidate["policy_id"],
                                               candidate["policy_version"])
            violations = []
            requirements_eval = []
            for req in requirements:
                run = self.store.latest_completed_run(
                    candidate["policy_id"], candidate["policy_version"],
                    req["scenario_id"], req["scenario_version"],
                    req["fixture_id"], req["fixture_version"],
                )
                entry = dict(req)
                if run is None:
                    entry["status"] = "missing_run"
                    violations.append({
                        "kind": "must_pass", "scope": req["scenario_id"],
                        "reason": "missing_run",
                    })
                else:
                    budget = json.loads(run["budget_json"])
                    entry.update({
                        "status": "evaluated",
                        "run_id": run["run_id"],
                        "digest": run["digest"],
                        "outcome": run["outcome"],
                        "budget_ok": budget["ok"],
                    })
                    if run["outcome"] != "passed":
                        violations.append({
                            "kind": "must_pass", "scope": req["scenario_id"],
                            "reason": f"outcome_{run['outcome']}",
                        })
                    if not budget["ok"]:
                        violations.append({
                            "kind": "budget", "scope": req["scenario_id"],
                            "reason": "budget_exceeded",
                        })
                requirements_eval.append(entry)
            approvals = self.store.list_approvals(candidate_id)

            def covered(violation: dict) -> bool:
                return any(
                    a["decision"] == "approved"
                    and a["kind"] == violation["kind"]
                    and a["scope"] == violation["scope"]
                    for a in approvals
                )

            uncovered = [v for v in violations if not covered(v)]
            verdict = "released" if not uncovered else "blocked"
            evidence = {
                "candidate_id": candidate_id,
                "policy": {
                    "policy_id": candidate["policy_id"],
                    "version": candidate["policy_version"],
                    "content_hash": policy_row["content_hash"],
                },
                "requirements": requirements_eval,
                "violations": violations,
                "uncovered_violations": uncovered,
                "approvals": [
                    {"approval_id": a["approval_id"], "kind": a["kind"],
                     "scope": a["scope"], "decision": a["decision"],
                     "approver": a["approver"], "reason": a["reason"]}
                    for a in approvals
                ],
                "verdict": verdict,
                "evaluated_at": self._now(),
            }
            evaluation_id = f"eval-{self.store.count('evaluations') + 1:04d}"
            self.store.insert_evaluation(evaluation_id, candidate_id, verdict,
                                         canonical(evidence), self._now())
            self.store.update_candidate_state(candidate_id, verdict)
            event_type = ("candidate.released" if verdict == "released"
                          else "candidate.blocked")
            self._event(event_type, candidate_id, {
                "evaluation_id": evaluation_id, "verdict": verdict,
                "uncovered_violations": uncovered,
            }, actor)
            if verdict == "released":
                self.store.set_policy_state(candidate["policy_id"],
                                            candidate["policy_version"],
                                            "released")
            evidence["evaluation_id"] = evaluation_id
        return evidence

    # ---- 查询接口 ----
    def get_run(self, run_id: str) -> dict:
        run = self._require_run(run_id)
        steps = [
            json.loads(row["payload_json"]) for row in self.store.list_steps(run_id)
        ]
        manifest = [
            {"path": m["path"], "sha256": m["sha256"],
             "size_bytes": m["size_bytes"], "origin_step": m["origin_step"]}
            for m in self.store.list_manifest(run_id)
        ]
        return {
            "run_id": run["run_id"],
            "state": run["state"],
            "outcome": run["outcome"],
            "digest": run["digest"],
            "manifest_hash": run["manifest_hash"],
            "scenario": {"scenario_id": run["scenario_id"],
                         "version": run["scenario_version"]},
            "policy": {"policy_id": run["policy_id"],
                       "version": run["policy_version"]},
            "fixture": {"fixture_id": run["fixture_id"],
                        "version": run["fixture_version"]},
            "task_id": run["task_id"],
            "clock": json.loads(run["clock_json"]),
            "executor_id": run["executor_id"],
            "fencing_token": run["fencing_token"],
            "lease_expires_at": run["lease_expires_at"],
            "budget": (json.loads(run["budget_json"])
                       if run["budget_json"] else None),
            "steps": steps,
            "manifest": manifest,
            "checkpoints": self.store.list_checkpoints(run_id),
            "created_at": run["created_at"],
            "completed_at": run["completed_at"],
        }

    def list_runs(self) -> list[dict]:
        return [
            {
                "run_id": run["run_id"],
                "scenario_id": run["scenario_id"],
                "scenario_version": run["scenario_version"],
                "policy_id": run["policy_id"],
                "policy_version": run["policy_version"],
                "state": run["state"],
                "outcome": run["outcome"],
                "digest": run["digest"],
            }
            for run in self.store.list_runs()
        ]

    def compare_runs(self, run_id_a: str, run_id_b: str) -> dict:
        """比较任意两次运行：新增暴露、误拦截、原因码变化。"""
        run_a = self.get_run(run_id_a)
        run_b = self.get_run(run_id_b)
        diff = diff_step_payloads(run_a["steps"], run_b["steps"])
        return {
            "run_a": {"run_id": run_id_a, "digest": run_a["digest"],
                      "policy": run_a["policy"], "scenario": run_a["scenario"],
                      "fixture": run_a["fixture"]},
            "run_b": {"run_id": run_id_b, "digest": run_b["digest"],
                      "policy": run_b["policy"], "scenario": run_b["scenario"],
                      "fixture": run_b["fixture"]},
            "digest_equal": run_a["digest"] == run_b["digest"]
            and run_a["digest"] is not None,
            **diff,
        }

    def release_evidence(self, candidate_id: str) -> dict:
        """发布依据追溯：最近一次评估、违例、审批与运行摘要。"""
        candidate = self.store.get_candidate(candidate_id)
        if candidate is None:
            raise NotFoundError(f"候选不存在：{candidate_id}")
        evaluation = self.store.latest_evaluation(candidate_id)
        return {
            "candidate": {
                "candidate_id": candidate_id,
                "policy_id": candidate["policy_id"],
                "policy_version": candidate["policy_version"],
                "state": candidate["state"],
                "requirements": json.loads(candidate["requirements_json"]),
            },
            "evaluation": (json.loads(evaluation["evidence_json"])
                           if evaluation else None),
            "approvals": self.store.list_approvals(candidate_id),
        }

    def events(self, aggregate_id: str | None = None) -> list[dict]:
        rows = self.store.list_events(aggregate_id)
        return [
            {**row, "payload": json.loads(row["payload_json"])}
            for row in rows
        ]
