"""运行编排：排队、租约、确定性执行、安全检查点与崩溃恢复。"""
from __future__ import annotations

import uuid
from datetime import timedelta

from .sandbox import Sandbox
from .store import Store, content_digest
from .util import digest_of, iso, parse_iso


class LeaseError(RuntimeError):
    """租约不属于当前执行器、已过期或运行状态不可执行。"""


class InjectedFailure(RuntimeError):
    """测试注入的执行器崩溃。"""


def queue_run(store: Store, clock, tenant: str, policy: dict, scenario: dict,
              fixture: dict, actor: str = "system") -> str:
    """排队一次运行：冻结策略/场景/夹具版本与起点时钟。"""
    run_id = "run-" + uuid.uuid4().hex[:12]
    now = iso(clock.now())
    record = {
        "run_id": run_id, "tenant": tenant,
        "policy_id": policy["policy_id"], "policy_version": policy["version"],
        "scenario_id": scenario["scenario_id"], "scenario_version": scenario["version"],
        "fixture_id": fixture["fixture_id"], "fixture_version": fixture["version"],
        "status": "queued", "clock_start": now, "created_at": now,
    }
    with store.transaction():
        store.insert_run(record)
        store.emit_event(
            f"evt-{run_id}-00-queued", "run.queued", run_id,
            {"policy": f"{policy['policy_id']}@{policy['version']}",
             "scenario": f"{scenario['scenario_id']}@{scenario['version']}",
             "fixture": f"{fixture['fixture_id']}@{fixture['version']}",
             "clock_start": now},
            now, actor)
    return run_id


class Runner:
    """执行器：领取租约并确定性执行；崩溃后可由其他执行器从检查点续跑。"""

    def __init__(self, store: Store, clock, tenant: str, executor_id: str):
        self.store = store
        self.clock = clock
        self.tenant = tenant
        self.executor_id = executor_id

    def lease(self, run_id: str | None = None, ttl_seconds: int = 300) -> str | None:
        """原子领取一个运行；两个执行器争领同一运行时只有一个成功。"""
        now_dt = self.clock.now()
        now = iso(now_dt)
        expires = iso(now_dt + timedelta(seconds=ttl_seconds))
        with self.store.transaction():
            if run_id is None:
                run_id = self.store.next_leasable_run(self.tenant, now)
                if run_id is None:
                    return None
            if not self.store.lease_run(run_id, self.executor_id, expires, now):
                return None
            attempt = self.store.get_run(run_id)["attempt"]
            self.store.emit_event(
                f"evt-{run_id}-01-leased-{attempt}", "run.leased", run_id,
                {"executor": self.executor_id, "attempt": attempt,
                 "lease_expires_at": expires},
                now, self.executor_id)
        return run_id

    def execute(self, run_id: str, fail_after: int | None = None) -> str:
        """执行到完成；每步连同检查点在一个事务中落库。

        ``fail_after`` 仅用于测试：在第 N 步前模拟执行器崩溃。
        """
        run = self.store.get_run(run_id)
        if run["lease_owner"] != self.executor_id:
            raise LeaseError(f"运行 {run_id} 的租约不属于 {self.executor_id}")
        if run["lease_expires_at"] is None or parse_iso(run["lease_expires_at"]) <= self.clock.now():
            raise LeaseError(f"运行 {run_id} 的租约已过期")
        if run["status"] not in ("leased", "running"):
            raise LeaseError(f"运行 {run_id} 状态为 {run['status']}，不可执行")
        policy = self.store.get_object("policy", run["tenant"], run["policy_id"],
                                       run["policy_version"])
        scenario = self.store.get_object("scenario", run["tenant"], run["scenario_id"],
                                         run["scenario_version"])
        fixture = self.store.get_object("fixture", run["tenant"], run["fixture_id"],
                                        run["fixture_version"])
        sandbox = Sandbox(policy, fixture, parse_iso(run["clock_start"]))
        checkpoint = self.store.latest_checkpoint(run_id)
        start = 0
        if checkpoint is not None:
            sandbox.restore(checkpoint["state"])
            start = checkpoint["step_index"] + 1
        steps = scenario["steps"]
        with self.store.transaction():
            self.store.set_running(run_id)
        for index in range(start, len(steps)):
            if fail_after is not None and index == fail_after:
                raise InjectedFailure(f"执行器在第 {index} 步前崩溃（注入）")
            record = sandbox.run_step(steps[index], index)
            now = iso(self.clock.now())
            with self.store.transaction():
                self.store.record_step(run_id, index, record)
                self.store.add_manifest(
                    run_id, [dict(e, step_index=index) for e in record["produced"]])
                self.store.save_checkpoint(run_id, index, sandbox.state(), now)
                self.store.set_steps_done(run_id, index + 1)
                self.store.emit_event(
                    f"evt-{run_id}-10-step-{index:04d}", "step.recorded", run_id,
                    {"step_index": index, "decision": record["decision"],
                     "reason_code": record["reason_code"], "verdict": record["verdict"]},
                    now, self.executor_id)
                self.store.emit_event(
                    f"evt-{run_id}-11-ckpt-{index:04d}", "checkpoint.saved", run_id,
                    {"step_index": index}, now, self.executor_id)
        return self._finalize(run_id, sandbox, policy, scenario, fixture)

    def work(self, ttl_seconds: int = 300, max_runs: int | None = None) -> list[str]:
        """循环领取并执行，直到队列为空。"""
        done = []
        while max_runs is None or len(done) < max_runs:
            run_id = self.lease(ttl_seconds=ttl_seconds)
            if run_id is None:
                break
            self.execute(run_id)
            done.append(run_id)
        return done

    def _finalize(self, run_id: str, sandbox: Sandbox, policy: dict, scenario: dict,
                  fixture: dict) -> str:
        # 摘要只覆盖冻结输入与判定事实，不含 run_id 等运行标识
        steps = [{k: v for k, v in s.items() if k != "run_id"}
                 for s in self.store.steps_of(run_id)]
        manifest = [{k: v for k, v in m.items() if k != "run_id"}
                    for m in self.store.manifest_of(run_id)]
        status = "passed" if all(s["verdict"] == "ok" for s in steps) else "failed"
        result_doc = {
            "policy": {"id": policy["policy_id"], "version": policy["version"],
                       "digest": content_digest(policy)},
            "scenario": {"id": scenario["scenario_id"], "version": scenario["version"],
                         "digest": content_digest(scenario)},
            "fixture": {"id": fixture["fixture_id"], "version": fixture["version"],
                        "digest": content_digest(fixture)},
            "steps": steps,
            "manifest": manifest,
            "outcome": status,
        }
        digest = digest_of(result_doc)
        now = iso(self.clock.now())
        with self.store.transaction():
            self.store.complete_run(run_id, status, digest, sandbox.elapsed_ms, now)
            self.store.emit_event(
                f"evt-{run_id}-90-completed", "run.completed", run_id,
                {"status": status, "digest": digest, "duration_ms": sandbox.elapsed_ms},
                now, self.executor_id)
        return status
