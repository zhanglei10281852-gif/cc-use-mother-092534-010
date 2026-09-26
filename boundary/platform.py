"""平台门面：注册版本化对象、排队与执行运行、差异比较、发布门禁与审计查询。"""
from __future__ import annotations

from .clock import SystemClock
from .compare import compare_runs
from .gate import Gate
from .runner import Runner, queue_run as _queue_run
from .schemas import (validate_fixture_body, validate_policy_body,
                      validate_scenario_body)
from .store import Store
from .util import iso


def _parse_ref(ref: str) -> tuple[str, int | None]:
    """``id@version`` 或 ``id``（取最新版本）。"""
    if "@" in ref:
        obj_id, _, version = ref.rpartition("@")
        return obj_id, int(version)
    return ref, None


class Platform:
    def __init__(self, db_path: str = ":memory:", clock=None, tenant: str = "default"):
        self.store = Store(db_path)
        self.clock = clock or SystemClock()
        self.tenant = tenant

    def close(self) -> None:
        self.store.close()

    # ---- 版本化对象注册 ----

    def register_policy(self, body: dict, actor: str = "system") -> dict:
        validate_policy_body(body)
        now = iso(self.clock.now())
        with self.store.transaction():
            ref = self.store.save_object("policy", self.tenant, body, actor, now)
            if ref["created"]:
                self.store.emit_event(
                    f"evt-policy-{self.tenant}-{ref['id']}-{ref['version']}",
                    "policy.created", ref["id"],
                    {"version": ref["version"], "digest": ref["digest"]}, now, actor)
        return ref

    def register_scenario(self, body: dict, actor: str = "system") -> dict:
        validate_scenario_body(body)
        now = iso(self.clock.now())
        with self.store.transaction():
            ref = self.store.save_object("scenario", self.tenant, body, actor, now)
            if ref["created"]:
                self.store.emit_event(
                    f"evt-scenario-{self.tenant}-{ref['id']}-{ref['version']}",
                    "scenario.versioned", ref["id"],
                    {"version": ref["version"], "digest": ref["digest"]}, now, actor)
        return ref

    def register_fixture(self, body: dict, actor: str = "system") -> dict:
        validate_fixture_body(body)
        now = iso(self.clock.now())
        with self.store.transaction():
            ref = self.store.save_object("fixture", self.tenant, body, actor, now)
        return ref

    # ---- 运行 ----

    def queue_run(self, policy_ref: str, scenario_ref: str, fixture_ref: str,
                  actor: str = "system") -> str:
        policy = self.store.get_object("policy", self.tenant, *_parse_ref(policy_ref))
        scenario = self.store.get_object("scenario", self.tenant, *_parse_ref(scenario_ref))
        fixture = self.store.get_object("fixture", self.tenant, *_parse_ref(fixture_ref))
        return _queue_run(self.store, self.clock, self.tenant, policy, scenario, fixture, actor)

    def runner(self, executor_id: str) -> Runner:
        return Runner(self.store, self.clock, self.tenant, executor_id)

    def work(self, executor_id: str, ttl_seconds: int = 300) -> list[str]:
        return self.runner(executor_id).work(ttl_seconds=ttl_seconds)

    def run_info(self, run_id: str) -> dict:
        return {
            "run": self.store.get_run(run_id),
            "steps": self.store.steps_of(run_id),
            "manifest": self.store.manifest_of(run_id),
            "checkpoints": self.store.checkpoint_count(run_id),
        }

    def list_runs(self) -> list[dict]:
        return self.store.list_runs(self.tenant)

    # ---- 差异比较 ----

    def compare(self, run_a: str, run_b: str) -> dict:
        return compare_runs(self.store, run_a, run_b)

    # ---- 发布门禁 ----

    def _gate(self) -> Gate:
        return Gate(self.store, self.clock, self.tenant)

    def create_candidate(self, candidate_id: str, policy_ref: str, must_pass: list[str],
                         perf_budget: dict | None = None, actor: str = "system") -> dict:
        policy_id, version = _parse_ref(policy_ref)
        if version is None:
            version = self.store.get_object("policy", self.tenant, policy_id)["version"]
        return self._gate().create_candidate(candidate_id, policy_id, version,
                                             must_pass, perf_budget, actor)

    def approve(self, candidate_id: str, approver: str, scope: str,
                decision: str = "approve", reason: str = "") -> str:
        return self._gate().add_approval(candidate_id, approver, scope, decision, reason)

    def evaluate_candidate(self, candidate_id: str, actor: str = "release-manager") -> dict:
        return self._gate().evaluate(candidate_id, actor)

    def release_basis(self, candidate_id: str) -> dict:
        return self._gate().basis(candidate_id)

    # ---- 审计 ----

    def events(self, aggregate_id: str | None = None) -> list[dict]:
        if aggregate_id is None:
            return self.store.all_events()
        return self.store.events_for(aggregate_id)
