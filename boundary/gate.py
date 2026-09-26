"""发布门禁：必过场景、性能预算与例外审批的联合裁决。

裁决依据（使用的运行、摘要、豁免审批）完整写入候选的决定文档，
审批人可随时追溯；已发布的候选不可改写。
"""
from __future__ import annotations

import uuid

from .store import Store, content_digest
from .util import iso

DEFAULT_BUDGET = {"max_run_ms": 60000, "max_step_ms": 1000}


class Gate:
    def __init__(self, store: Store, clock, tenant: str):
        self.store = store
        self.clock = clock
        self.tenant = tenant

    def create_candidate(self, candidate_id: str, policy_id: str, policy_version: int,
                         must_pass: list[str], perf_budget: dict | None = None,
                         actor: str = "system") -> dict:
        self.store.get_object("policy", self.tenant, policy_id, policy_version)  # 校验存在
        budget = dict(DEFAULT_BUDGET)
        budget.update({k: int(v) for k, v in (perf_budget or {}).items()})
        gate = {"must_pass": list(must_pass), "perf_budget": budget}
        now = iso(self.clock.now())
        with self.store.transaction():
            self.store.create_candidate(self.tenant, candidate_id, policy_id,
                                        policy_version, gate, now)
        return {"candidate_id": candidate_id, "status": "draft", "gate": gate}

    def add_approval(self, candidate_id: str, approver: str, scope: str,
                     decision: str = "approve", reason: str = "") -> str:
        if decision not in ("approve", "reject"):
            raise ValueError("审批决定必须是 approve/reject")
        self.store.get_candidate(self.tenant, candidate_id)  # 校验存在
        approval_id = "apv-" + uuid.uuid4().hex[:12]
        now = iso(self.clock.now())
        with self.store.transaction():
            self.store.add_approval(approval_id, self.tenant, candidate_id, scope,
                                    decision, reason, approver, now)
        return approval_id

    def evaluate(self, candidate_id: str, actor: str = "release-manager") -> dict:
        """裁决候选：必过场景全部通过（或已豁免）且性能预算达标（或已豁免）才发布。"""
        candidate = self.store.get_candidate(self.tenant, candidate_id)
        if candidate["status"] == "released":
            return candidate["decision"]  # 已发布决定不可改写
        policy = self.store.get_object("policy", self.tenant, candidate["policy_id"],
                                       candidate["policy_version"])
        gate = candidate["gate"]
        must_pass = []
        for sid in gate["must_pass"]:
            run = self.store.latest_completed_run(self.tenant, candidate["policy_id"],
                                                  candidate["policy_version"], sid)
            entry = {"scenario": sid}
            if run is None:
                entry.update(status="missing", met=False)
            else:
                entry.update(status=run["status"], run_id=run["run_id"], digest=run["digest"],
                             duration_ms=run["duration_ms"], met=run["status"] == "passed")
            if not entry["met"]:
                approval = self.store.latest_approval(self.tenant, candidate_id,
                                                      f"scenario:{sid}")
                if approval and approval["decision"] == "approve":
                    entry["met"] = True
                    entry["waived_by"] = approval["approval_id"]
            must_pass.append(entry)
        budget = gate["perf_budget"]
        violations = []
        for entry in must_pass:
            run_id = entry.get("run_id")
            if run_id is None:
                continue
            if entry["duration_ms"] > budget["max_run_ms"]:
                violations.append({"kind": "run_duration", "scenario": entry["scenario"],
                                   "run_id": run_id, "value": entry["duration_ms"],
                                   "limit": budget["max_run_ms"]})
            for step in self.store.steps_of(run_id):
                if step["duration_ms"] > budget["max_step_ms"]:
                    violations.append({"kind": "step_duration", "scenario": entry["scenario"],
                                       "run_id": run_id, "step_index": step["step_index"],
                                       "value": step["duration_ms"],
                                       "limit": budget["max_step_ms"]})
        perf = {"met": not violations, "violations": violations, "budget": budget}
        if violations:
            approval = self.store.latest_approval(self.tenant, candidate_id, "perf")
            if approval and approval["decision"] == "approve":
                perf["met"] = True
                perf["waived_by"] = approval["approval_id"]
        released = all(e["met"] for e in must_pass) and perf["met"]
        decision = {
            "released": released,
            "decided_at": iso(self.clock.now()),
            "decided_by": actor,
            "policy": {"policy_id": policy["policy_id"], "version": policy["version"],
                       "digest": content_digest(policy)},
            "must_pass": must_pass,
            "performance": perf,
            "approvals": self.store.approvals_of(self.tenant, candidate_id),
        }
        with self.store.transaction():
            self.store.update_candidate_decision(
                self.tenant, candidate_id, "released" if released else "blocked",
                decision, decision["decided_at"])
            if released:
                self.store.emit_event(
                    f"evt-{candidate_id}-released", "candidate.released", candidate_id,
                    {"policy": decision["policy"],
                     "runs": {e["scenario"]: e.get("run_id") for e in must_pass}},
                    decision["decided_at"], actor)
        return decision

    def basis(self, candidate_id: str) -> dict:
        """发布依据追溯：候选、决定文档、全部审批与相关事件。"""
        return {
            "candidate": self.store.get_candidate(self.tenant, candidate_id),
            "approvals": self.store.approvals_of(self.tenant, candidate_id),
            "events": self.store.events_for(candidate_id),
        }
