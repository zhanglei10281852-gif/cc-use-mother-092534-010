"""发布门禁：必过场景、性能预算、例外审批与发布依据追溯。"""
from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from boundary.clock import ManualClock
from boundary.platform import Platform

ROOT = Path(__file__).resolve().parents[1]
START = datetime(2026, 9, 26, 1, 0, 0, tzinfo=timezone.utc)
SCENARIO_NAMES = ["dir_traversal", "link_jump", "archive_member", "late_mount", "residue"]
SCENARIO_IDS = ["dir-traversal", "link-jump", "archive-member", "late-mount", "residue"]


def load(name: str) -> dict:
    return json.loads((ROOT / "examples" / name).read_text(encoding="utf-8"))


class GateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = ManualClock(START)
        self.platform = Platform(":memory:", clock=self.clock)
        self.platform.register_fixture(load("fixture_lab.json"))
        for name in SCENARIO_NAMES:
            self.platform.register_scenario(load(f"scenarios/{name}.json"))
        self.platform.register_policy(load("policy_lax.json"))
        self.platform.register_policy(load("policy_strict.json"))
        # 两个策略版本都完成全部场景
        for version in (1, 2):
            for sid in SCENARIO_IDS:
                self.platform.queue_run(f"vm-isolation@{version}", sid, "vm-lab@1")
        self.platform.work("exec-gate")

    def tearDown(self) -> None:
        self.platform.close()

    def create(self, candidate_id: str, policy: str = "vm-isolation@2",
               must_pass: list[str] | None = None, **budget) -> None:
        self.platform.create_candidate(
            candidate_id, policy, must_pass=must_pass or list(SCENARIO_IDS),
            perf_budget=budget or {"max_run_ms": 120, "max_step_ms": 50})

    def test_release_when_all_criteria_met(self) -> None:
        self.create("CAND-1")
        decision = self.platform.evaluate_candidate("CAND-1")
        self.assertTrue(decision["released"])
        self.assertEqual(len(decision["must_pass"]), 5)
        self.assertTrue(all(e["met"] for e in decision["must_pass"]))
        self.assertTrue(decision["performance"]["met"])
        for entry in decision["must_pass"]:
            self.assertIn("run_id", entry)
            self.assertIn("digest", entry)
        basis = self.platform.release_basis("CAND-1")
        self.assertIn("candidate.released", [e["event_type"] for e in basis["events"]])
        self.assertEqual(basis["candidate"]["status"], "released")

    def test_blocked_when_must_pass_missing(self) -> None:
        self.create("CAND-2", must_pass=SCENARIO_IDS + ["ghost-scenario"])
        decision = self.platform.evaluate_candidate("CAND-2")
        self.assertFalse(decision["released"])
        missing = [e for e in decision["must_pass"] if e["status"] == "missing"]
        self.assertEqual(len(missing), 1)
        self.assertEqual(self.platform.release_basis("CAND-2")["candidate"]["status"], "blocked")

    def test_exception_approval_waives_failed_scenario(self) -> None:
        # 宽松策略候选：dir-traversal 运行失败（存在暴露）
        self.create("CAND-3", policy="vm-isolation@1", must_pass=["dir-traversal"])
        decision = self.platform.evaluate_candidate("CAND-3")
        self.assertFalse(decision["released"])
        self.assertEqual(decision["must_pass"][0]["status"], "failed")
        self.platform.approve("CAND-3", approver="security-lead",
                              scope="scenario:dir-traversal",
                              reason="已知暴露，下版本修复，本次豁免")
        decision = self.platform.evaluate_candidate("CAND-3")
        self.assertTrue(decision["released"])
        self.assertIn("waived_by", decision["must_pass"][0])
        basis = self.platform.release_basis("CAND-3")
        self.assertEqual(len(basis["approvals"]), 1)
        self.assertEqual(basis["approvals"][0]["approver"], "security-lead")
        self.assertEqual(basis["approvals"][0]["scope"], "scenario:dir-traversal")

    def test_perf_budget_violation_and_waiver(self) -> None:
        self.create("CAND-4", max_run_ms=40, max_step_ms=50)
        decision = self.platform.evaluate_candidate("CAND-4")
        self.assertFalse(decision["released"])
        violations = decision["performance"]["violations"]
        self.assertTrue(any(v["scenario"] == "late-mount" for v in violations))
        self.platform.approve("CAND-4", approver="release-lead", scope="perf",
                              reason="迟到挂载成本已纳入容量计划")
        decision = self.platform.evaluate_candidate("CAND-4")
        self.assertTrue(decision["released"])
        self.assertIn("waived_by", decision["performance"])

    def test_step_level_budget_violation(self) -> None:
        self.create("CAND-5", max_run_ms=1000, max_step_ms=20)
        decision = self.platform.evaluate_candidate("CAND-5")
        self.assertFalse(decision["released"])
        kinds = {v["kind"] for v in decision["performance"]["violations"]}
        self.assertEqual(kinds, {"step_duration"})

    def test_released_decision_is_immutable(self) -> None:
        self.create("CAND-6")
        first = self.platform.evaluate_candidate("CAND-6")
        self.assertTrue(first["released"])
        self.platform.approve("CAND-6", approver="auditor", scope="perf",
                              decision="reject", reason="事后反悔不应改写历史")
        again = self.platform.evaluate_candidate("CAND-6")
        self.assertEqual(again, first)
        self.assertEqual(self.platform.release_basis("CAND-6")["candidate"]["status"],
                         "released")

    def test_reject_approval_does_not_waive(self) -> None:
        self.create("CAND-7", policy="vm-isolation@1", must_pass=["dir-traversal"])
        self.platform.approve("CAND-7", approver="security-lead",
                              scope="scenario:dir-traversal", decision="reject",
                              reason="暴露不可接受")
        decision = self.platform.evaluate_candidate("CAND-7")
        self.assertFalse(decision["released"])


if __name__ == "__main__":
    unittest.main()
