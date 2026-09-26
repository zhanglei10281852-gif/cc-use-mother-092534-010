"""发布门禁：必过场景、性能预算、例外审批三者同时满足才能发布。"""
from __future__ import annotations

import unittest

import support


class ReleaseGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.service = support.make_service()
        self.pv, self.fv, self.sv = support.setup_platform(self.service)

    def tearDown(self) -> None:
        self.service.close()

    def _requirements(self, *scenario_ids: str) -> list[dict]:
        return [
            {"scenario_id": sid, "scenario_version": self.sv[sid],
             "fixture_id": "fx-lab", "fixture_version": self.fv}
            for sid in scenario_ids
        ]

    def _candidate(self, *scenario_ids: str) -> str:
        return self.service.create_candidate(
            "pol-vm", self.pv, self._requirements(*scenario_ids))

    def test_missing_run_blocks_release(self) -> None:
        candidate = self._candidate("scn-traversal")
        evidence = self.service.evaluate_candidate(candidate)
        self.assertEqual(evidence["verdict"], "blocked")
        self.assertEqual(evidence["uncovered_violations"],
                         [{"kind": "must_pass", "scope": "scn-traversal",
                           "reason": "missing_run"}])

    def test_all_must_pass_runs_release_candidate(self) -> None:
        for sid in ("scn-traversal", "scn-link"):
            support.run_scenario(self.service, sid, self.sv[sid],
                                 self.pv, self.fv, nonce=sid)
        candidate = self._candidate("scn-traversal", "scn-link")
        evidence = self.service.evaluate_candidate(candidate)
        self.assertEqual(evidence["verdict"], "released")
        self.assertEqual(evidence["violations"], [])
        # 策略版本随发布进入 released 状态
        policy = self.service.store.get_policy("pol-vm", self.pv)
        self.assertEqual(policy["state"], "released")
        # 发布事件可追溯
        events = [e for e in self.service.events(candidate)
                  if e["event_type"] == "candidate.released"]
        self.assertEqual(len(events), 1)

    def test_failed_must_pass_needs_exception_approval(self) -> None:
        # 宽松策略让残留场景失败（期望拒绝却放行）
        loose = support.strict_policy()
        loose["persistence_dirs"] = [
            {"path": "/var/persist", "mode": "shared", "quota_bytes": 64}]
        pv2 = self.service.create_policy("pol-vm", loose)
        support.run_scenario(self.service, "scn-residue",
                             self.sv["scn-residue"], pv2, self.fv, nonce="x")
        candidate = self.service.create_candidate(
            "pol-vm", pv2, self._requirements("scn-residue"))
        evidence = self.service.evaluate_candidate(candidate)
        self.assertEqual(evidence["verdict"], "blocked")
        self.assertEqual(evidence["uncovered_violations"][0]["kind"],
                         "must_pass")
        # 审批驳回不算数
        self.service.approve(candidate, "must_pass", "scn-residue",
                             "rejected", "reviewer-1", "风险不可接受")
        self.assertEqual(
            self.service.evaluate_candidate(candidate)["verdict"], "blocked")
        # 审批通过后发布
        self.service.approve(candidate, "must_pass", "scn-residue",
                             "approved", "reviewer-2",
                             "共享目录为临时方案，下版本回退")
        evidence = self.service.evaluate_candidate(candidate)
        self.assertEqual(evidence["verdict"], "released")

    def test_budget_violation_needs_budget_exception(self) -> None:
        slow = {
            "name": "慢步骤", "task_id": "task-b",
            "steps": [
                {"key": "slow-read", "kind": "read_file", "expect": "allow",
                 "params": {"path": "/workspace/a.txt"}, "simulated_ms": 120},
            ],
        }
        sv = self.service.create_scenario("scn-slow", slow)
        support.run_scenario(self.service, "scn-slow", sv,
                             self.pv, self.fv, nonce="slow")
        candidate = self.service.create_candidate(
            "pol-vm", self.pv,
            [{"scenario_id": "scn-slow", "scenario_version": sv,
              "fixture_id": "fx-lab", "fixture_version": self.fv}])
        evidence = self.service.evaluate_candidate(candidate)
        self.assertEqual(evidence["verdict"], "blocked")
        self.assertEqual(evidence["uncovered_violations"],
                         [{"kind": "budget", "scope": "scn-slow",
                           "reason": "budget_exceeded"}])
        # 误用 must_pass 审批不能覆盖预算违例
        self.service.approve(candidate, "must_pass", "scn-slow",
                             "approved", "reviewer-1", "类型不匹配")
        self.assertEqual(
            self.service.evaluate_candidate(candidate)["verdict"], "blocked")
        self.service.approve(candidate, "budget", "scn-slow",
                             "approved", "reviewer-1", "冷启动可接受")
        self.assertEqual(
            self.service.evaluate_candidate(candidate)["verdict"], "released")

    def test_release_evidence_is_traceable(self) -> None:
        run_id = support.run_scenario(
            self.service, "scn-archive", self.sv["scn-archive"],
            self.pv, self.fv, nonce="trace")
        candidate = self._candidate("scn-archive")
        self.service.evaluate_candidate(candidate)
        evidence = self.service.release_evidence(candidate)
        self.assertEqual(evidence["candidate"]["state"], "released")
        evaluation = evidence["evaluation"]
        self.assertEqual(evaluation["verdict"], "released")
        requirement = evaluation["requirements"][0]
        self.assertEqual(requirement["run_id"], run_id)
        self.assertEqual(
            requirement["digest"], self.service.get_run(run_id)["digest"])
        self.assertTrue(requirement["budget_ok"])
        self.assertEqual(
            evaluation["policy"]["content_hash"],
            self.service.store.get_policy("pol-vm", self.pv)["content_hash"])

    def test_reevaluation_appends_history(self) -> None:
        candidate = self._candidate("scn-link")
        self.service.evaluate_candidate(candidate)  # blocked：缺运行
        support.run_scenario(self.service, "scn-link", self.sv["scn-link"],
                             self.pv, self.fv, nonce="late")
        evidence = self.service.evaluate_candidate(candidate)
        self.assertEqual(evidence["verdict"], "released")
        evaluations = self.service.store._all(
            "SELECT * FROM evaluations WHERE candidate_id = ? ORDER BY rowid",
            (candidate,))
        self.assertEqual([row["verdict"] for row in evaluations],
                         ["blocked", "released"])


if __name__ == "__main__":
    unittest.main()
