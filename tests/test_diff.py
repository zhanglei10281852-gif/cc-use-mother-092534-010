"""差异裁决：新增暴露、误拦截与原因码变化。"""
from __future__ import annotations

import unittest

import support


def diff_scenario() -> dict:
    return {
        "name": "差异演示",
        "task_id": "task-b",
        "steps": [
            {"key": "read-secret", "kind": "read_file", "expect": "deny",
             "params": {"path": "/etc/secret"}},
            {"key": "read-workspace", "kind": "read_file", "expect": "allow",
             "params": {"path": "/workspace/a.txt"}},
            {"key": "traverse", "kind": "read_file", "expect": "deny",
             "params": {"path": "../../etc/secret", "base_dir": "/workspace"}},
        ],
    }


class DiffTest(unittest.TestCase):
    def setUp(self) -> None:
        self.service = support.make_service()
        scenarios = {"scn-diff": diff_scenario()}
        self.pv, self.fv, self.sv = support.setup_platform(
            self.service, scenarios=scenarios)
        self.baseline = support.run_scenario(
            self.service, "scn-diff", self.sv["scn-diff"],
            self.pv, self.fv, nonce="baseline")

    def tearDown(self) -> None:
        self.service.close()

    def _rerun(self, policy_content: dict, nonce: str,
               scenario_version: int | None = None) -> str:
        pv = self.service.create_policy("pol-vm", policy_content)
        return support.run_scenario(
            self.service, "scn-diff",
            scenario_version or self.sv["scn-diff"], pv, self.fv, nonce=nonce)

    def test_new_exposure_detected(self) -> None:
        loose = support.strict_policy()
        loose["file_visibility"]["rules"] = [
            {"effect": "allow", "pattern": "/workspace/**"},
            {"effect": "allow", "pattern": "/etc/**"},
        ]
        candidate = self._rerun(loose, "loose")
        diff = self.service.compare_runs(self.baseline, candidate)
        self.assertFalse(diff["digest_equal"])
        self.assertEqual(len(diff["new_exposures"]), 1)
        exposure = diff["new_exposures"][0]
        self.assertEqual(exposure["step_key"], "read-secret")
        self.assertEqual(exposure["a"]["reason_code"], "FILE_DENY_RULE")
        self.assertEqual(exposure["b"]["reason_code"], "FILE_ALLOW")
        self.assertEqual(diff["false_blocks"], [])

    def test_false_block_detected(self) -> None:
        tighter = support.strict_policy()
        tighter["file_visibility"]["rules"].insert(
            0, {"effect": "deny", "pattern": "/workspace/a.txt"})
        candidate = self._rerun(tighter, "tighter")
        diff = self.service.compare_runs(self.baseline, candidate)
        self.assertEqual(len(diff["false_blocks"]), 1)
        block = diff["false_blocks"][0]
        self.assertEqual(block["step_key"], "read-workspace")
        self.assertEqual(block["b"]["reason_code"], "FILE_DENY_RULE")
        self.assertEqual(diff["new_exposures"], [])

    def test_reason_code_change_detected(self) -> None:
        # 场景 v2 去掉 base_dir：同一步骤仍是拒绝，但原因码从遍历变为规则
        changed = diff_scenario()
        changed["steps"][2]["params"] = {"path": "/etc/secret"}
        sv2 = self.service.create_scenario("scn-diff", changed)
        candidate = support.run_scenario(
            self.service, "scn-diff", sv2, self.pv, self.fv, nonce="v2")
        diff = self.service.compare_runs(self.baseline, candidate)
        # read-secret 与 traverse 变为同一路径的两次规则拒绝
        self.assertEqual(diff["new_exposures"], [])
        self.assertEqual(diff["false_blocks"], [])
        self.assertEqual(len(diff["reason_changes"]), 1)
        change = diff["reason_changes"][0]
        self.assertEqual(change["step_key"], "traverse")
        self.assertEqual(change["a_reason_code"], "FILE_DENY_TRAVERSAL")
        self.assertEqual(change["b_reason_code"], "FILE_DENY_RULE")
        self.assertEqual(change["decision"], "deny")

    def test_identical_runs_have_empty_diff(self) -> None:
        twin = support.run_scenario(
            self.service, "scn-diff", self.sv["scn-diff"],
            self.pv, self.fv, nonce="twin")
        diff = self.service.compare_runs(self.baseline, twin)
        self.assertTrue(diff["digest_equal"])
        self.assertEqual(diff["new_exposures"], [])
        self.assertEqual(diff["false_blocks"], [])
        self.assertEqual(diff["reason_changes"], [])

    def test_added_and_removed_steps_listed(self) -> None:
        changed = diff_scenario()
        changed["steps"].append(
            {"key": "extra", "kind": "use_tool", "expect": "deny",
             "params": {"tool": "shell"}})
        changed["steps"].pop(0)
        sv2 = self.service.create_scenario("scn-diff", changed)
        candidate = support.run_scenario(
            self.service, "scn-diff", sv2, self.pv, self.fv, nonce="v3")
        diff = self.service.compare_runs(self.baseline, candidate)
        self.assertEqual(diff["added_steps"], ["extra"])
        self.assertEqual(diff["removed_steps"], ["read-secret"])


if __name__ == "__main__":
    unittest.main()
