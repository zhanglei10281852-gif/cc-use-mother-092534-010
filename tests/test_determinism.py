"""确定性：相同输入与时钟摘要一致；策略或夹具变化产生新版本与新摘要。"""
from __future__ import annotations

import unittest

import support


class DeterminismTest(unittest.TestCase):
    def setUp(self) -> None:
        self.service = support.make_service()
        self.pv, self.fv, self.sv = support.setup_platform(self.service)

    def tearDown(self) -> None:
        self.service.close()

    def _digest(self, scenario_id: str, policy_version: int,
                fixture_version: int, nonce: str) -> str:
        run_id = support.run_scenario(
            self.service, scenario_id, self.sv[scenario_id],
            policy_version, fixture_version, nonce=nonce)
        return self.service.get_run(run_id)["digest"]

    def test_same_inputs_same_digest(self) -> None:
        first = self._digest("scn-archive", self.pv, self.fv, "r1")
        second = self._digest("scn-archive", self.pv, self.fv, "r2")
        self.assertEqual(first, second)

    def test_all_chains_replay_identically(self) -> None:
        for scenario_id in self.sv:
            first = self._digest(scenario_id, self.pv, self.fv, "a")
            second = self._digest(scenario_id, self.pv, self.fv, "b")
            self.assertEqual(first, second, scenario_id)

    def test_policy_change_yields_new_version_and_digest(self) -> None:
        baseline = self._digest("scn-traversal", self.pv, self.fv, "base")
        changed = support.strict_policy()
        changed["file_visibility"]["rules"].append(
            {"effect": "deny", "pattern": "/proc/**"})
        pv2 = self.service.create_policy("pol-vm", changed)
        self.assertEqual(pv2, self.pv + 1)
        rerun = self._digest("scn-traversal", pv2, self.fv, "next")
        self.assertNotEqual(baseline, rerun)

    def test_fixture_change_yields_new_version_and_digest(self) -> None:
        baseline = self._digest("scn-archive", self.pv, self.fv, "base")
        changed = support.lab_fixture()
        changed["archives"]["bundle.tar"][0]["content"] = "changed"
        fv2 = self.service.create_fixture("fx-lab", changed)
        self.assertEqual(fv2, self.fv + 1)
        rerun = self._digest("scn-archive", self.pv, fv2, "next")
        self.assertNotEqual(baseline, rerun)

    def test_clock_change_yields_new_digest(self) -> None:
        baseline = self._digest("scn-link", self.pv, self.fv, "base")
        run_id = self.service.queue_run(
            "scn-link", self.sv["scn-link"], "pol-vm", self.pv, "fx-lab",
            self.fv, clock_start="2026-09-26T10:00:00+08:00",
            step_ms_default=9.0, nonce="other-clock")
        self.service.execute_run(run_id, "exec-1")
        self.assertNotEqual(baseline, self.service.get_run(run_id)["digest"])

    def test_manifest_digest_stable(self) -> None:
        run_a = support.run_scenario(
            self.service, "scn-archive", self.sv["scn-archive"],
            self.pv, self.fv, nonce="m1")
        run_b = support.run_scenario(
            self.service, "scn-archive", self.sv["scn-archive"],
            self.pv, self.fv, nonce="m2")
        info_a = self.service.get_run(run_a)
        info_b = self.service.get_run(run_b)
        self.assertEqual(info_a["manifest_hash"], info_b["manifest_hash"])
        self.assertEqual(info_a["manifest"], info_b["manifest"])


if __name__ == "__main__":
    unittest.main()
