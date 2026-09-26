"""运行编排：确定性摘要、租约争用不双计数、崩溃后从检查点恢复。"""
from __future__ import annotations

import json
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path

from boundary.clock import ManualClock
from boundary.platform import Platform
from boundary.runner import InjectedFailure, LeaseError, Runner
from boundary.store import Store

ROOT = Path(__file__).resolve().parents[1]
START = datetime(2026, 9, 26, 1, 0, 0, tzinfo=timezone.utc)
SCENARIO_NAMES = ["dir_traversal", "link_jump", "archive_member", "late_mount", "residue"]


def load(name: str) -> dict:
    return json.loads((ROOT / "examples" / name).read_text(encoding="utf-8"))


def register_all(platform: Platform) -> None:
    platform.register_fixture(load("fixture_lab.json"))
    for name in SCENARIO_NAMES:
        platform.register_scenario(load(f"scenarios/{name}.json"))
    platform.register_policy(load("policy_lax.json"))
    platform.register_policy(load("policy_strict.json"))


class RunnerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = ManualClock(START)
        self.platform = Platform(":memory:", clock=self.clock)
        register_all(self.platform)

    def tearDown(self) -> None:
        self.platform.close()

    def queue(self, scenario: str = "dir-traversal", policy: str = "vm-isolation@2") -> str:
        return self.platform.queue_run(policy, scenario, "vm-lab@1")

    def digest(self, run_id: str) -> str:
        return self.platform.run_info(run_id)["run"]["digest"]

    def test_deterministic_digest_same_clock(self) -> None:
        first, second = self.queue(), self.queue()
        self.platform.work("exec-x")
        self.assertEqual(self.digest(first), self.digest(second))
        info = self.platform.run_info(first)
        self.assertEqual(info["run"]["status"], "passed")
        self.assertEqual(info["run"]["steps_done"], 7)
        self.assertEqual(info["checkpoints"], 7)

    def test_digest_depends_on_clock(self) -> None:
        first = self.queue()
        self.platform.work("exec-x")
        self.clock.advance(seconds=5)
        second = self.queue()
        self.platform.work("exec-x")
        self.assertNotEqual(self.digest(first), self.digest(second))
        decisions_a = [s["decision"] for s in self.platform.run_info(first)["steps"]]
        decisions_b = [s["decision"] for s in self.platform.run_info(second)["steps"]]
        self.assertEqual(decisions_a, decisions_b)

    def test_policy_change_produces_new_version(self) -> None:
        # 与最新版本内容一致：幂等，不产生新版本
        strict = load("policy_strict.json")
        ref = self.platform.register_policy(strict)
        self.assertFalse(ref["created"])
        self.assertEqual(ref["version"], 2)
        # 内容变化：追加新版本；回滚到旧内容同样产生新版本（只追加不覆盖）
        changed = dict(strict)
        changed["persistence_dirs"] = []
        ref2 = self.platform.register_policy(changed)
        self.assertTrue(ref2["created"])
        self.assertEqual(ref2["version"], 3)
        rollback = self.platform.register_policy(load("policy_lax.json"))
        self.assertTrue(rollback["created"])
        self.assertEqual(rollback["version"], 4)

    def test_execute_without_lease_rejected(self) -> None:
        run_id = self.queue()
        with self.assertRaises(LeaseError):
            self.platform.runner("exec-x").execute(run_id)

    def test_lease_contention_single_winner_no_double_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "lab.db")
            clock = ManualClock(START)
            platform = Platform(db_path, clock=clock)
            try:
                register_all(platform)
                run_id = platform.queue_run("vm-isolation@2", "dir-traversal", "vm-lab@1")
                barrier = threading.Barrier(2)
                outcomes: dict[str, str | None] = {}

                def compete(name: str) -> None:
                    store = Store(db_path)
                    try:
                        runner = Runner(store, clock, "default", name)
                        barrier.wait(timeout=10)
                        outcomes[name] = runner.lease(run_id)
                    finally:
                        store.close()

                threads = [threading.Thread(target=compete, args=(f"exec-{i}",))
                           for i in range(2)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=30)
                self.assertEqual(sorted(o is not None for o in outcomes.values()),
                                 [False, True])
                winner = next(name for name, got in outcomes.items() if got is not None)
                loser = next(name for name, got in outcomes.items() if got is None)
                with self.assertRaises(LeaseError):
                    platform.runner(loser).execute(run_id)
                platform.runner(winner).execute(run_id)
                info = platform.run_info(run_id)
                self.assertEqual(len(info["steps"]), 7)
                self.assertEqual([s["step_index"] for s in info["steps"]], list(range(7)))
            finally:
                platform.close()

    def test_resume_after_crash_matches_uninterrupted(self) -> None:
        reference = self.queue("residue")
        crashed = self.queue("residue")
        steady = self.platform.runner("exec-steady")
        steady.lease(reference)
        steady.execute(reference)
        crasher = self.platform.runner("exec-crash")
        crasher.lease(crashed, ttl_seconds=30)
        with self.assertRaises(InjectedFailure):
            crasher.execute(crashed, fail_after=2)
        info = self.platform.run_info(crashed)
        self.assertEqual(info["run"]["steps_done"], 2)
        self.assertEqual(info["checkpoints"], 2)
        # 租约未过期前其他执行器无法接管
        self.assertIsNone(self.platform.runner("exec-early").lease(crashed))
        self.clock.advance(seconds=31)
        recovery = self.platform.runner("exec-recovery")
        self.assertEqual(recovery.lease(crashed), crashed)
        self.assertEqual(recovery.execute(crashed), "passed")
        self.assertEqual(self.digest(crashed), self.digest(reference))
        steps = self.platform.run_info(crashed)["steps"]
        self.assertEqual(len(steps), 4)
        self.assertEqual([s["step_index"] for s in steps], [0, 1, 2, 3])
        types = [e["event_type"] for e in self.platform.events(crashed)]
        self.assertIn("checkpoint.saved", types)
        self.assertEqual(types.count("run.leased"), 2)
        self.assertEqual(types.count("step.recorded"), 4)

    def test_reexecute_completed_run_rejected(self) -> None:
        run_id = self.queue()
        self.platform.work("exec-x")
        with self.assertRaises(LeaseError):
            self.platform.runner("exec-y").execute(run_id)


if __name__ == "__main__":
    unittest.main()
