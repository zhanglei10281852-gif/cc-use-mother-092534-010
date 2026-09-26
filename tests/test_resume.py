"""断点恢复：失败中断后从安全检查点继续，结果与不中断运行一致。"""
from __future__ import annotations

import json
import unittest

import support


def four_step_scenario() -> dict:
    return {
        "name": "多步骤混合链",
        "task_id": "task-b",
        "steps": [
            {"key": "s0", "kind": "read_file", "expect": "allow",
             "params": {"path": "/workspace/a.txt"}},
            {"key": "s1", "kind": "egress", "expect": "deny",
             "params": {"host": "evil.example", "port": 443}},
            {"key": "s2", "kind": "write_file", "expect": "allow",
             "params": {"path": "/var/persist/task-b/out", "content": "abc"}},
            {"key": "s3", "kind": "use_tool", "expect": "deny",
             "params": {"tool": "shell"}},
        ],
    }


class ResumeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.service = support.make_service()
        scenarios = {"scn-mixed": four_step_scenario()}
        self.pv, self.fv, self.sv = support.setup_platform(
            self.service, scenarios=scenarios)

    def tearDown(self) -> None:
        self.service.close()

    def _queue(self, nonce: str) -> str:
        return self.service.queue_run(
            "scn-mixed", self.sv["scn-mixed"], "pol-vm", self.pv, "fx-lab",
            self.fv, clock_start=support.START, nonce=nonce)

    def test_crash_and_resume_matches_uninterrupted_digest(self) -> None:
        crashed = self._queue("crash")
        self.service.execute_run(crashed, "exec-1", stop_after=2)
        self.assertEqual(self.service.get_run(crashed)["state"], "paused")
        self.assertEqual(len(self.service.get_run(crashed)["steps"]), 2)
        self.service.clock.advance(31)
        self.service.resume_run(crashed, "exec-2")
        clean = self._queue("clean")
        self.service.execute_run(clean, "exec-1")
        self.assertEqual(
            self.service.get_run(crashed)["digest"],
            self.service.get_run(clean)["digest"])
        self.assertEqual(
            len(self.service.get_run(crashed)["steps"]), 4)

    def test_resume_without_checkpoint_restarts_safely(self) -> None:
        run_id = self._queue("no-checkpoint")
        # 检查点间隔大于步骤数：中断时没有任何检查点
        self.service.execute_run(run_id, "exec-1", stop_after=3,
                                 checkpoint_every=100)
        self.assertEqual(len(self.service.get_run(run_id)["steps"]), 3)
        self.service.clock.advance(31)
        self.service.resume_run(run_id, "exec-2")
        run = self.service.get_run(run_id)
        self.assertEqual(len(run["steps"]), 4)  # 从头安全重放，无双计数
        clean = self._queue("clean-2")
        self.service.execute_run(clean, "exec-1")
        self.assertEqual(run["digest"], self.service.get_run(clean)["digest"])

    def test_corrupted_tail_rolls_back_to_safe_checkpoint(self) -> None:
        run_id = self._queue("corrupt")
        self.service.execute_run(run_id, "exec-1", stop_after=3)
        # 模拟落盘数据被破坏：篡改第 2 步的载荷
        row = self.service.store.get_step(run_id, 2)
        tampered = json.loads(row["payload_json"])
        tampered["reason_code"] = "FILE_DENY_RULE"
        self.service.store._exec(
            "UPDATE steps SET payload_json = ? WHERE run_id = ? AND "
            "step_index = ?",
            (json.dumps(tampered, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=False), run_id, 2),
        )
        self.service.clock.advance(31)
        self.service.resume_run(run_id, "exec-2")
        run = self.service.get_run(run_id)
        self.assertEqual(run["state"], "passed")
        clean = self._queue("clean-3")
        self.service.execute_run(clean, "exec-1")
        self.assertEqual(run["digest"], self.service.get_run(clean)["digest"])

    def test_checkpoint_covers_recorded_prefix(self) -> None:
        run_id = self._queue("ckpt")
        self.service.execute_run(run_id, "exec-1", stop_after=2)
        checkpoints = self.service.get_run(run_id)["checkpoints"]
        self.assertEqual([c["step_index"] for c in checkpoints], [0, 1])
        hashes = {c["state_hash"] for c in checkpoints}
        self.assertEqual(len(hashes), 2)  # 每个检查点摘要都不同


if __name__ == "__main__":
    unittest.main()
