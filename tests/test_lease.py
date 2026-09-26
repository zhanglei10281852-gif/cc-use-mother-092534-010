"""租约与栅栏令牌：两个执行器争领同一场景不得双计数。"""
from __future__ import annotations

import unittest

import support
from boundary import errors


class LeaseTest(unittest.TestCase):
    def setUp(self) -> None:
        self.service = support.make_service()
        self.pv, self.fv, self.sv = support.setup_platform(self.service)
        self.run_id = self.service.queue_run(
            "scn-late-mount", self.sv["scn-late-mount"], "pol-vm", self.pv,
            "fx-lab", self.fv, clock_start=support.START, nonce="lease")

    def tearDown(self) -> None:
        self.service.close()

    def test_second_executor_cannot_claim_active_lease(self) -> None:
        lease = self.service.claim_run(self.run_id, "exec-1", lease_seconds=30)
        self.assertIsNotNone(lease)
        self.assertIsNone(self.service.claim_run(self.run_id, "exec-2"))
        # 同一执行器可续租，令牌递增
        renewed = self.service.claim_run(self.run_id, "exec-1")
        self.assertEqual(renewed["fencing_token"], lease["fencing_token"] + 1)

    def test_takeover_after_expiry_rejects_stale_token(self) -> None:
        lease = self.service.claim_run(self.run_id, "exec-1", lease_seconds=30)
        self.service.clock.advance(31)
        takeover = self.service.claim_run(self.run_id, "exec-2")
        self.assertEqual(takeover["fencing_token"],
                         lease["fencing_token"] + 1)
        payload = {
            "step_index": 0, "key": "warmup", "kind": "read_file",
            "expect": "allow", "decision": "allow",
            "reason_code": "FILE_ALLOW", "detail": {}, "duration_ms": 5.0,
        }
        with self.assertRaises(errors.StaleLeaseError):
            self.service.record_step(self.run_id, payload, [],
                                     lease["fencing_token"])

    def test_conflicting_recording_marks_run_blocked(self) -> None:
        lease = self.service.claim_run(self.run_id, "exec-1")
        payload = {
            "step_index": 0, "key": "warmup", "kind": "read_file",
            "expect": "allow", "decision": "allow",
            "reason_code": "FILE_ALLOW", "detail": {}, "duration_ms": 5.0,
        }
        self.assertTrue(self.service.record_step(
            self.run_id, payload, [], lease["fencing_token"]))
        # 相同结果幂等：不双计数
        self.assertFalse(self.service.record_step(
            self.run_id, payload, [], lease["fencing_token"]))
        tampered = dict(payload, reason_code="FILE_DENY_RULE",
                        decision="deny")
        with self.assertRaises(errors.DeterminismError):
            self.service.record_step(
                self.run_id, tampered, [], lease["fencing_token"])
        self.assertEqual(self.service.get_run(self.run_id)["state"], "blocked")

    def test_no_double_count_when_executors_race(self) -> None:
        # exec-1 执行一步后崩溃（租约未释放）
        self.service.execute_run(self.run_id, "exec-1", lease_seconds=30,
                                 stop_after=1)
        # exec-2 在租约未过期时无法接管
        with self.assertRaises(errors.LeaseConflictError):
            self.service.execute_run(self.run_id, "exec-2")
        # 租约过期后 exec-2 接管并跑完
        self.service.clock.advance(31)
        self.service.execute_run(self.run_id, "exec-2")
        run = self.service.get_run(self.run_id)
        self.assertEqual(run["state"], "passed")
        self.assertEqual(len(run["steps"]), 2)  # 场景只有两步，未双计数
        self.assertEqual([s["step_index"] for s in run["steps"]], [0, 1])
        # 与单执行器一次跑完的摘要一致
        clean = support.run_scenario(
            self.service, "scn-late-mount", self.sv["scn-late-mount"],
            self.pv, self.fv, nonce="clean")
        self.assertEqual(
            run["digest"], self.service.get_run(clean)["digest"])

    def test_step_recorded_events_match_step_count(self) -> None:
        self.service.execute_run(self.run_id, "exec-1", stop_after=1)
        self.service.clock.advance(31)
        self.service.execute_run(self.run_id, "exec-2")
        recorded = [
            event for event in self.service.events(self.run_id)
            if event["event_type"] == "step.recorded"
        ]
        self.assertEqual(len(recorded), 2)


if __name__ == "__main__":
    unittest.main()
