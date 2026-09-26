"""差异裁决：新增暴露、误拦截、原因码变化与文件清单差异。"""
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


def load(name: str) -> dict:
    return json.loads((ROOT / "examples" / name).read_text(encoding="utf-8"))


class CompareTest(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = ManualClock(START)
        self.platform = Platform(":memory:", clock=self.clock)
        self.platform.register_fixture(load("fixture_lab.json"))
        for name in SCENARIO_NAMES:
            self.platform.register_scenario(load(f"scenarios/{name}.json"))
        self.platform.register_policy(load("policy_lax.json"))
        self.platform.register_policy(load("policy_strict.json"))
        self.runs = {}
        for version in (1, 2):
            for sid in ("dir-traversal", "archive-member"):
                self.runs[(version, sid)] = self.platform.queue_run(
                    f"vm-isolation@{version}", sid, "vm-lab@1")
        self.platform.work("exec-compare")

    def tearDown(self) -> None:
        self.platform.close()

    def test_new_exposures_when_relaxing_policy(self) -> None:
        diff = self.platform.compare(self.runs[(2, "dir-traversal")],
                                     self.runs[(1, "dir-traversal")])
        self.assertEqual(len(diff["new_exposures"]), 3)
        self.assertEqual({e["step_index"] for e in diff["new_exposures"]}, {1, 5, 6})
        self.assertEqual(diff["new_false_blocks"], [])
        self.assertFalse(diff["digest_equal"])
        self.assertTrue(diff["same_scenario"])

    def test_reason_code_changes(self) -> None:
        diff = self.platform.compare(self.runs[(1, "dir-traversal")],
                                     self.runs[(2, "dir-traversal")])
        pairs = {(c["a"], c["b"]) for c in diff["reason_code_changes"]}
        self.assertIn(("EVERYTHING_ALLOWED", "SYSTEM_CONFIG_DENIED"), pairs)
        self.assertIn(("EGRESS_DEFAULT_ALLOW", "EGRESS_DEFAULT_DENY"), pairs)
        self.assertIn(("TOOL_GRANTED", "TOOL_NOT_GRANTED"), pairs)
        self.assertEqual(diff["new_exposures"], [])
        self.assertEqual(len(diff["decision_changes"]), 3)

    def test_manifest_diff(self) -> None:
        diff = self.platform.compare(self.runs[(2, "archive-member")],
                                     self.runs[(1, "archive-member")])
        self.assertEqual(diff["manifest"]["added"], ["/etc/keys/report.txt"])
        self.assertEqual(diff["manifest"]["removed"], [])
        self.assertEqual(diff["manifest"]["changed"], [])

    def test_identical_replay_has_no_diff(self) -> None:
        replay = self.platform.queue_run("vm-isolation@2", "dir-traversal@1", "vm-lab@1")
        self.platform.work("exec-compare")
        diff = self.platform.compare(self.runs[(2, "dir-traversal")], replay)
        self.assertTrue(diff["digest_equal"])
        self.assertEqual(diff["new_exposures"], [])
        self.assertEqual(diff["new_false_blocks"], [])
        self.assertEqual(diff["reason_code_changes"], [])
        self.assertEqual(diff["decision_changes"], [])
        self.assertEqual(diff["manifest"], {"added": [], "removed": [], "changed": []})
        self.assertTrue(all(not s["changes"] for s in diff["steps"]))


if __name__ == "__main__":
    unittest.main()
