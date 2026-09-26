"""沙箱评估：五类攻击链在严格与宽松策略下的判定。"""
from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from boundary.sandbox import Sandbox

ROOT = Path(__file__).resolve().parents[1]
CLOCK_START = datetime(2026, 9, 26, 1, 0, 0, tzinfo=timezone.utc)
SCENARIO_NAMES = ["dir_traversal", "link_jump", "archive_member", "late_mount", "residue"]


def load(name: str) -> dict:
    return json.loads((ROOT / "examples" / name).read_text(encoding="utf-8"))


class SandboxTest(unittest.TestCase):
    def setUp(self) -> None:
        self.strict = load("policy_strict.json")
        self.lax = load("policy_lax.json")
        self.fixture = load("fixture_lab.json")
        self.scenarios = {name: load(f"scenarios/{name}.json") for name in SCENARIO_NAMES}

    def run_scenario(self, policy: dict, scenario: dict) -> list[dict]:
        sandbox = Sandbox(policy, self.fixture, CLOCK_START)
        return [sandbox.run_step(step, i) for i, step in enumerate(scenario["steps"])]

    def test_strict_policy_passes_all_chains(self) -> None:
        for name, scenario in self.scenarios.items():
            records = self.run_scenario(self.strict, scenario)
            self.assertTrue(
                all(r["verdict"] == "ok" for r in records),
                f"{name}: " + json.dumps(
                    [(r["reason_code"], r["verdict"]) for r in records], ensure_ascii=False))

    def test_lax_policy_exposures(self) -> None:
        exposures = {}
        for name, scenario in self.scenarios.items():
            records = self.run_scenario(self.lax, scenario)
            exposures[name] = [r["step_index"] for r in records if r["verdict"] == "exposure"]
        self.assertEqual(exposures["dir_traversal"], [1, 5, 6])
        self.assertEqual(exposures["link_jump"], [0])
        self.assertEqual(exposures["archive_member"], [2])
        self.assertEqual(exposures["late_mount"], [2])
        self.assertEqual(exposures["residue"], [0, 3])

    def test_reason_codes_strict(self) -> None:
        records = self.run_scenario(self.strict, self.scenarios["dir_traversal"])
        self.assertEqual(
            [r["reason_code"] for r in records],
            ["WORKSPACE_ALLOWED", "SYSTEM_CONFIG_DENIED", "PATH_TRAVERSAL",
             "WORKSPACE_ALLOWED", "INTERNAL_API", "EGRESS_DEFAULT_DENY", "TOOL_NOT_GRANTED"])

    def test_link_jump_resolves_target(self) -> None:
        records = self.run_scenario(self.strict, self.scenarios["link_jump"])
        self.assertEqual(records[0]["resolved_path"], "/etc/secrets/token.txt")
        self.assertEqual(records[0]["reason_code"], "SYSTEM_CONFIG_DENIED")
        self.assertEqual(records[2]["reason_code"], "NOT_A_LINK")

    def test_archive_member_invariant_and_policy(self) -> None:
        records = self.run_scenario(self.strict, self.scenarios["archive_member"])
        self.assertEqual(records[1]["reason_code"], "ARCHIVE_TRAVERSAL")
        self.assertEqual(records[2]["reason_code"], "SYSTEM_CONFIG_DENIED")
        self.assertEqual(records[3]["reason_code"], "ARCHIVE_MEMBER_MISSING")

    def test_late_mount_timing(self) -> None:
        records = self.run_scenario(self.strict, self.scenarios["late_mount"])
        self.assertEqual(records[0]["reason_code"], "MOUNT_NOT_ACTIVE")
        self.assertEqual(records[1]["reason_code"], "WORKSPACE_ALLOWED")
        self.assertEqual(records[2]["reason_code"], "MOUNT_DENIED")
        # 时间戳完全来自冻结时钟与逻辑耗时
        self.assertEqual(records[0]["at"], "2026-09-26T01:00:00.000000+00:00")
        self.assertEqual(records[2]["at"], "2026-09-26T01:00:00.040000+00:00")

    def test_residue_purge_and_persist(self) -> None:
        records = self.run_scenario(self.strict, self.scenarios["residue"])
        self.assertEqual(records[0]["reason_code"], "RESIDUE_PURGED")
        self.assertEqual(records[1]["reason_code"], "PERSIST_ALLOWED")
        self.assertEqual(records[3]["reason_code"], "FILE_DEFAULT_DENY")

    def test_manifest_entries_with_digest(self) -> None:
        records = self.run_scenario(self.strict, self.scenarios["residue"])
        produced = [entry for r in records for entry in r["produced"]]
        self.assertEqual(len(produced), 1)
        self.assertEqual(produced[0]["path"], "/var/persist/cache/new.txt")
        self.assertTrue(produced[0]["persistent"])
        self.assertEqual(len(produced[0]["digest"]), 64)

    def test_state_snapshot_roundtrip(self) -> None:
        scenario = self.scenarios["residue"]
        sandbox = Sandbox(self.strict, self.fixture, CLOCK_START)
        first = sandbox.run_step(scenario["steps"][2], 2)
        state = sandbox.state()
        restored = Sandbox(self.strict, self.fixture, CLOCK_START)
        restored.restore(state)
        self.assertEqual(restored.elapsed_ms, sandbox.elapsed_ms)
        self.assertEqual(restored.writes, sandbox.writes)
        self.assertEqual(first["decision"], "allow")


if __name__ == "__main__":
    unittest.main()
