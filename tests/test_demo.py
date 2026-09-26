"""端到端演示与 CLI 冒烟。"""
from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from boundary.cli import main as cli_main
from boundary.demo import run_demo

ROOT = Path(__file__).resolve().parents[1]


class DemoTest(unittest.TestCase):
    def test_demo_end_to_end(self) -> None:
        summary = run_demo()
        self.assertTrue(summary["确定性重放一致"])
        self.assertTrue(summary["崩溃恢复一致"])
        self.assertTrue(summary["步骤不双计数"])
        self.assertTrue(summary["租约唯一获胜者"])
        self.assertTrue(summary["门禁_严格候选发布"])
        self.assertTrue(summary["门禁_预算收紧阻断"])
        self.assertTrue(summary["门禁_例外审批放行"])
        self.assertEqual(summary["差异裁决"]["严格到宽松_新增暴露"], 3)
        self.assertGreaterEqual(summary["差异裁决"]["宽松到严格_原因码变化"], 3)
        self.assertEqual(summary["发布依据_审批数"], 1)
        statuses = {key: value["status"] for key, value in summary["运行结果"].items()}
        for key, status in statuses.items():
            self.assertEqual(status, "passed" if key.startswith("v2/") else "failed", key)


class CliTest(unittest.TestCase):
    def invoke(self, *args: str) -> dict:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli_main(list(args))
        self.assertEqual(code, 0)
        return json.loads(buffer.getvalue())

    def test_cli_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "lab.db")
            examples = ROOT / "examples"
            self.invoke("--db", db, "fixture", str(examples / "fixture_lab.json"))
            self.invoke("--db", db, "scenario", str(examples / "scenarios" / "dir_traversal.json"))
            self.invoke("--db", db, "policy", str(examples / "policy_strict.json"))
            queued = self.invoke("--db", db, "queue", "vm-isolation@1", "dir-traversal@1",
                                 "vm-lab@1")
            run_id = queued["run_id"]
            worked = self.invoke("--db", db, "work", "--executor", "exec-cli")
            self.assertEqual(worked["completed"], [run_id])
            shown = self.invoke("--db", db, "show", run_id)
            self.assertEqual(shown["run"]["status"], "passed")
            self.assertEqual(len(shown["steps"]), 7)
            candidate = self.invoke("--db", db, "candidate", "CAND-CLI", "vm-isolation@1",
                                    "--must-pass", "dir-traversal",
                                    "--max-run-ms", "120", "--max-step-ms", "50")
            self.assertEqual(candidate["status"], "draft")
            decision = self.invoke("--db", db, "evaluate", "CAND-CLI")
            self.assertTrue(decision["released"])
            basis = self.invoke("--db", db, "basis", "CAND-CLI")
            self.assertIn("candidate.released",
                          [e["event_type"] for e in basis["events"]])

    def test_cli_demo(self) -> None:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli_main(["demo"])
        self.assertEqual(code, 0)
        summary = json.loads(buffer.getvalue())
        self.assertTrue(summary["门禁_严格候选发布"])


if __name__ == "__main__":
    unittest.main()
