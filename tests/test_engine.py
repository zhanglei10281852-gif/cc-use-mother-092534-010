"""攻击链求值：五类攻击链在严格策略下都被拒绝并给出正确原因码。"""
from __future__ import annotations

import unittest

import support
from boundary import models


class AttackChainTest(unittest.TestCase):
    def setUp(self) -> None:
        self.service = support.make_service()
        self.pv, self.fv, self.sv = support.setup_platform(self.service)

    def tearDown(self) -> None:
        self.service.close()

    def _run(self, scenario_id: str) -> dict:
        run_id = support.run_scenario(
            self.service, scenario_id, self.sv[scenario_id], self.pv, self.fv)
        return self.service.get_run(run_id)

    def test_directory_traversal_denied(self) -> None:
        run = self._run("scn-traversal")
        step = run["steps"][0]
        self.assertEqual(step["decision"], models.DENY)
        self.assertEqual(step["reason_code"], models.FILE_DENY_TRAVERSAL)
        self.assertEqual(run["outcome"], "passed")

    def test_symlink_escape_denied(self) -> None:
        run = self._run("scn-link")
        step = run["steps"][0]
        self.assertEqual(step["decision"], models.DENY)
        self.assertEqual(step["reason_code"], models.LINK_DENY_ESCAPE)
        self.assertEqual(step["detail"]["resolved"], "/etc/secret")

    def test_archive_member_escape_denied_and_manifest_clean(self) -> None:
        run = self._run("scn-archive")
        step = run["steps"][0]
        self.assertEqual(step["decision"], models.DENY)
        self.assertEqual(step["reason_code"], models.ARCHIVE_DENY_MEMBER_ESCAPE)
        # 只有安全成员落盘，逃逸成员不进入清单
        self.assertEqual(
            [entry["path"] for entry in run["manifest"]],
            ["/workspace/unpacked/ok.txt"],
        )
        self.assertTrue(all(
            not entry["path"].startswith("/etc") for entry in run["manifest"]
        ))

    def test_late_mount_denied(self) -> None:
        run = self._run("scn-late-mount")
        warmup, mounted = run["steps"]
        self.assertEqual(warmup["decision"], models.ALLOW)
        self.assertEqual(mounted["decision"], models.DENY)
        self.assertEqual(mounted["reason_code"], models.MOUNT_DENY_LATE)

    def test_cross_task_residue_denied(self) -> None:
        run = self._run("scn-residue")
        step = run["steps"][0]
        self.assertEqual(step["decision"], models.DENY)
        self.assertEqual(step["reason_code"], models.RESIDUE_DENY_CROSS_TASK)
        self.assertEqual(step["detail"]["visible_files"], [])

    def test_egress_and_tool_capability(self) -> None:
        scenario = {
            "name": "出口与工具",
            "task_id": "task-b",
            "steps": [
                {"key": "pypi", "kind": "egress", "expect": "allow",
                 "params": {"host": "pypi.org", "port": 443}},
                {"key": "evil-host", "kind": "egress", "expect": "deny",
                 "params": {"host": "evil.example", "port": 443}},
                {"key": "shell", "kind": "use_tool", "expect": "deny",
                 "params": {"tool": "shell"}},
                {"key": "read", "kind": "use_tool", "expect": "allow",
                 "params": {"tool": "read"}},
            ],
        }
        version = self.service.create_scenario("scn-egress-tool", scenario)
        run_id = support.run_scenario(
            self.service, "scn-egress-tool", version, self.pv, self.fv)
        run = self.service.get_run(run_id)
        reasons = [step["reason_code"] for step in run["steps"]]
        self.assertEqual(reasons, [
            models.EGRESS_ALLOW,
            models.EGRESS_DENY_HOST,
            models.TOOL_DENY_CAPABILITY,
            models.TOOL_ALLOW,
        ])
        self.assertEqual(run["outcome"], "passed")

    def test_persistence_quota_enforced(self) -> None:
        scenario = {
            "name": "持久化配额",
            "task_id": "task-b",
            "steps": [
                {"key": "write-1", "kind": "write_file", "expect": "allow",
                 "params": {"path": "/var/persist/task-b/blob-1",
                            "content": "x" * 40}},
                {"key": "write-2", "kind": "write_file", "expect": "deny",
                 "params": {"path": "/var/persist/task-b/blob-2",
                            "content": "y" * 40}},
            ],
        }
        version = self.service.create_scenario("scn-quota", scenario)
        run_id = support.run_scenario(
            self.service, "scn-quota", version, self.pv, self.fv)
        run = self.service.get_run(run_id)
        first, second = run["steps"]
        self.assertEqual(first["reason_code"], models.PERSIST_ALLOW)
        self.assertEqual(second["reason_code"], models.PERSIST_DENY_QUOTA)
        self.assertEqual(second["detail"]["quota_bytes"], 64)
        self.assertEqual(run["outcome"], "passed")

    def test_shared_persistence_exposes_residue(self) -> None:
        """宽松策略把持久化目录声明为共享：残留步骤从拒绝变为允许。"""
        loose = support.strict_policy()
        loose["persistence_dirs"] = [
            {"path": "/var/persist", "mode": "shared", "quota_bytes": 64},
        ]
        pv2 = self.service.create_policy("pol-vm", loose)
        run_id = support.run_scenario(
            self.service, "scn-residue", self.sv["scn-residue"], pv2, self.fv,
            nonce="loose")
        run = self.service.get_run(run_id)
        step = run["steps"][0]
        self.assertEqual(step["decision"], models.ALLOW)
        self.assertEqual(step["reason_code"], models.RESIDUE_ALLOW_SHARED)
        self.assertEqual(step["detail"]["visible_files"],
                         ["task-a/leftover.txt"])
        self.assertEqual(run["outcome"], "failed")  # 期望拒绝却放行 → 暴露


if __name__ == "__main__":
    unittest.main()
